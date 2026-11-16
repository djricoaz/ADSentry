"""Administration de l'IA locale depuis la console : réglages, état d'Ollama, installation du modèle,
base de connaissances (RAG).

Tout passe par l'API HTTP d'Ollama, sur le réseau interne de l'appliance. Ollama télécharge lui-même les
modèles (réseau « models ») : ni l'API ni le worker ne sortent du réseau interne (règle d'or 8).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel, Field

from ..appliance.config import STATE_DIR
from .prompts import SYSTEM_PROMPT

# Paramètres du modèle analyste : identiques à ai/Modelfile (vérifié par tests/test_ai_admin.py)
MODEL_PARAMETERS = {"temperature": 0.2, "top_p": 0.9, "repeat_penalty": 1.1, "num_ctx": 8192}

KNOWLEDGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,60}\.md$")
KNOWLEDGE_MAX_BYTES = 200_000


def ollama_url() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


def knowledge_dir() -> Path:
    return STATE_DIR / "knowledge"


def index_path() -> Path:
    return STATE_DIR / "rag_index.npz"


# ----------------------------------------------------------------------------- réglages


class AiSettings(BaseModel):
    base_model: str = Field(default_factory=lambda: os.environ.get("ADSENTRY_BASE_MODEL", "qwen3.5:4b"))
    analyst_model: str = Field(default_factory=lambda: os.environ.get("ADSENTRY_MODEL", "adsentry-analyst"))
    embed_model: str = "nomic-embed-text"
    use_rag: bool = True
    rag_snippets: int = Field(default=8, ge=0, le=20)


MODEL_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,100}(:[a-zA-Z0-9._-]{1,60})?$")


def load_settings() -> AiSettings:
    path = STATE_DIR / "ai.json"
    if path.exists():
        try:
            return AiSettings.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return AiSettings()


def save_settings(s: AiSettings) -> AiSettings:
    for name in (s.base_model, s.analyst_model, s.embed_model):
        if not MODEL_NAME_RE.match(name):
            raise ValueError(f"Nom de modèle invalide : {name}")
    path = STATE_DIR / "ai.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(s.model_dump_json(indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return s


# ----------------------------------------------------------------------------- Ollama


def _same_model(a: str, b: str) -> bool:
    norm = lambda n: n if ":" in n else f"{n}:latest"  # noqa: E731
    return norm(a) == norm(b)


class OllamaAdmin:
    def __init__(self, base_url: str | None = None, http: httpx.Client | None = None):
        self.base_url = (base_url or ollama_url()).rstrip("/")
        self.http = http or httpx.Client(timeout=httpx.Timeout(10, read=3600))

    def version(self) -> str:
        r = self.http.get(f"{self.base_url}/api/version", timeout=5)
        r.raise_for_status()
        return r.json().get("version", "?")

    def models(self) -> list[dict]:
        r = self.http.get(f"{self.base_url}/api/tags", timeout=10)
        r.raise_for_status()
        return [
            {"name": m["name"], "size": m.get("size"), "modified_at": m.get("modified_at")}
            for m in r.json().get("models", [])
        ]

    def has(self, name: str, models: list[dict] | None = None) -> bool:
        return any(_same_model(m["name"], name) for m in (models if models is not None else self.models()))

    def _stream(self, path: str, payload: dict, on_event: Callable[[dict], None]) -> None:
        with self.http.stream("POST", f"{self.base_url}{path}", json={**payload, "stream": True}) as r:
            if r.status_code >= 400:
                r.read()
                raise RuntimeError(f"Ollama {path} : {r.status_code} {r.text[:200]}")
            for line in r.iter_lines():
                if not line.strip():
                    continue
                event = json.loads(line)
                if "error" in event:
                    raise RuntimeError(f"Ollama : {event['error']}")
                on_event(event)

    def pull(self, model: str, on_progress: Callable[[float, str], None]) -> None:
        """Télécharge un modèle ; on_progress(fraction 0-1, libellé)."""

        def handle(e: dict) -> None:
            total, done = e.get("total"), e.get("completed")
            if total and done is not None:
                on_progress(done / total, f"Téléchargement de {model} : {_size(done)} / {_size(total)}")
            else:
                on_progress(-1, f"{model} : {e.get('status', '')}")

        self._stream("/api/pull", {"model": model}, handle)

    def create_analyst(self, name: str, base: str, on_status: Callable[[str], None]) -> None:
        payload = {"model": name, "from": base, "system": SYSTEM_PROMPT, "parameters": MODEL_PARAMETERS}
        self._stream("/api/create", payload, lambda e: on_status(e.get("status", "")))


def _size(n: int) -> str:
    return f"{n / 1e9:.2f} Go" if n >= 1e9 else f"{n / 1e6:.0f} Mo"


def status(settings: AiSettings | None = None, admin: OllamaAdmin | None = None) -> dict:
    """État de l'IA locale pour la console (n'échoue jamais : les erreurs sont rapportées)."""
    s = settings or load_settings()
    out: dict = {"settings": s.model_dump(), "ollama_url": ollama_url(), "reachable": False}
    try:
        admin = admin or OllamaAdmin()
        out["version"] = admin.version()
        models = admin.models()
        out["reachable"] = True
        out["models"] = models
        out["base_ready"] = admin.has(s.base_model, models)
        out["embed_ready"] = admin.has(s.embed_model, models)
        out["analyst_ready"] = admin.has(s.analyst_model, models)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        out["error"] = f"Ollama injoignable ({ollama_url()}) : {exc}"
    out["knowledge"] = list_knowledge()
    out["index"] = index_info()
    return out


# ----------------------------------------------------------------------------- base de connaissances


def list_knowledge() -> list[dict]:
    d = knowledge_dir()
    if not d.exists():
        return []
    return [
        {
            "name": p.name,
            "size": p.stat().st_size,
            "updated_at": datetime.fromtimestamp(p.stat().st_mtime, UTC).isoformat(),
            "sections": sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.startswith("## ")),
        }
        for p in sorted(d.glob("*.md"))
    ]


def _doc_path(name: str) -> Path:
    if not KNOWLEDGE_NAME_RE.match(name):
        raise ValueError("Nom de document invalide : minuscules, chiffres, - et _, extension .md (ex. tier0.md)")
    return knowledge_dir() / name


def read_knowledge(name: str) -> str:
    path = _doc_path(name)
    if not path.exists():
        raise FileNotFoundError(name)
    return path.read_text(encoding="utf-8")


def write_knowledge(name: str, content: str) -> None:
    path = _doc_path(name)
    if len(content.encode("utf-8")) > KNOWLEDGE_MAX_BYTES:
        raise ValueError(f"Document trop volumineux ({KNOWLEDGE_MAX_BYTES // 1000} Ko maximum)")
    if not content.strip():
        raise ValueError("Document vide")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.replace("\r\n", "\n"), encoding="utf-8")


def delete_knowledge(name: str) -> None:
    path = _doc_path(name)
    if not path.exists():
        raise FileNotFoundError(name)
    path.unlink()


def index_info() -> dict:
    path = index_path()
    if not path.exists():
        return {"built": False, "stale": True}
    built = path.stat().st_mtime
    docs = list(knowledge_dir().glob("*.md")) if knowledge_dir().exists() else []
    newest = max((p.stat().st_mtime for p in docs), default=0)
    meta_path = path.with_suffix(".json")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    return {
        "built": True,
        "built_at": datetime.fromtimestamp(built, UTC).isoformat(),
        "chunks": meta.get("chunks"),
        "documents": meta.get("documents"),
        # index périmé si un document est plus récent, ou si un document indexé a été supprimé
        "stale": newest > built or meta.get("documents", len(docs)) != len(docs),
    }


def build_index(settings: AiSettings | None = None, client=None) -> int:
    from . import rag
    from .ollama_client import OllamaClient

    s = settings or load_settings()
    client = client or OllamaClient(model=s.analyst_model)
    n = rag.build_index(knowledge_dir(), client=client, path=index_path(), embed_model=s.embed_model)
    meta = {"chunks": n, "documents": len(list_knowledge()), "embed_model": s.embed_model}
    index_path().with_suffix(".json").write_text(json.dumps(meta), encoding="utf-8")
    return n


def context_for(result, settings: AiSettings | None = None, client=None) -> list[str]:
    """Extraits de la base de connaissances pour les constats les plus lourds (vide si désactivé ou absent)."""
    from . import rag

    s = settings or load_settings()
    if not s.use_rag or not s.rag_snippets or not index_path().exists():
        return []
    snippets: list[str] = []
    for f in sorted(result.findings, key=lambda f: -f.points)[:5]:
        snippets += rag.search(
            f"{f.title} {f.remediation}", k=2, client=client, path=index_path(), embed_model=s.embed_model
        )
    return list(dict.fromkeys(snippets))[: s.rag_snippets]


ASK_SYSTEM = (
    "Tu es un analyste sécurité Active Directory, PKI (ADCS) et Entra ID francophone. Réponds en français, "
    "en texte clair et concis, pour un public d'administrateurs. Décris les risques de façon défensive "
    "(impact, détection, correction), sans commande d'exploitation. Si tu n'es pas sûr, dis-le."
)


def ask(question: str, settings: AiSettings | None = None, client=None) -> dict:
    """Question libre à l'analyste (test depuis la console), avec extraits de la base de connaissances."""
    from . import rag
    from .ollama_client import OllamaClient

    s = settings or load_settings()
    client = client or OllamaClient(model=s.analyst_model)
    context = (
        rag.search(question, k=3, client=client, path=index_path(), embed_model=s.embed_model)
        if s.use_rag and index_path().exists()
        else []
    )
    user = question if not context else question + "\n\nContexte interne :\n" + "\n---\n".join(context)
    answer = client.chat([{"role": "system", "content": ASK_SYSTEM}, {"role": "user", "content": user}])
    return {"answer": answer.strip(), "context": context, "model": s.analyst_model}
