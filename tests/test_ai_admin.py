"""Administration de l'IA locale depuis la console, contre un faux serveur Ollama (sans réseau)."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path

import httpx
import pytest
from conftest import load_raw

pytest.importorskip("fastapi")
pytest.importorskip("multipart")

H = {"X-ADSentry": "1"}
ROOT = Path(__file__).resolve().parents[1]


class FakeOllama:
    def __init__(self):
        self.models = {"llama3:8b"}
        self.created: dict | None = None
        self.chats: list[dict] = []
        self.embed_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if path == "/api/version":
            return httpx.Response(200, json={"version": "0.12.0"})
        if path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": m, "size": 1} for m in sorted(self.models)]})
        if path == "/api/pull":
            name = body["model"]
            events = [{"status": "pulling manifest"}]
            events += [
                {"status": "pulling abc", "digest": "abc", "total": 1000, "completed": c} for c in range(0, 1001, 50)
            ]
            events += [{"status": "success"}]
            self.models.add(name if ":" in name else f"{name}:latest")
            return httpx.Response(200, content="\n".join(json.dumps(e) for e in events).encode())
        if path == "/api/create":
            self.created = body
            self.models.add(f"{body['model']}:latest")
            return httpx.Response(200, content=b'{"status":"writing manifest"}\n{"status":"success"}\n')
        if path == "/api/embed":
            self.embed_calls += 1
            vec = lambda t: [b / 255 for b in hashlib.sha256(t.encode()).digest()[:16]]  # noqa: E731
            return httpx.Response(200, json={"embeddings": [vec(t) for t in body["input"]]})
        if path == "/api/chat":
            self.chats.append(body)
            if body.get("format"):
                answer = {
                    "resume_executif": "Synthèse.",
                    "niveau_risque": "Critique",
                    "top_risques": [],
                    "plan_remediation": [],
                    "questions_a_verifier": [],
                }
                return httpx.Response(200, json={"message": {"content": json.dumps(answer)}})
            return httpx.Response(200, json={"message": {"content": "ESC1 : un modèle permet de choisir le sujet."}})
        return httpx.Response(404, json={"error": "inconnu"})


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("ADSENTRY_DATA", str(tmp_path / "state" / "scans"))
    monkeypatch.setenv("ADSENTRY_CONFIG", str(tmp_path / "etc"))
    monkeypatch.delenv("ADSENTRY_WEB_DIR", raising=False)
    import adsentry.ai.admin as ai_admin
    import adsentry.api.main as api
    import adsentry.appliance.auth as auth
    import adsentry.appliance.config as config
    import adsentry.appliance.jobs as jobs
    import adsentry.appliance.runner as runner

    for mod in (config, auth, jobs, ai_admin, runner, api):
        importlib.reload(mod)
    from fastapi.testclient import TestClient

    fake = FakeOllama()
    real_client = httpx.Client
    transport = httpx.MockTransport(fake.handler)
    # Tous les clients HTTP créés par ADSentry parlent au faux Ollama
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: real_client(transport=transport))

    auth.UserStore().create("admin", "Adm1n-Passw0rd!", auth.Role.admin)
    auth.UserStore().create("lecteur", "V1ewer-Passw0rd!", auth.Role.viewer)

    def login(user, pwd):
        c = TestClient(api.app, headers=H)
        assert c.post("/api/auth/login", json={"username": user, "password": pwd}).status_code == 200
        return c

    class E:
        pass

    e = E()
    e.fake, e.api, e.ai, e.jobs, e.runner, e.tmp = fake, api, ai_admin, jobs, runner, tmp_path
    e.admin = login("admin", "Adm1n-Passw0rd!")
    e.viewer = login("lecteur", "V1ewer-Passw0rd!")
    return e


def _run_next_job(e):
    store = e.jobs.JobStore()
    return e.runner.execute_job(store.claim_next(), store)


def test_modelfile_matches_console_model():
    from adsentry.ai.admin import MODEL_PARAMETERS
    from adsentry.ai.prompts import SYSTEM_PROMPT

    mf = (ROOT / "ai" / "Modelfile").read_text(encoding="utf-8")
    assert re.search(r'SYSTEM """(.*?)"""', mf, re.S).group(1).strip() == SYSTEM_PROMPT.strip()
    params = {k: float(v) for k, v in re.findall(r"^PARAMETER (\S+) (\S+)", mf, re.M)}
    assert params == {k: float(v) for k, v in MODEL_PARAMETERS.items()}


def test_status_reports_missing_models(env):
    st = env.admin.get("/api/ai/status").json()
    assert st["reachable"] and st["version"] == "0.12.0"
    assert not st["base_ready"] and not st["analyst_ready"] and not st["index"]["built"]
    assert st["settings"]["base_model"] == "qwen3.5:4b"


def test_viewer_cannot_administer_ai(env):
    for method, path in [
        ("get", "/api/ai/status"),
        ("post", "/api/ai/setup"),
        ("post", "/api/ai/index"),
        ("get", "/api/ai/knowledge"),
        ("put", "/api/ai/knowledge/x.md"),
        ("post", "/api/ai/ask"),
        ("get", "/api/ai/dataset"),
        ("put", "/api/ai/settings"),
    ]:
        assert (
            getattr(env.viewer, method)(path, **({"json": {}} if method in ("put", "post") else {})).status_code == 403
        ), path


def test_setup_job_pulls_and_creates_analyst(env):
    job = env.admin.post("/api/ai/setup").json()
    assert job["kind"] == "ai_setup"
    done = _run_next_job(env)
    assert done.status == "succeeded", done.error
    created = env.fake.created
    from adsentry.ai.prompts import SYSTEM_PROMPT

    assert created["model"] == "adsentry-analyst" and created["from"] == "qwen3.5:4b"
    assert created["system"] == SYSTEM_PROMPT and created["parameters"]["num_ctx"] == 8192
    # L'avancement du téléchargement met à jour l'étape sans inonder le journal
    assert len(done.log) < 20
    st = env.admin.get("/api/ai/status").json()
    assert st["base_ready"] and st["embed_ready"] and st["analyst_ready"]
    assert st["last_jobs"]["ai_setup"]["status"] == "succeeded"


def test_settings_validation(env):
    bad = {"base_model": "qwen; rm -rf", "analyst_model": "a", "embed_model": "e"}
    assert env.admin.put("/api/ai/settings", json=bad).status_code == 400
    ok = {
        "base_model": "llama3.2:3b",
        "analyst_model": "mon-analyste",
        "embed_model": "nomic-embed-text",
        "use_rag": False,
    }
    assert env.admin.put("/api/ai/settings", json=ok).json()["base_model"] == "llama3.2:3b"
    assert env.admin.get("/api/ai/status").json()["settings"]["use_rag"] is False


def test_knowledge_crud_and_index(env):
    doc = "# Tier 0\n\n## Comptes\nLes comptes Tier 0 n'ouvrent jamais de session sur un poste.\n"
    assert env.admin.put("/api/ai/knowledge/../x.md", json={"content": doc}).status_code in (400, 404)
    assert env.admin.put("/api/ai/knowledge/Tier0.MD", json={"content": doc}).status_code == 400
    assert env.admin.put("/api/ai/knowledge/vide.md", json={"content": "  "}).status_code == 400
    r = env.admin.put("/api/ai/knowledge/tier0.md", json={"content": doc})
    assert r.status_code == 200 and r.json()["index"]["stale"] is True
    # tier0.md (document par défaut) est remplacé par celui de l'administrateur
    tier0 = next(d for d in env.admin.get("/api/ai/knowledge").json() if d["name"] == "tier0.md")
    assert tier0["sections"] == 1
    assert env.admin.get("/api/ai/knowledge/tier0.md").json()["content"] == doc

    env.admin.post("/api/ai/index")
    done = _run_next_job(env)
    assert done.status == "succeeded", done.error
    idx = env.admin.get("/api/ai/status").json()["index"]
    assert (
        idx["built"] and not idx["stale"] and idx["documents"] == 3 and idx["chunks"] > 200
    )  # catalogue + 3 documents

    assert env.admin.delete("/api/ai/knowledge/tier0.md").json()["index"]["stale"] is True
    assert env.admin.get("/api/ai/knowledge/tier0.md").status_code == 404


def test_synthesis_uses_knowledge_base(env):
    env.admin.put(
        "/api/ai/knowledge/tier0.md", json={"content": "## Règle maison\nAucun compte Tier 0 sur les postes.\n"}
    )
    env.admin.post("/api/ai/index")
    _run_next_job(env)
    payload = json.dumps(load_raw("vulnerable")).encode()
    scan_id = env.admin.post("/api/scans", files={"snapshot": ("s.json", payload, "application/json")}).json()["id"]
    env.admin.post(f"/api/scans/{scan_id}/ai-analysis")
    done = _run_next_job(env)
    assert done.status == "succeeded", done.error
    prompt = env.fake.chats[-1]["messages"][1]["content"]
    assert "Connaissances internes pertinentes" in prompt
    analysis = env.viewer.get(f"/api/scans/{scan_id}/ai-analysis").json()
    assert analysis["_contexte"]["extraits"] > 0 and analysis["_controle_qualite"]["fiable"] is True


def test_ask_and_dataset(env):
    r = env.admin.post("/api/ai/ask", json={"question": "Qu'est-ce que ESC1 ?"})
    assert r.status_code == 200 and "ESC1" in r.json()["answer"]
    assert env.fake.chats[-1]["messages"][0]["role"] == "system" and "format" not in env.fake.chats[-1]
    r = env.admin.get("/api/ai/dataset?n=12")
    lines = [json.loads(x) for x in r.text.splitlines()]
    assert len(lines) == 12 and lines[0]["messages"][2]["role"] == "assistant"
    assert "attachment" in r.headers["content-disposition"]


def test_default_knowledge_installed_once(env):
    docs = {d["name"] for d in env.admin.get("/api/ai/knowledge").json()}
    assert docs == {"tier0.md", "procedures-remediation.md", "comptes-de-service.md"}
    assert "[équipe ou personne]" in env.admin.get("/api/ai/knowledge/tier0.md").json()["content"]
    # un document supprimé ne revient pas, un document modifié n'est pas écrasé
    assert env.admin.delete("/api/ai/knowledge/tier0.md").status_code == 200
    env.admin.put("/api/ai/knowledge/comptes-de-service.md", json={"content": "## Maison\nRègle interne.\n"})
    again = {d["name"] for d in env.admin.get("/api/ai/knowledge").json()}
    assert again == {"procedures-remediation.md", "comptes-de-service.md"}
    assert env.admin.get("/api/ai/knowledge/comptes-de-service.md").json()["content"] == "## Maison\nRègle interne.\n"
    assert env.ai.ensure_default_knowledge() == []


def test_existing_document_not_overwritten(tmp_path, monkeypatch):
    import importlib

    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path))
    import adsentry.ai.admin as ai_admin
    import adsentry.appliance.config as config

    importlib.reload(config)
    importlib.reload(ai_admin)
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "tier0.md").write_text("## À moi\n", encoding="utf-8")
    added = ai_admin.ensure_default_knowledge()
    assert "tier0.md" not in added and (tmp_path / "knowledge" / "tier0.md").read_text(encoding="utf-8") == "## À moi\n"
    assert "comptes-de-service.md" in added
