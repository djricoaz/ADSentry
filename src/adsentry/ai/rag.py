"""RAG minimal : base de connaissances locale (catalogue de règles + dossier knowledge/).

Étape 1 de la stratégie IA (avant tout fine-tuning) : donner au petit modèle les bons
documents au bon moment. On indexe :
* les règles du catalogue (description + remédiation) ;
* les fichiers Markdown de ``knowledge/`` (politiques internes, guides ANSSI résumés, procédures).
Les embeddings sont calculés par Ollama (``nomic-embed-text``) et stockés en .npz.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ..rules.engine import load_rules
from .ollama_client import OllamaClient

INDEX_PATH = Path.home() / ".cache" / "adsentry" / "rag_index.npz"


def _chunks_from_markdown(path: Path, max_chars: int = 1200) -> list[str]:
    text = path.read_text(encoding="utf-8")
    sections = [s.strip() for s in text.split("\n## ") if s.strip()]
    chunks: list[str] = []
    for s in sections:
        for i in range(0, len(s), max_chars):
            chunks.append(f"[{path.name}] {s[i : i + max_chars]}")
    return chunks


def collect_documents(knowledge_dir: Path) -> list[str]:
    docs = [f"[{r.id}] {r.title}\n{r.description}\nRemédiation : {r.remediation}" for r in load_rules()]
    if knowledge_dir.exists():
        for p in sorted(knowledge_dir.rglob("*.md")):
            docs += _chunks_from_markdown(p)
    return docs


def build_index(
    knowledge_dir: Path,
    client: OllamaClient | None = None,
    path: Path = INDEX_PATH,
    embed_model: str = "nomic-embed-text",
    batch: int = 64,
) -> int:
    client = client or OllamaClient()
    docs = collect_documents(knowledge_dir)
    embeddings: list[list[float]] = []
    for i in range(0, len(docs), batch):  # par lots : évite une requête géante sur CPU
        embeddings += client.embed(docs[i : i + batch], model=embed_model)
    vectors = np.array(embeddings, dtype=np.float32)
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True) + 1e-9
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, vectors=vectors, docs=np.array([json.dumps(d) for d in docs]))
    return len(docs)


def search(
    query: str,
    k: int = 4,
    client: OllamaClient | None = None,
    path: Path = INDEX_PATH,
    embed_model: str = "nomic-embed-text",
) -> list[str]:
    if not path.exists():
        return []
    client = client or OllamaClient()
    data = np.load(path)
    q = np.array(client.embed([query], model=embed_model)[0], dtype=np.float32)
    q /= np.linalg.norm(q) + 1e-9
    scores = data["vectors"] @ q
    top = np.argsort(-scores)[:k]
    return [json.loads(str(data["docs"][i])) for i in top]
