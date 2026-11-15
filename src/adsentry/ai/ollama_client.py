"""Client Ollama local (API HTTP, sorties structurées JSON).

Toutes les données restent sur la machine : aucune donnée d'annuaire ne part vers un cloud.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from ..models import ScanResult
from .prompts import ANALYSIS_SCHEMA, SYSTEM_PROMPT, build_user_prompt

OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("ADSENTRY_MODEL", "adsentry-analyst")


class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_URL, model: str = DEFAULT_MODEL, timeout: float = 600):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.http = httpx.Client(timeout=timeout)

    def chat(self, messages: list[dict], fmt: dict | str | None = None, **options: Any) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2, **options},
        }
        if fmt is not None:
            payload["format"] = fmt
        r = self.http.post(f"{self.base_url}/api/chat", json=payload)
        r.raise_for_status()
        return r.json()["message"]["content"]

    def embed(self, texts: list[str], model: str = "nomic-embed-text") -> list[list[float]]:
        r = self.http.post(f"{self.base_url}/api/embed", json={"model": model, "input": texts})
        r.raise_for_status()
        return r.json()["embeddings"]


def analyze_with_llm(
    result: ScanResult, client: OllamaClient | None = None, context_snippets: list[str] | None = None
) -> dict:
    client = client or OllamaClient()
    raw = client.chat(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(result, context_snippets)},
        ],
        fmt=ANALYSIS_SCHEMA,
    )
    analysis = json.loads(raw)
    return guard_against_hallucinations(analysis, result)


def guard_against_hallucinations(analysis: dict, result: ScanResult) -> dict:
    """Retire toute référence à une règle qui n'existe pas dans les constats et le signale."""
    known = {f.rule_id for f in result.findings}
    invented: set[str] = set()

    kept = []
    for item in analysis.get("top_risques", []):
        if item.get("rule_id") in known:
            kept.append(item)
        else:
            invented.add(str(item.get("rule_id")))
    analysis["top_risques"] = kept

    for step in analysis.get("plan_remediation", []):
        bad = [r for r in step.get("regles", []) if r not in known]
        invented.update(bad)
        step["regles"] = [r for r in step.get("regles", []) if r in known]

    analysis["_controle_qualite"] = {
        "regles_inventees_retirees": sorted(invented),
        "fiable": not invented,
    }
    return analysis
