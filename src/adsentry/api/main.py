"""API FastAPI consommée par le dashboard web (web/ – React, phase 4).

Stockage v0.1 : fichiers JSON dans ADSENTRY_DATA (par défaut ~/.local/share/adsentry/scans).
À remplacer par SQLite (SQLModel) en phase 4.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from ..mitre.navigator import build_layer
from ..models import ScanResult, Snapshot
from ..rules.engine import analyze, load_rules

DATA_DIR = Path(os.environ.get("ADSENTRY_DATA", Path.home() / ".local/share/adsentry/scans"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="ADSentry API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])


def _load(scan_id: str) -> ScanResult:
    if not scan_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "Identifiant invalide")
    path = DATA_DIR / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(404, "Scan introuvable")
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/dashboard")
def dashboard_view(domain: str | None = None):
    from ..history import dashboard, load_all

    return dashboard(load_all(DATA_DIR), domain)


@app.get("/api/compare")
def compare_view(base: str, target: str):
    from ..history import compare

    a, b = _load(base), _load(target)
    if a.collected_at > b.collected_at:
        a, b = b, a
    return compare(a, b)


@app.get("/api/mitre")
def mitre_reference():
    from ..mitre.attack import EXPORT_PATH

    if not EXPORT_PATH.exists():
        raise HTTPException(404, "Référentiel ATT&CK absent : lancer « adsentry mitre-check »")
    return json.loads(EXPORT_PATH.read_text(encoding="utf-8"))


@app.get("/api/rules")
def list_rules():
    return [r.model_dump(mode="json") for r in load_rules()]


@app.post("/api/scans")
async def create_scan(snapshot: UploadFile):
    snap = Snapshot.model_validate_json(await snapshot.read())
    result = analyze(snap)
    scan_id = uuid.uuid4().hex[:12]
    (DATA_DIR / f"{scan_id}.json").write_text(result.model_dump_json(indent=1), encoding="utf-8")
    return {"id": scan_id, "global_score": result.global_score}


@app.get("/api/scans")
def list_scans():
    from ..history import maturity

    out = []
    for p in DATA_DIR.glob("*.json"):
        if p.name.endswith(".ai.json"):
            continue
        r = ScanResult.model_validate_json(p.read_text(encoding="utf-8"))
        out.append(
            {
                "id": p.stem,
                "domain": r.domain,
                "collected_at": r.collected_at.isoformat(),
                "analyzed_at": r.analyzed_at.isoformat(),
                "global_score": r.global_score,
                "findings": len(r.findings),
                "maturity": maturity(r.findings),
                "ai": (DATA_DIR / f"{p.stem}.ai.json").exists(),
            }
        )
    return sorted(out, key=lambda x: x["collected_at"], reverse=True)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    return _load(scan_id).model_dump(mode="json")


@app.get("/api/scans/{scan_id}/navigator")
def get_navigator_layer(scan_id: str):
    return build_layer(_load(scan_id))


@app.get("/api/scans/{scan_id}/ai-analysis")
def get_ai_analysis(scan_id: str):
    _load(scan_id)  # valide l'identifiant et l'existence du scan
    path = DATA_DIR / f"{scan_id}.ai.json"
    if not path.exists():
        raise HTTPException(404, "Pas encore d'analyse IA pour ce scan")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/catalog-stats")
def catalog_stats():
    from collections import Counter

    rules = load_rules()
    return {
        "rules": len(rules),
        "by_category": dict(Counter(r.category.value for r in rules)),
        "by_source": dict(Counter(r.source for r in rules)),
        "adcs_escalations": len([r for r in rules if r.id.startswith("PKI-ESC")]),
    }


@app.post("/api/scans/{scan_id}/ai-analysis")
def ai_analysis(scan_id: str):
    from ..ai.ollama_client import analyze_with_llm

    path = DATA_DIR / f"{scan_id}.ai.json"
    analysis = analyze_with_llm(_load(scan_id))
    path.write_text(json.dumps(analysis, ensure_ascii=False, indent=1), encoding="utf-8")
    return analysis


# Mode développement sans Caddy (monté en dernier pour ne pas masquer /api) :
#   ADSENTRY_WEB_DIR=appliance/web adsentry serve
if os.environ.get("ADSENTRY_WEB_DIR"):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=os.environ["ADSENTRY_WEB_DIR"], html=True), name="web")
