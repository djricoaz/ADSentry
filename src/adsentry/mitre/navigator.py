"""Export des constats en couche ATT&CK Navigator (format layer 4.5).

Le fichier produit s'ouvre dans https://mitre-attack.github.io/attack-navigator/
(« Open Existing Layer » → « Upload from local ») ou dans une instance Navigator interne.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import SEVERITY_ORDER, ScanResult, Severity

SEVERITY_SCORE = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 10,
}


def build_layer(result: ScanResult, attack_version: str | None = None) -> dict:
    per_tech: dict[str, list] = defaultdict(list)
    for f in result.findings:
        for m in f.mitre:
            per_tech[m.technique].append(f)

    techniques = []
    for tid, findings in sorted(per_tech.items()):
        worst = min((f.severity for f in findings), key=lambda s: SEVERITY_ORDER[s])
        techniques.append(
            {
                "techniqueID": tid,
                "score": SEVERITY_SCORE[worst],
                "enabled": True,
                "showSubtechniques": True,
                "comment": "; ".join(f"{f.rule_id} ({len(f.affected)} objet(s))" for f in findings),
                "metadata": [{"name": f.rule_id, "value": f.title} for f in findings],
            }
        )

    versions = {"layer": "4.5", "navigator": "5.1.0"}
    if attack_version:
        versions["attack"] = attack_version.split(".")[0]

    return {
        "name": f"ADSentry – {result.domain}",
        "description": f"Constats du {result.analyzed_at:%Y-%m-%d} – score global {result.global_score}/100",
        "domain": "enterprise-attack",
        "versions": versions,
        "techniques": techniques,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Critique", "color": "#ff6666"},
            {"label": "Moyen", "color": "#ffb366"},
            {"label": "Faible", "color": "#ffe766"},
        ],
        "hideDisabled": False,
    }
