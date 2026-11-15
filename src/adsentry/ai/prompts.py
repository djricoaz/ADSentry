"""Prompts et schéma de sortie de l'analyste IA.

Principe de sécurité : l'IA n'invente ni constats ni scores. Elle reçoit les constats
déterministes du moteur de règles et les explique, les priorise et propose un plan.
"""

from __future__ import annotations

import json

from ..models import ScanResult
from ..scoring import maturity_level

SYSTEM_PROMPT = """Tu es un analyste sécurité Active Directory et PKI (ADCS) francophone.
Tu reçois les résultats d'un audit automatisé sous forme JSON. Règles impératives :
1. Tu ne t'appuies QUE sur les constats fournis. N'invente aucun constat, compte, chiffre ou règle.
2. Tu cites toujours l'identifiant de règle (ex: PKI-ESC1) quand tu parles d'un constat.
3. Tu expliques pour un public mixte : une phrase claire pour la direction, le détail technique pour l'équipe AD.
4. Tu priorises par impact réel : un chemin direct vers Domain Admin passe avant l'hygiène.
5. Tu décris les chemins d'attaque de façon défensive (ce qu'un attaquant pourrait faire, comment le détecter),
   sans commandes d'exploitation.
6. Si une information manque pour conclure, tu l'indiques dans "questions_a_verifier".
Réponds uniquement en JSON valide conforme au schéma demandé, en français."""

ANALYSIS_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "resume_executif": {"type": "string"},
        "niveau_risque": {"type": "string", "enum": ["Critique", "Élevé", "Modéré", "Faible"]},
        "top_risques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "pourquoi_prioritaire": {"type": "string"},
                    "scenario_attaque": {"type": "string"},
                    "detection": {"type": "string"},
                },
                "required": ["rule_id", "pourquoi_prioritaire", "scenario_attaque", "detection"],
            },
        },
        "plan_remediation": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "horizon": {"type": "string", "enum": ["Immédiat", "30 jours", "90 jours"]},
                    "action": {"type": "string"},
                    "regles": {"type": "array", "items": {"type": "string"}},
                    "effort": {"type": "string", "enum": ["Faible", "Moyen", "Élevé"]},
                },
                "required": ["horizon", "action", "regles", "effort"],
            },
        },
        "questions_a_verifier": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["resume_executif", "niveau_risque", "top_risques", "plan_remediation"],
}


def findings_payload(result: ScanResult, max_affected: int = 10) -> dict:
    """Version compacte et anonymisable du résultat envoyée au modèle (pas de dump AD brut)."""
    return {
        "domaine": result.domain,
        "score_global": result.global_score,
        "niveau": maturity_level(result.global_score),
        "scores_par_categorie": {k.value: v for k, v in result.scores.items()},
        "constats": [
            {
                "rule_id": f.rule_id,
                "categorie": f.category.value,
                "severite": f.severity.value,
                "titre": f.title,
                "description": f.description,
                "nb_objets": len(f.affected),
                "exemples": f.affected[:max_affected],
                "mitre": [m.technique for m in f.mitre],
                "remediation_reference": f.remediation,
                "detection_reference": f.detection,
            }
            for f in result.findings
        ],
        "classification_pki": [
            c.model_dump(mode="json") for c in result.pki_classification if c.risque.value in ("critical", "high")
        ],
    }


def build_user_prompt(result: ScanResult, context_snippets: list[str] | None = None) -> str:
    parts = ["Résultats de l'audit :", json.dumps(findings_payload(result), ensure_ascii=False, indent=1)]
    if context_snippets:
        parts += ["", "Connaissances internes pertinentes (politiques, guides) :", *context_snippets]
    parts += ["", "Produis l'analyse au format JSON demandé (5 risques prioritaires maximum)."]
    return "\n".join(parts)
