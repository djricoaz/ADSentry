"""Génère le jeu d'entraînement (JSONL, format chat) pour le modèle analyste.

Deux sources :
1. **Synthétique** : on tire au hasard des combinaisons de règles du catalogue pour fabriquer de
   faux résultats d'audit, et on produit la réponse attendue à partir des textes d'expert du
   catalogue (description, remédiation, détection). Cela apprend au modèle le FORMAT, la
   PRIORISATION et l'ANCRAGE (ne citer que les règles présentes).
2. **Gold** : analyses rédigées ou relues par un humain (ai/dataset/gold/*.json, même format
   {"messages": [...]}) — ce sont elles qui apprennent la qualité rédactionnelle.

⚠ Aucune donnée d'un vrai client ne doit entrer dans ce jeu : uniquement du synthétique ou du
lab, éventuellement anonymisé.

Usage :  python ai/dataset/build_dataset.py --n 1500 --out ai/dataset/train.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime
from pathlib import Path

from adsentry.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from adsentry.models import SEVERITY_ORDER, Finding, Rule, ScanResult, Severity
from adsentry.rules.engine import load_rules
from adsentry.scoring import compute_scores, maturity_level

FAKE_OBJECTS = {
    "pki": ["UserSAN", "WebServerV1", "VPN-Users", "Corp-Auth", "SmartcardTmp", "CORP-ROOT-CA", "ISSUING-CA01"],
    "privileged_accounts": ["svc_backup", "adm_jdupont", "svc_sql", "SRV-APP01", "DC03"],
    "stale_objects": ["old.account", "PC-0042", "SRV-2012-01", "stagiaire2019"],
    "anomalies": ["svc_print", "j.martin", "corp.local", "DC01"],
    "trusts": ["filiale.local", "partenaire.com"],
    "entra_id": ["admin@contoso.com", "App-Automatisation", "invite@partenaire.com", "contoso.com"],
}

HORIZON = {Severity.CRITICAL: "Immédiat", Severity.HIGH: "30 jours"}
EFFORT_BY_PREFIX = {"PKI-": "Moyen", "P-": "Moyen", "A-": "Faible", "S-": "Élevé", "T-": "Faible", "E-": "Faible"}


def fake_result(rules: list[Rule], rng: random.Random) -> ScanResult:
    chosen = rng.sample([r for r in rules if not r.manual], k=rng.randint(2, 12))
    findings = [
        Finding(
            rule_id=r.id,
            category=r.category,
            severity=r.severity,
            title=r.title,
            description=r.description,
            points=r.points,
            affected=rng.sample(pool := FAKE_OBJECTS[r.category.value], k=rng.randint(1, min(3, len(pool)))),
            mitre=r.mitre,
            remediation=r.remediation,
            detection=r.detection,
        )
        for r in chosen
    ]
    scores, global_score = compute_scores(findings)
    now = datetime.now(UTC)
    return ScanResult(
        domain="lab.local",
        collected_at=now,
        analyzed_at=now,
        findings=findings,
        scores=scores,
        global_score=global_score,
    )


def expected_answer(res: ScanResult) -> dict:
    ordered = sorted(res.findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.points))
    top = ordered[:5]
    crit = [f for f in res.findings if f.severity == Severity.CRITICAL]
    resume = (
        f"Le domaine {res.domain} obtient un score de risque de {res.global_score}/100 "
        f"({maturity_level(res.global_score).lower()}). "
        + (
            f"{len(crit)} constat(s) critique(s) offrent un chemin direct vers la compromission du domaine, "
            f"en priorité {', '.join(f.rule_id for f in crit[:3])}. "
            if crit
            else "Aucun chemin direct vers Domain Admin n'a été détecté ; les constats relèvent de l'hygiène. "
        )
        + "Les actions ci-dessous sont classées par urgence."
    )
    return {
        "resume_executif": resume,
        "niveau_risque": maturity_level(res.global_score),
        "top_risques": [
            {
                "rule_id": f.rule_id,
                "pourquoi_prioritaire": f"Sévérité {f.severity.value}, {len(f.affected)} objet(s) concerné(s) "
                f"({', '.join(f.affected)}). {f.description}",
                "scenario_attaque": f.description,
                "detection": f.detection or "Pas de détection spécifique documentée : renforcer la journalisation.",
            }
            for f in top
        ],
        "plan_remediation": [
            {
                "horizon": HORIZON.get(f.severity, "90 jours"),
                "action": f.remediation,
                "regles": [f.rule_id],
                "effort": next(v for k, v in EFFORT_BY_PREFIX.items() if f.rule_id.startswith(k)),
            }
            for f in ordered
        ],
        "questions_a_verifier": [],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=Path("ai/dataset/train.jsonl"))
    ap.add_argument("--gold", type=Path, default=Path("ai/dataset/gold"))
    args = ap.parse_args()

    rng = random.Random(args.seed)
    rules = load_rules()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.out.open("w", encoding="utf-8") as fh:
        for _ in range(args.n):
            res = fake_result(rules, rng)
            sample = {
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(res)},
                    {"role": "assistant", "content": json.dumps(expected_answer(res), ensure_ascii=False)},
                ]
            }
            fh.write(json.dumps(sample, ensure_ascii=False) + "\n")
            count += 1
        for gold in sorted(args.gold.glob("*.json")) if args.gold.exists() else []:
            # les exemples gold sont répétés 3x pour peser davantage
            line = json.dumps(json.loads(gold.read_text(encoding="utf-8")), ensure_ascii=False)
            for _ in range(3):
                fh.write(line + "\n")
                count += 1
    print(f"{count} exemples écrits dans {args.out}")


if __name__ == "__main__":
    main()
