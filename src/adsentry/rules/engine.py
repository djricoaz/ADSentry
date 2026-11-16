"""Chargement du catalogue YAML et exécution des règles (déterministe, sans IA)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

from ..models import Finding, Rule, ScanResult, Snapshot
from ..pki.classification import classify_templates
from ..scoring import compute_scores
from .registry import load_all_checks

CATALOG_DIR = Path(__file__).parent / "catalog"


def load_rules(catalog_dir: Path = CATALOG_DIR) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(catalog_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        rules.extend(Rule.model_validate(item) for item in data)
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Identifiants de règles en double : {sorted(duplicates)}")
    return rules


def run_rules(snapshot: Snapshot, rules: list[Rule]) -> tuple[list[Finding], list[str], list[str]]:
    checks = load_all_checks()
    findings: list[Finding] = []
    manual: list[str] = []
    skipped: list[str] = []
    for rule in rules:
        if rule.manual:
            manual.append(rule.id)
            continue
        if (rule.scope == "ad" and snapshot.domain is None) or (rule.scope == "entra" and snapshot.entra is None):
            skipped.append(rule.id)
            continue
        fn = checks.get(rule.check)
        if fn is None:
            raise KeyError(f"La règle {rule.id} référence un contrôle inconnu : {rule.check}")
        result = fn(snapshot, rule.params)
        if result:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    points=rule.points,
                    affected=sorted(set(result.affected)),
                    details=result.details,
                    mitre=rule.mitre,
                    remediation=rule.remediation,
                    detection=rule.detection,
                )
            )
    return findings, manual, skipped


def target_name(snapshot: Snapshot) -> str:
    parts = [snapshot.domain.name] if snapshot.domain else []
    if snapshot.entra:
        parts.append(f"Entra:{snapshot.entra.name}")
    return " + ".join(parts) or "inconnu"


def analyze(snapshot: Snapshot, rules: list[Rule] | None = None) -> ScanResult:
    rules = rules if rules is not None else load_rules()
    findings, manual, skipped = run_rules(snapshot, rules)
    scores, global_score = compute_scores(findings)
    return ScanResult(
        domain=target_name(snapshot),
        ad_domain=snapshot.domain.name if snapshot.domain else None,
        tenant_id=snapshot.entra.tenant_id if snapshot.entra else None,
        collected_at=snapshot.collected_at,
        analyzed_at=datetime.now(UTC),
        findings=findings,
        scores=scores,
        global_score=global_score,
        pki_classification=classify_templates(snapshot, findings),
        manual_checks=manual,
        not_evaluated=skipped,
    )
