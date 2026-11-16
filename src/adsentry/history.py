"""Historisation des scans : résumés, KPI, maturité, cycle de vie des constats et comparaison de rapports.

Tout est calculé à partir des ScanResult stockés (aucune base de données nécessaire en v0.x).

Niveau de maturité (1 à 5), déterministe et explicable :
    1 Initial    : au moins un constat critique
    2 Fragile    : au moins un constat élevé
    3 Défini     : au moins un constat moyen
    4 Maîtrisé   : seulement des constats faibles ou informatifs
    5 Optimisé   : aucun constat
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .models import Category, Finding, ScanResult, Severity

SEV_RANK = {s.value: i for i, s in enumerate(Severity)}
MATURITY_LABELS = {1: "Initial", 2: "Fragile", 3: "Défini", 4: "Maîtrisé", 5: "Optimisé"}
_BLOCKING = [(Severity.CRITICAL, 1), (Severity.HIGH, 2), (Severity.MEDIUM, 3)]


def maturity(findings: list[Finding]) -> int:
    present = {f.severity for f in findings}
    for sev, level in _BLOCKING:
        if sev in present:
            return level
    return 4 if findings else 5


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def summarize(scan_id: str, r: ScanResult) -> dict:
    level = maturity(r.findings)
    return {
        "id": scan_id,
        "domain": r.domain,
        "analyzed_at": r.analyzed_at.isoformat(),
        "collected_at": r.collected_at.isoformat(),
        "global_score": r.global_score,
        "scores": {k.value: v for k, v in r.scores.items()},
        "severity": severity_counts(r.findings),
        "findings": len(r.findings),
        "objects": sum(len(f.affected) for f in r.findings),
        "maturity": level,
        "maturity_label": MATURITY_LABELS[level],
    }


def load_all(data_dir: Path) -> list[tuple[str, ScanResult]]:
    out = []
    for p in data_dir.glob("*.json"):
        if p.name.endswith((".ai.json", ".graph.json")):
            continue
        try:
            out.append((p.stem, ScanResult.model_validate_json(p.read_text(encoding="utf-8"))))
        except ValueError:
            continue
    return sorted(out, key=lambda x: x[1].collected_at)


# ----------------------------------------------------------------------------- comparaison


def compare(base: ScanResult, target: ScanResult) -> dict:
    """Ce qui a changé entre deux rapports (base = plus ancien, target = plus récent)."""
    a = {f.rule_id: f for f in base.findings}
    b = {f.rule_id: f for f in target.findings}

    def brief(f: Finding) -> dict:
        return {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category.value,
            "objects": len(f.affected),
            "points": f.points,
        }

    changed = []
    for rid in sorted(a.keys() & b.keys()):
        added = sorted(set(b[rid].affected) - set(a[rid].affected))
        removed = sorted(set(a[rid].affected) - set(b[rid].affected))
        if added or removed or a[rid].severity != b[rid].severity:
            changed.append(
                {
                    **brief(b[rid]),
                    "added": added,
                    "removed": removed,
                    "before": len(a[rid].affected),
                    "after": len(b[rid].affected),
                }
            )
    return {
        "base": {
            "domain": base.domain,
            "date": base.collected_at.isoformat(),
            "global_score": base.global_score,
            "maturity": maturity(base.findings),
        },
        "target": {
            "domain": target.domain,
            "date": target.collected_at.isoformat(),
            "global_score": target.global_score,
            "maturity": maturity(target.findings),
        },
        "scores": {c.value: {"before": base.scores.get(c, 0), "after": target.scores.get(c, 0)} for c in Category},
        "severity": {"before": severity_counts(base.findings), "after": severity_counts(target.findings)},
        "new": sorted((brief(b[r]) for r in b.keys() - a.keys()), key=lambda x: -x["points"]),
        "resolved": sorted((brief(a[r]) for r in a.keys() - b.keys()), key=lambda x: -x["points"]),
        "changed": changed,
    }


# ----------------------------------------------------------------------------- tableau de bord


def dashboard(scans: list[tuple[str, ScanResult]], domain: str | None = None, days: int | None = None) -> dict:
    """KPI, séries temporelles et cycle de vie des constats pour un périmètre.

    days : ne retenir que les scans des N jours précédant le dernier scan du périmètre (le dernier est toujours
    inclus) ; tous les indicateurs sont alors recalculés sur cette période.
    """
    domains = sorted({r.domain for _, r in scans})
    domain = domain or (scans[-1][1].domain if scans else None)
    series = [(sid, r) for sid, r in scans if r.domain == domain]
    if not series:
        return {"domains": domains, "domain": domain, "timeline": [], "kpis": {}, "lifecycle": [], "events": []}
    total_scans = len(series)
    if days:
        cutoff = series[-1][1].collected_at - timedelta(days=days)
        series = [(sid, r) for sid, r in series if r.collected_at >= cutoff]

    timeline = [summarize(sid, r) for sid, r in series]

    # Cycle de vie : première apparition, dernière apparition, corrigé / réapparu
    life: dict[str, dict] = {}
    previous: set[str] = set()
    events = []
    for sid, r in series:
        current = {f.rule_id: f for f in r.findings}
        new, fixed = sorted(current.keys() - previous), sorted(previous - current.keys())
        for rid in new:
            entry = life.setdefault(rid, {"rule_id": rid, "first_seen": r.collected_at, "reopened": 0})
            if entry.get("resolved_at"):
                entry["reopened"] += 1
                entry["resolved_at"] = None
        for rid in fixed:
            life[rid]["resolved_at"] = r.collected_at
        for rid, f in current.items():
            life[rid].update(
                last_seen=r.collected_at,
                title=f.title,
                severity=f.severity.value,
                category=f.category.value,
                objects=len(f.affected),
            )
        if events or new or fixed:
            events.append(
                {
                    "id": sid,
                    "date": r.collected_at.isoformat(),
                    "new": len(new) if events else 0,
                    "resolved": len(fixed),
                    "global_score": r.global_score,
                    "maturity": maturity(r.findings),
                    "first": not events,
                }
            )
        previous = set(current)

    now: datetime = series[-1][1].collected_at
    open_items = [v for v in life.values() if not v.get("resolved_at")]
    closed = [v for v in life.values() if v.get("resolved_at")]
    mttr = round(sum((v["resolved_at"] - v["first_seen"]).days for v in closed) / len(closed)) if closed else None
    last, prev = timeline[-1], timeline[-2] if len(timeline) > 1 else None

    def delta(key: str):
        return None if prev is None else last[key] - prev[key]

    kpis = {
        "global_score": last["global_score"],
        "global_score_delta": delta("global_score"),
        "maturity": last["maturity"],
        "maturity_label": last["maturity_label"],
        "maturity_delta": delta("maturity"),
        "critical": last["severity"]["critical"],
        "critical_delta": None if prev is None else last["severity"]["critical"] - prev["severity"]["critical"],
        "open": len(open_items),
        "resolved_total": len(closed),
        "remediation_rate": round(100 * len(closed) / len(life)) if life else None,
        "mttr_days": mttr,
        "oldest_critical_days": max(
            ((now - v["first_seen"]).days for v in open_items if v.get("severity") == "critical"), default=None
        ),
        "scans": len(timeline),
        "scans_total": total_scans,
        "last_scan_id": series[-1][0],
        "last_collected_at": now.isoformat(),
        "objects": last["objects"],
        "severity": last["severity"],
    }
    lifecycle = sorted(
        (
            {
                **v,
                "first_seen": v["first_seen"].isoformat(),
                "last_seen": v["last_seen"].isoformat(),
                "resolved_at": v["resolved_at"].isoformat() if v.get("resolved_at") else None,
                "age_days": (now - v["first_seen"]).days,
            }
            for v in life.values()
        ),
        key=lambda x: (x["resolved_at"] is not None, SEV_RANK.get(x.get("severity"), 9), -x["age_days"]),
    )
    return {
        "domains": domains,
        "domain": domain,
        "timeline": timeline,
        "kpis": kpis,
        "lifecycle": lifecycle,
        "events": list(reversed(events)),
    }


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
