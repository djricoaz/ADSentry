"""Fabrique un historique de démonstration (7 scans mensuels d'un même domaine qui s'améliore).

python tests/fixtures/build_history.py /var/lib/adsentry/scans
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from adsentry.models import SEVERITY_ORDER, Snapshot
from adsentry.rules.engine import analyze
from adsentry.scoring import compute_scores

FIXTURE = Path(__file__).parent / "vulnerable_snapshot.json"


def build(out: Path) -> list[Path]:
    base = analyze(Snapshot.model_validate_json(FIXTURE.read_text(encoding="utf-8")))
    ordered = sorted(base.findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.points, f.rule_id))
    # part des constats corrigés à chaque scan (cumulatif) ; le 4e scan contient une régression
    fixed_share = [0.0, 0.15, 0.32, 0.42, 0.58, 0.72, 0.86]
    paths = []
    out.mkdir(parents=True, exist_ok=True)
    for i, share in enumerate(fixed_share):
        n_fixed = int(len(ordered) * share)
        fixed = {f.rule_id for f in ordered[:n_fixed]}  # les plus graves d'abord
        if i == 3:  # régression : deux constats corrigés réapparaissent
            fixed -= {"P-DCSYNC-NON-DC", "A-SPOOLER-DC"}
        findings = []
        for f in base.findings:
            if f.rule_id in fixed:
                continue
            keep = max(1, len(f.affected) - i) if len(f.affected) > 1 else 1
            findings.append(f.model_copy(update={"affected": f.affected[:keep]}))
        scores, global_score = compute_scores(findings)
        date = base.collected_at - timedelta(days=30 * (len(fixed_share) - 1 - i))
        r = base.model_copy(
            update={
                "findings": findings,
                "scores": scores,
                "global_score": global_score,
                "collected_at": date,
                "analyzed_at": date,
            }
        )
        path = out / f"{date:%Y%m%d}-0217-corp.json"
        path.write_text(r.model_dump_json(indent=1), encoding="utf-8")
        paths.append(path)
    return paths


if __name__ == "__main__":
    for p in build(Path(sys.argv[1] if len(sys.argv) > 1 else "demo-scans")):
        print("écrit", p)
