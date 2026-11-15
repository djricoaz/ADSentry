"""Historisation : maturité, KPI, cycle de vie, comparaison de rapports."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))

from build_history import build  # noqa: E402

from adsentry.history import compare, dashboard, load_all, maturity  # noqa: E402


def test_maturity_levels(vuln, hardened):
    assert maturity(vuln.findings) == 1
    assert maturity(hardened.findings) == 5


def test_dashboard_and_lifecycle(tmp_path):
    build(tmp_path)
    scans = load_all(tmp_path)
    assert len(scans) == 7
    d = dashboard(scans)
    assert d["domain"] == "corp.local + Entra:contoso"
    assert [t["global_score"] for t in d["timeline"]][0] == 100
    k = d["kpis"]
    assert k["scans"] == 7 and k["resolved_total"] > 50 and 0 < k["remediation_rate"] < 100
    assert k["mttr_days"] > 0
    assert d["timeline"][-1]["findings"] < d["timeline"][0]["findings"]
    reopened = [x for x in d["lifecycle"] if x["reopened"]]
    assert {x["rule_id"] for x in reopened} >= {"P-DCSYNC-NON-DC"} or any(
        e["new"] for e in d["events"] if not e["first"]
    )


def test_compare_reports(tmp_path):
    build(tmp_path)
    (_, first), (_, second) = load_all(tmp_path)[:2]
    c = compare(first, second)
    assert c["resolved"] and not c["new"]
    assert c["base"]["global_score"] >= c["target"]["global_score"]
    assert any(ch["removed"] for ch in c["changed"])
