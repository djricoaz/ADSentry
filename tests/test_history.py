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


def test_dashboard_period(tmp_path):
    build(tmp_path)
    scans = load_all(tmp_path)
    full = dashboard(scans)
    first, last = scans[0][1].collected_at, scans[-1][1].collected_at
    span = (last - first).days
    short = dashboard(scans, days=max(1, span // 3))
    assert 1 <= short["kpis"]["scans"] < full["kpis"]["scans"] == short["kpis"]["scans_total"] == 7
    assert short["kpis"]["last_scan_id"] == full["kpis"]["last_scan_id"] == scans[-1][0]
    assert short["timeline"][-1] == full["timeline"][-1]  # le dernier scan est toujours inclus
    assert short["kpis"]["global_score"] == full["kpis"]["global_score"]
    assert dashboard(scans, days=span + 1)["kpis"]["scans"] == 7
    assert sum(full["kpis"]["severity"].values()) == full["timeline"][-1]["findings"]


def test_compare_reports(tmp_path):
    build(tmp_path)
    (_, first), (_, second) = load_all(tmp_path)[:2]
    c = compare(first, second)
    assert c["resolved"] and not c["new"]
    assert c["base"]["global_score"] >= c["target"]["global_score"]
    assert any(ch["removed"] for ch in c["changed"])
