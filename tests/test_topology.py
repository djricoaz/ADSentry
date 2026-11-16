"""Topologie : chemins vers le Tier 0 et carte des approbations (fonctions pures, données de démonstration)."""

from __future__ import annotations

import json

import pytest
from conftest import load_raw

from adsentry.models import Snapshot
from adsentry.topology import build


@pytest.fixture(scope="module")
def vuln_topo():
    return build(Snapshot.model_validate(load_raw("vulnerable")))


@pytest.fixture(scope="module")
def hard_topo():
    return build(Snapshot.model_validate(load_raw("hardened")))


def _labels(t):
    return {n["id"]: n["label"] for n in t["graph"]["nodes"]}


def test_low_privileged_path_to_domain_admins(vuln_topo):
    g, lab = vuln_topo["graph"], _labels(vuln_topo)
    chains = [[lab[n] for n in p["nodes"]] for p in g["paths"]]
    assert ["Authenticated Users", "helpdesk.lead", "Domain Admins"] in chains
    first = g["paths"][0]
    assert lab[first["nodes"][0]] in ("Authenticated Users", "Domain Users")  # les plus graves en premier
    assert g["stats"]["low_priv_paths"] >= 2


def test_edges_and_flags(vuln_topo):
    g, lab = vuln_topo["graph"], _labels(vuln_topo)
    kinds = {(lab[e["source"]], e["kind"], lab[e["target"]]) for e in g["edges"]}
    assert ("backup_op", "DCSync", "corp.local") in kinds
    assert ("j.doe", "GenericAll", "AdminSDHolder") in kinds
    assert ("SRV-OLD", "Unconstrained", "corp.local") in kinds
    nodes = {n["label"]: n for n in g["nodes"]}
    assert "spn" in nodes["svc_web"]["flags"]
    assert nodes["Domain Admins"]["tier0"] and nodes["Domain Admins"]["distance"] == 0
    assert nodes["helpdesk.lead"]["exposed"] and nodes["helpdesk.lead"]["distance"] == 1
    # chaque arête marquée « vers le Tier 0 » rapproche d'un cran
    by_id = {n["id"]: n for n in g["nodes"]}
    for e in g["edges"]:
        if e["to_tier0"]:
            assert by_id[e["target"]]["distance"] == by_id[e["source"]]["distance"] - 1


def test_hardened_domain_has_no_exposure(hard_topo):
    s = hard_topo["graph"]["stats"]
    assert s["exposed"] == 0 and s["low_priv_paths"] == 0 and s["risky_accounts"] == 0
    assert hard_topo["graph"]["paths"] == []


def test_trust_map(vuln_topo):
    tm = vuln_topo["trust_map"]
    trusts = {t["target"]: t for t in tm["trusts"]}
    partner = trusts["partner.local"]
    assert partner["kind"] == "external" and partner["transitive"] is False
    assert {r["label"] for r in partner["risks"]} >= {"Filtrage SID désactivé", "Délégation de TGT autorisée"}
    assert partner["severity"] == "high"
    assert trusts["paris.corp.local"]["kind"] == "within_forest" and trusts["paris.corp.local"]["sid_filtering"] is None
    assert trusts["LEGACYNT4"]["access"] == [{"from": "LEGACYNT4", "to": "corp.local"}]  # sortante : LEGACYNT4 accède
    forests = {f["name"]: f["domains"] for f in tm["forests"] if f["name"]}
    assert set(forests["corp.local"]) == {"corp.local", "paris.corp.local", "lyon.corp.local"}
    assert forests["filiale.example"] == ["filiale.example"]


def test_unknown_trust_kind_is_not_guessed():
    raw = load_raw("vulnerable")
    for t in raw["trusts"]:
        t.pop("kind", None)
    tm = build(Snapshot.model_validate(raw))["trust_map"]
    t = next(x for x in tm["trusts"] if x["target"] == "partner.local")
    assert t["kind"] is None and t["kind_label"] == "Type non collecté" and t["transitive"] is None


def test_graph_is_json_serialisable(vuln_topo):
    assert json.loads(json.dumps(vuln_topo))["domain"] == "corp.local"


def test_api_topology(tmp_path, monkeypatch):
    pytest.importorskip("multipart")
    import importlib

    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path))
    monkeypatch.setenv("ADSENTRY_DATA", str(tmp_path / "scans"))
    from fastapi.testclient import TestClient

    import adsentry.api.main as api
    import adsentry.appliance.auth as auth
    import adsentry.appliance.config as config
    import adsentry.appliance.jobs as jobs
    import adsentry.appliance.runner as runner

    for mod in (config, auth, jobs, runner, api):
        importlib.reload(mod)
    auth.UserStore().create("admin", "Adm1n-Passw0rd!", auth.Role.admin)
    auth.UserStore().create("lecteur", "V1ewer-Passw0rd!", auth.Role.viewer)
    admin = TestClient(api.app, headers={"X-ADSentry": "1"})
    admin.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-Passw0rd!"})
    viewer = TestClient(api.app, headers={"X-ADSentry": "1"})
    viewer.post("/api/auth/login", json={"username": "lecteur", "password": "V1ewer-Passw0rd!"})
    payload = json.dumps(load_raw("vulnerable")).encode()
    scan_id = admin.post("/api/scans", files={"snapshot": ("s.json", payload, "application/json")}).json()["id"]
    topo = viewer.get(f"/api/scans/{scan_id}/topology").json()  # visible par les lecteurs
    assert topo["graph"]["stats"]["low_priv_paths"] >= 2
    assert [s["id"] for s in viewer.get("/api/scans").json()] == [scan_id]  # le graphe n'est pas listé comme un scan
    assert admin.delete(f"/api/scans/{scan_id}").status_code == 200
    assert not (tmp_path / "scans" / f"{scan_id}.graph.json").exists()
