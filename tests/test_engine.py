"""Moteur de règles sur les domaines synthétiques « vulnérable » et « durci »."""

from __future__ import annotations

import json

import pytest
from conftest import by_id, load_raw

from adsentry.ai.ollama_client import guard_against_hallucinations
from adsentry.mitre.navigator import build_layer
from adsentry.models import Category, Snapshot
from adsentry.rules.engine import analyze

# Règles qui ne PEUVENT pas se déclencher dans le domaine vulnérable car elles contredisent
# une autre règle (testées par variante plus bas).
EXPECTED_SILENT = {"A-NOT-ENOUGH-DC", "A-PROTECTED-USERS-MISSING", "E-GUEST-NOT-RESTRICTED"}


def test_every_rule_fires_on_vulnerable_domain(vuln, rules):
    evaluated = {r.id for r in rules if not r.manual} - set(vuln.not_evaluated)
    fired = {f.rule_id for f in vuln.findings}
    assert sorted(evaluated - fired - EXPECTED_SILENT) == []
    assert not (fired & EXPECTED_SILENT)
    assert vuln.global_score == 100


def test_nothing_fires_on_hardened_domain(hardened):
    assert {f.rule_id: f.affected for f in hardened.findings} == {}
    assert hardened.global_score == 0


@pytest.mark.parametrize(
    "rule_id, patch",
    [
        ("A-NOT-ENOUGH-DC", lambda d: d.update(computers=[c for c in d["computers"] if c["name"] != "DC02"])),
        ("A-PROTECTED-USERS-MISSING", lambda d: d["domain"].update(protected_users_exists=False)),
        ("E-GUEST-NOT-RESTRICTED", lambda d: d["entra"].update(guest_role="limited")),
    ],
)
def test_conflicting_rules_by_variant(rule_id, patch):
    data = load_raw("hardened")
    patch(data)
    res = analyze(Snapshot.model_validate(data))
    assert rule_id in by_id(res)


# ---------------------------------------------------------------- PKI


def test_pki_esc_exact(vuln):
    pki = {fid: f.affected for fid, f in by_id(vuln).items() if fid.startswith("PKI-ESC")}
    assert pki == {
        "PKI-ESC1": ["VulnAuth"],
        "PKI-ESC2": ["AnyPurpose"],
        "PKI-ESC3": ["EnrollAgent"],
        "PKI-ESC4": ["WritableTpl"],
        "PKI-ESC5": ["CN=NTAuthCertificates"],
        "PKI-ESC6": ["CORP-CA"],
        "PKI-ESC7": ["LEGACY-CA"],
        "PKI-ESC8": ["LEGACY-CA"],
        "PKI-ESC9": ["NoSecExt"],
        "PKI-ESC10": ["Contrôleurs de domaine (Kerberos)"],
        "PKI-ESC11": ["LEGACY-CA"],
        "PKI-ESC13": ["PolicyLinked"],
        "PKI-ESC14": ["m.martin"],
        "PKI-ESC15": ["WebServer"],
        "PKI-ESC16": ["LEGACY-CA"],
    }


def test_esc_negatives(vuln):
    esc1 = by_id(vuln)["PKI-ESC1"].affected
    assert "ApprovalRequired" not in esc1 and "Unpublished" not in esc1 and "User" not in esc1
    assert "a.strong" not in by_id(vuln)["PKI-ESC14"].affected


def test_esc9_suppressed_when_strong_binding_enforced():
    data = load_raw("vulnerable")
    data["dc_registry"]["strong_cert_binding_enforcement"] = 2
    res = by_id(analyze(Snapshot.model_validate(data)))
    assert "PKI-ESC9" not in res and "PKI-ESC10" not in res


def test_template_classification(vuln):
    cls = {c.template: c for c in vuln.pki_classification}
    assert cls["VulnAuth"].classe.startswith("T0") and cls["VulnAuth"].exposition == "Large"
    assert cls["User"].classe == "Authentification"
    assert cls["Unpublished"].classe.startswith("Inactif")
    assert cls["WeakKey"].classe == "Usage restreint"
    assert vuln.pki_classification[0].risque.value == "critical"


# ---------------------------------------------------------------- AD : quelques assertions précises


def test_ad_precise(vuln):
    f = by_id(vuln)
    assert f["P-DCSYNC-NON-DC"].affected == ["backup_op"]  # Domain Controllers exclu
    assert f["P-ADMIN-KERBEROASTABLE"].affected == ["svc_sql_admin"]
    assert f["A-ASREP-ROASTABLE"].affected == ["j.doe"]  # adm_old (admin) relève de P-ADMIN-NO-PREAUTH
    assert f["P-ADMIN-NO-PREAUTH"].affected == ["adm_old"]
    assert f["T-SID-HISTORY-SAME-DOMAIN"].affected == ["hidden.admin"]
    assert f["T-SID-HISTORY-DANGEROUS"].affected == ["migrated.user"]
    assert f["T-SID-HISTORY-UNKNOWN-DOMAIN"].affected == ["migrated.user"]
    assert "Helpdesk" not in f["P-DELEGATION-EVERYONE"].details.get("OU=Paris,DC=corp,DC=local", [""])[0]
    assert "Authenticated Users" in f["P-CONTROL-PATH-EVERYONE"].affected
    assert f["S-OBSOLETE-OS"].affected == ["SRV-OLD", "WS01"]  # WS01 = Windows 11 Pro 24H2, hors support
    assert "PC-45" not in f["S-OBSOLETE-OS"].affected  # Enterprise 24H2 encore supporté
    assert f["A-NTLMV1"].affected == ["Default Domain Controllers Policy = 3"]
    assert f["A-AUDIT-DC"].affected and "Audit Logon" not in f["A-AUDIT-DC"].affected


def test_entra_precise(vuln):
    f = by_id(vuln)
    assert f["E-SYNCED-PRIVILEGED"].affected == ["ga1@corp.com"]
    assert f["E-PRIVILEGED-GUESTS"].affected == ["partner@ext.com"]
    assert f["E-APP-CRITICAL-PERMISSIONS"].affected == ["OldAutomation"]
    assert f["E-APP-OWNER-NON-ADMIN"].details["OldAutomation"] == ["dev1@corp.com"]
    assert f["E-SP-PASSWORD-CREDENTIALS"].affected == ["SP-Persist"]


# ---------------------------------------------------------------- périmètres


def test_ad_only_snapshot_skips_entra_rules(rules):
    data = load_raw("vulnerable")
    data["entra"] = None
    res = analyze(Snapshot.model_validate(data), rules)
    assert all(r.startswith("E-") for r in res.not_evaluated)
    assert not any(f.rule_id.startswith("E-") for f in res.findings)


def test_entra_only_snapshot(rules):
    data = load_raw("vulnerable")
    snap = Snapshot.model_validate({"collected_at": data["collected_at"], "entra": data["entra"]})
    res = analyze(snap, rules)
    assert res.domain == "Entra:contoso"
    assert {f.category for f in res.findings} == {Category.ENTRA}
    assert res.scores[Category.ENTRA] == 100


def test_unknown_data_never_fires(rules):
    """Un snapshot minimal (données non collectées = None) ne doit déclencher aucune règle GPO/sonde/DNS."""
    data = load_raw("hardened")
    data.update(gpos=None, dns_zones=None, dc_probes=[], tls_probes=[])
    res = analyze(Snapshot.model_validate(data), rules)
    sources = {r.id: r.source for r in rules}
    assert [f.rule_id for f in res.findings if sources[f.rule_id] in ("gpo", "probe", "dns")] == []


# ---------------------------------------------------------------- MITRE / IA / API


def test_navigator_layer(vuln):
    techs = {t["techniqueID"]: t for t in build_layer(vuln)["techniques"]}
    assert techs["T1649"]["score"] == 100
    assert {"T1558.003", "T1003.006", "T1556.007", "T1098.003"} <= set(techs)


def test_hallucination_guard(vuln):
    fake = {
        "top_risques": [
            {"rule_id": "PKI-ESC1", "pourquoi_prioritaire": "x", "scenario_attaque": "x", "detection": "x"},
            {"rule_id": "PKI-ESC99", "pourquoi_prioritaire": "x", "scenario_attaque": "x", "detection": "x"},
        ],
        "plan_remediation": [
            {"horizon": "Immédiat", "action": "x", "regles": ["PKI-ESC1", "FAKE-1"], "effort": "Faible"}
        ],
    }
    out = guard_against_hallucinations(fake, vuln)
    assert [r["rule_id"] for r in out["top_risques"]] == ["PKI-ESC1"]
    assert out["_controle_qualite"]["regles_inventees_retirees"] == ["FAKE-1", "PKI-ESC99"]


def test_ollama_client_structured_output(vuln):
    import httpx

    from adsentry.ai.ollama_client import OllamaClient, analyze_with_llm

    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.update(json.loads(request.content))
        answer = {
            "resume_executif": "x",
            "niveau_risque": "Critique",
            "plan_remediation": [],
            "top_risques": [
                {"rule_id": "E-ADMIN-NO-MFA", "pourquoi_prioritaire": "x", "scenario_attaque": "x", "detection": "x"}
            ],
        }
        return httpx.Response(200, json={"message": {"role": "assistant", "content": json.dumps(answer)}})

    client = OllamaClient(base_url="http://ollama.test", model="adsentry-analyst")
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    out = analyze_with_llm(vuln, client=client)
    assert sent["stream"] is False and sent["format"]["required"][0] == "resume_executif"
    assert out["_controle_qualite"]["fiable"] is True


def test_api_roundtrip(tmp_path, monkeypatch):
    pytest.importorskip("multipart")
    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path))
    monkeypatch.setenv("ADSENTRY_DATA", str(tmp_path / "scans"))
    import importlib

    from fastapi.testclient import TestClient

    import adsentry.api.main as api
    import adsentry.appliance.auth as auth
    import adsentry.appliance.config as config
    import adsentry.appliance.jobs as jobs

    for mod in (config, auth, jobs, api):
        importlib.reload(mod)
    auth.UserStore().create("admin", "Adm1n-Passw0rd!", auth.Role.admin)
    client = TestClient(api.app, headers={"X-ADSentry": "1"})
    client.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-Passw0rd!"})
    payload = json.dumps(load_raw("vulnerable")).encode()
    r = client.post("/api/scans", files={"snapshot": ("s.json", payload, "application/json")})
    assert r.status_code == 200
    scan_id = r.json()["id"]
    assert client.get("/api/scans").json()[0]["id"] == scan_id
    assert client.get(f"/api/scans/{scan_id}/navigator").json()["techniques"]
    assert client.get("/api/health").json()["status"] == "ok"
