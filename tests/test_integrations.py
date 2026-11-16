"""Intégrations : notifications, SIEM (Syslog CEF, Splunk), ITSM (Jira, ServiceNow), jetons d'API, Swagger."""

from __future__ import annotations

import importlib
import json
import socket

import httpx
import pytest
from conftest import load_raw

pytest.importorskip("fastapi")
pytest.importorskip("multipart")

H = {"X-ADSentry": "1"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path))
    monkeypatch.setenv("ADSENTRY_DATA", str(tmp_path / "scans"))
    monkeypatch.setenv("ADSENTRY_CONFIG", str(tmp_path / "etc"))
    from fastapi.testclient import TestClient

    import adsentry.api.main as api
    import adsentry.appliance.auth as auth
    import adsentry.appliance.config as config
    import adsentry.appliance.jobs as jobs
    import adsentry.appliance.runner as runner

    for mod in (config, auth, jobs, runner, api):
        importlib.reload(mod)

    calls: list[httpx.Request] = []
    responses: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        for prefix, resp in responses.items():
            if str(request.url).startswith(prefix):
                return resp(request) if callable(resp) else resp
        return httpx.Response(404)

    real = httpx.Client
    import adsentry.integrations.senders as senders

    monkeypatch.setattr(senders, "_client", lambda verify=True: real(transport=httpx.MockTransport(handler)))
    auth.UserStore().create("admin", "Adm1n-Passw0rd!", auth.Role.admin)
    auth.UserStore().create("lecteur", "V1ewer-Passw0rd!", auth.Role.viewer)

    def login(u, p):
        c = TestClient(api.app, headers=H)
        assert c.post("/api/auth/login", json={"username": u, "password": p}).status_code == 200
        return c

    class E:
        pass

    e = E()
    e.api, e.jobs, e.runner, e.tmp, e.calls, e.responses = api, jobs, runner, tmp_path, calls, responses
    e.admin, e.viewer = login("admin", "Adm1n-Passw0rd!"), login("lecteur", "V1ewer-Passw0rd!")
    e.anon = TestClient(api.app)

    def run_all():
        store = jobs.JobStore()
        done = []
        while (job := store.claim_next()) is not None:
            done.append(runner.execute_job(job, store))
        return done

    def import_scan(raw=None):
        payload = json.dumps(raw or load_raw("vulnerable")).encode()
        scan = e.admin.post("/api/scans", files={"snapshot": ("s.json", payload, "application/json")}).json()["id"]
        return scan, run_all()

    e.run_all, e.import_scan = run_all, import_scan
    return e


def configure(e, kind, config, secret=None):
    r = e.admin.put(f"/api/integrations/{kind}", json={"config": config, "secret": secret})
    assert r.status_code == 200, r.text
    return r.json()


# ----------------------------------------------------------------------------- droits et secrets


def test_integrations_admin_only_and_secrets_hidden(env):
    assert env.viewer.get("/api/integrations").status_code == 403
    assert env.viewer.put("/api/integrations/jira", json={"config": {}}).status_code == 403
    view = configure(
        env,
        "jira",
        {"enabled": True, "url": "https://jira.example", "project": "SEC", "username": "bot@x"},
        "J1r4-T0ken",
    )
    assert view["secrets"]["jira"] is True and "J1r4-T0ken" not in json.dumps(view)
    for f in env.tmp.rglob("*"):
        if f.is_file():
            assert "J1r4-T0ken" not in f.read_text(errors="ignore"), f
    bad = env.admin.put("/api/integrations/webhook", json={"config": {"url": "ftp://x"}})
    assert bad.status_code == 400 and "https://" in bad.json()["detail"]
    assert env.admin.put("/api/integrations/inconnu", json={"config": {}}).status_code == 404


# ----------------------------------------------------------------------------- notifications


def test_notification_center(env):
    scan, done = env.import_scan()
    assert [j.kind for j in done] == ["notify"] and done[0].status == "succeeded"
    n = env.viewer.get("/api/notifications").json()
    assert n["unread"] >= 1 and n["items"][0]["title"].startswith("Scan terminé : corp.local")
    env.viewer.post("/api/notifications/read")
    assert env.viewer.get("/api/notifications").json()["unread"] == 0
    assert env.admin.get("/api/notifications").json()["unread"] >= 1  # marqueur de lecture par utilisateur


def test_webhook_and_email(env, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, **kw):
            self.host = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent.append("starttls")

        def login(self, u, p):
            sent.append(("login", u, p))

        def send_message(self, msg):
            sent.append(msg)

    import adsentry.integrations.senders as senders

    monkeypatch.setattr(senders.smtplib, "SMTP", FakeSMTP)
    configure(
        env,
        "email",
        {
            "enabled": True,
            "host": "smtp.example",
            "username": "adsentry@x",
            "sender": "adsentry@x",
            "recipients": ["soc@x"],
        },
        "Smtp-P4ss",
    )
    configure(env, "webhook", {"enabled": True, "url": "https://hooks.example/abc", "format": "teams"})
    env.responses["https://hooks.example/"] = httpx.Response(200)
    env.import_scan()
    msg = next(m for m in sent if not isinstance(m, (str, tuple)))
    assert msg["To"] == "soc@x" and "Scan terminé" in msg["Subject"] and ("login", "adsentry@x", "Smtp-P4ss") in sent
    hook = next(c for c in env.calls if str(c.url).startswith("https://hooks.example/"))
    assert "Scan terminé" in json.loads(hook.content)["title"]


def test_failing_integration_never_breaks_scan(env):
    configure(env, "webhook", {"enabled": True, "url": "https://hooks.example/abc"})
    env.responses["https://hooks.example/"] = httpx.Response(500, text="boom")
    _, done = env.import_scan()
    assert done[0].status == "succeeded" and done[0].result["webhook"] is False
    status = env.admin.get("/api/integrations").json()["status"]["webhook"]
    assert status["ok"] is False and "500" in status["detail"]
    titles = [i["title"] for i in env.admin.get("/api/notifications").json()["items"]]
    assert "Intégration webhook en échec" in titles
    assert "Intégration webhook en échec" not in [
        i["title"] for i in env.viewer.get("/api/notifications").json()["items"]
    ]


# ----------------------------------------------------------------------------- SIEM


def test_syslog_cef_over_udp(env):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    configure(
        env,
        "syslog",
        {"enabled": True, "host": "127.0.0.1", "port": srv.getsockname()[1], "protocol": "udp", "format": "cef"},
    )
    env.import_scan()
    lines = []
    try:
        while True:
            lines.append(srv.recvfrom(65535)[0].decode())
    except TimeoutError:
        pass
    srv.close()
    assert lines and lines[0].startswith("<16")  # local4 + critique (premier événement : résumé du scan)
    # RFC 5424 : <PRI>1 HORODATAGE HÔTE APPLICATION PROCID MSGID DONNÉES-STRUCTURÉES MESSAGE
    fields = [x.rstrip("\n").split(" ", 7) for x in lines]
    assert all(f[3] == "ADSentry" and f[6] == "-" for f in fields)
    cef = [f[7] for f in fields]
    assert all(c.startswith("CEF:0|ADSentry|ADSentry|") for c in cef)
    asrep = next(c for c in cef if "|A-ASREP-ROASTABLE|" in c)
    assert "|8|" in asrep and "dvchost=corp.local" in asrep and "act=new" in asrep


def test_cef_escaping():
    from adsentry.integrations.senders import to_cef

    cef = to_cef(
        {
            "type": "finding",
            "at": "2026-11-01T10:00:00+00:00",
            "rule_id": "X|Y",
            "title": "a|b\\c",
            "severity": "high",
            "summary": "k=v\nsuite",
            "affected": ["x=1"],
        }
    )
    assert "X\\|Y" in cef and "a\\|b\\\\c" in cef and "msg=k\\=v\\nsuite" in cef and "cs1=x\\=1" in cef


def test_splunk_hec(env):
    configure(
        env,
        "splunk",
        {"enabled": True, "url": "https://splunk.example:8088", "index": "secu", "send": "all"},
        "HEC-T0KEN",
    )
    env.responses["https://splunk.example:8088/services/collector/event"] = httpx.Response(200, json={"code": 0})
    env.import_scan()
    call = next(c for c in env.calls if "collector" in str(c.url))
    assert call.headers["authorization"] == "Splunk HEC-T0KEN"
    events = [json.loads(x) for x in call.content.decode().splitlines()]
    assert events[0]["event"]["type"] == "scan" and all(e["index"] == "secu" for e in events)
    assert len(events) > 200  # « tous les constats »


# ----------------------------------------------------------------------------- ITSM


def test_jira_auto_and_manual_tickets_without_duplicates(env):
    configure(
        env,
        "jira",
        {
            "enabled": True,
            "url": "https://jira.example",
            "project": "SEC",
            "username": "bot@x",
            "auto_min_severity": "critical",
        },
        "J1r4",
    )
    counter = {"n": 0}

    def create(req):
        counter["n"] += 1
        body = json.loads(req.content)
        assert body["fields"]["project"] == {"key": "SEC"} and "Correction recommandée" in body["fields"]["description"]
        return httpx.Response(201, json={"key": f"SEC-{counter['n']}"})

    env.responses["https://jira.example/rest/api/2/issue"] = create
    scan, done = env.import_scan()
    auto = done[0].result["tickets"]
    assert auto and counter["n"] == len(auto)  # un ticket par nouveau constat critique
    call = next(c for c in env.calls if "/rest/api/2/issue" in str(c.url))
    assert call.headers["authorization"].startswith("Basic ")
    tickets = env.viewer.get(f"/api/scans/{scan}/tickets").json()
    assert tickets["system"] == "jira" and tickets["tickets"]["PKI-ESC1"]["url"].startswith(
        "https://jira.example/browse/SEC-"
    )

    # ticket manuel pour un constat moins grave, puis pas de doublon
    assert env.viewer.post(f"/api/scans/{scan}/tickets/A-ASREP-ROASTABLE").status_code == 403
    env.admin.post(f"/api/scans/{scan}/tickets/A-ASREP-ROASTABLE")
    env.run_all()
    before = counter["n"]
    env.admin.post(f"/api/scans/{scan}/tickets/A-ASREP-ROASTABLE")
    env.run_all()
    assert counter["n"] == before
    # second scan identique : aucun nouveau constat, aucun nouveau ticket
    env.import_scan()
    assert counter["n"] == before


def test_servicenow_ticket(env):
    configure(
        env,
        "servicenow",
        {"enabled": True, "url": "https://acme.service-now.com", "username": "svc", "assignment_group": "AD"},
        "Sn0w",
    )
    env.responses["https://acme.service-now.com/api/now/table/incident"] = httpx.Response(
        201, json={"result": {"number": "INC0010001", "sys_id": "abc"}}
    )
    scan, _ = env.import_scan()
    env.admin.post(f"/api/scans/{scan}/tickets/PKI-ESC1")
    job = env.run_all()[0]
    assert job.status == "succeeded" and job.result["key"] == "INC0010001"
    body = json.loads(next(c for c in env.calls if "incident" in str(c.url)).content)
    assert body["urgency"] == "1" and body["assignment_group"] == "AD"


def test_integration_test_job(env):
    configure(env, "jira", {"enabled": True, "url": "https://jira.example", "project": "SEC", "auth": "bearer"}, "PAT")
    env.responses["https://jira.example/rest/api/2/project/SEC"] = httpx.Response(200, json={"key": "SEC"})
    env.admin.post("/api/integrations/jira/test")
    job = env.run_all()[0]
    assert job.status == "succeeded"
    call = next(c for c in env.calls if "/project/SEC" in str(c.url))
    assert call.headers["authorization"] == "Bearer PAT"


# ----------------------------------------------------------------------------- jetons d'API et Swagger


def test_api_tokens(env):
    r = env.admin.post("/api/tokens", json={"name": "SIEM lecture", "role": "viewer", "days": 30}).json()
    token = r["token"]
    assert token.startswith("ads_") and "digest" not in r
    assert token not in json.dumps(env.admin.get("/api/tokens").json())
    bot = env.anon
    auth = {"Authorization": f"Bearer {token}"}
    assert bot.get("/api/scans", headers=auth).status_code == 200
    # rôle du jeton respecté ; pas d'en-tête anti-CSRF requis pour un jeton
    assert bot.post("/api/targets", headers=auth, json={}).status_code == 403
    assert bot.get("/api/scans", headers={"Authorization": "Bearer ads_faux"}).status_code == 401
    admin_tok = env.admin.post("/api/tokens", json={"name": "Automate", "role": "admin"}).json()["token"]
    a2 = {"Authorization": f"Bearer {admin_tok}"}
    assert bot.post("/api/tokens", headers=a2, json={"name": "x2", "role": "admin"}).status_code == 403
    assert env.admin.delete(f"/api/tokens/{r['id']}").status_code == 200
    assert bot.get("/api/scans", headers=auth).status_code == 401


def test_swagger(env):
    assert env.anon.get("/api/openapi.json").status_code == 401
    assert env.anon.get("/api/docs", follow_redirects=False).status_code in (302, 307)
    schema = env.viewer.get("/api/openapi.json").json()
    assert "jeton" in schema["components"]["securitySchemes"] and "/api/scans" in schema["paths"]
    page = env.viewer.get("/api/docs")
    assert page.status_code == 200 and "/api/docs/init.js" in page.text and "<script>" not in page.text
    pytest.importorskip("swagger_ui_bundle")
    assert env.viewer.get("/api/docs/static/swagger-ui-bundle.js").status_code == 200
    assert env.viewer.get("/api/docs/static/../../etc/passwd").status_code == 404
