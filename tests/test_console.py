"""Console web : comptes et rôles, cibles et secrets, file de tâches (sans réseau)."""

from __future__ import annotations

import importlib
import json

import pytest
from conftest import load_raw

from adsentry.models import Snapshot

pytest.importorskip("fastapi")
pytest.importorskip("multipart")

H = {"X-ADSentry": "1"}
ADMIN_PWD = "Adm1n-Passw0rd!"
VIEWER_PWD = "V1ewer-Passw0rd!"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ADSENTRY_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("ADSENTRY_CONFIG", str(tmp_path / "etc"))
    monkeypatch.setenv("ADSENTRY_DATA", str(tmp_path / "state" / "scans"))
    monkeypatch.delenv("ADSENTRY_WEB_DIR", raising=False)
    monkeypatch.delenv("ADSENTRY_EMBEDDED_WORKER", raising=False)
    import adsentry.api.main as api
    import adsentry.appliance.auth as auth
    import adsentry.appliance.config as config
    import adsentry.appliance.jobs as jobs
    import adsentry.appliance.runner as runner

    for mod in (config, auth, jobs, runner, api):
        importlib.reload(mod)
    from fastapi.testclient import TestClient

    class Env:
        pass

    e = Env()
    e.api, e.auth, e.config, e.jobs, e.runner, e.tmp = api, auth, config, jobs, runner, tmp_path
    e.client = lambda: TestClient(api.app)
    return e


def _setup_admin(e):
    c = e.client()
    with c:  # déclenche le lifespan : création du jeton d'installation
        token = e.auth.setup_token_path().read_text().strip()
        r = c.post("/api/auth/setup", headers=H, json={"token": token, "username": "admin", "password": ADMIN_PWD})
        assert r.status_code == 200, r.text
    return c


def _viewer(e, admin):
    r = admin.post("/api/users", headers=H, json={"username": "lecteur", "password": VIEWER_PWD, "role": "viewer"})
    assert r.status_code == 200, r.text
    v = e.client()
    assert v.post("/api/auth/login", headers=H, json={"username": "lecteur", "password": VIEWER_PWD}).status_code == 200
    return v


AD_TARGET = {
    "name": "corp",
    "schedule": "17 2 * * *",
    "ai_analysis": False,
    "ad": {"domain": "corp.example", "dc": "10.0.0.10", "username": "svc-audit", "password": "Sup3r-S3cret!"},
}


# ----------------------------------------------------------------------------- premier démarrage


def test_setup_requires_token_and_runs_once(env):
    c = env.client()
    with c:
        assert c.get("/api/auth/status").json()["setup_required"] is True
        body = {"token": "faux", "username": "admin", "password": ADMIN_PWD}
        assert c.post("/api/auth/setup", headers=H, json=body).status_code == 403
        body["token"] = env.auth.setup_token_path().read_text().strip()
        weak = {**body, "password": "court"}
        assert c.post("/api/auth/setup", headers=H, json=weak).status_code == 400
        assert env.auth.setup_token_path().exists()  # le jeton survit à une saisie refusée
        r = c.post("/api/auth/setup", headers=H, json=body)
        assert r.status_code == 200 and r.json()["role"] == "admin"
        assert not env.auth.setup_token_path().exists()
        assert c.get("/api/auth/status").json()["user"]["username"] == "admin"
        assert c.post("/api/auth/setup", headers=H, json=body).status_code == 409


def test_password_hash_never_plaintext(env):
    _setup_admin(env)
    raw = (env.tmp / "state" / "users.json").read_text()
    assert ADMIN_PWD not in raw and "scrypt$" in raw


# ----------------------------------------------------------------------------- sessions et rôles


def test_unauthenticated_and_csrf(env):
    admin = _setup_admin(env)
    anon = env.client()
    assert anon.get("/api/health").status_code == 200
    assert anon.get("/api/scans").status_code == 401
    assert anon.get("/api/dashboard").status_code == 401
    # Requête modifiante sans l'en-tête anti-CSRF : refusée même authentifiée
    assert admin.post("/api/targets", json=AD_TARGET).status_code == 403


def test_viewer_reads_but_cannot_administer(env):
    admin = _setup_admin(env)
    viewer = _viewer(env, admin)
    payload = json.dumps(load_raw("vulnerable")).encode()
    r = admin.post("/api/scans", headers=H, files={"snapshot": ("s.json", payload, "application/json")})
    scan_id = r.json()["id"]

    assert viewer.get("/api/scans").json()[0]["id"] == scan_id
    assert viewer.get(f"/api/scans/{scan_id}").status_code == 200
    assert viewer.get("/api/rules").status_code == 200
    assert viewer.get("/api/auth/status").json()["user"]["role"] == "viewer"
    for method, path in [
        ("post", "/api/scans"),
        ("delete", f"/api/scans/{scan_id}"),
        ("post", f"/api/scans/{scan_id}/ai-analysis"),
        ("get", "/api/targets"),
        ("get", "/api/jobs"),
        ("get", "/api/users"),
        ("get", "/api/audit"),
    ]:
        kw = {"files": {"snapshot": ("s.json", payload)}} if path == "/api/scans" else {}
        assert getattr(viewer, method)(path, headers=H, **kw).status_code == 403, path

    assert admin.delete(f"/api/scans/{scan_id}", headers=H).status_code == 200
    assert viewer.get("/api/scans").json() == []


def test_login_lockout_and_logout(env):
    admin = _setup_admin(env)
    c = env.client()
    for _ in range(env.auth.LOCK_AFTER):
        assert (
            c.post("/api/auth/login", headers=H, json={"username": "admin", "password": "mauvais"}).status_code == 401
        )
    good = {"username": "admin", "password": ADMIN_PWD}
    assert c.post("/api/auth/login", headers=H, json=good).status_code == 429
    assert admin.post("/api/auth/logout", headers=H).status_code == 200
    assert admin.get("/api/scans").status_code == 401
    events = [e["event"] for e in env.auth.read_audit()]
    assert "login_failed" in events and "login_locked" in events


def test_user_management_guards(env):
    admin = _setup_admin(env)
    viewer = _viewer(env, admin)
    # Pas d'auto-rétrogradation, pas de suppression de soi-même ni du dernier administrateur
    assert admin.patch("/api/users/admin", headers=H, json={"role": "viewer"}).status_code == 400
    assert admin.delete("/api/users/admin", headers=H).status_code == 400
    # Changer le rôle d'un compte ferme ses sessions
    assert admin.patch("/api/users/lecteur", headers=H, json={"role": "admin"}).status_code == 200
    assert viewer.get("/api/scans").status_code == 401
    # Changement de son propre mot de passe
    body = {"current": ADMIN_PWD, "new": "N0uveau-Passw0rd!"}
    assert admin.post("/api/auth/password", headers=H, json={**body, "current": "x"}).status_code == 400
    assert admin.post("/api/auth/password", headers=H, json=body).status_code == 200
    assert admin.get("/api/scans").status_code == 200  # la session courante est conservée
    assert admin.delete("/api/users/lecteur", headers=H).status_code == 200


# ----------------------------------------------------------------------------- cibles et secrets


def test_target_secrets_are_encrypted_and_hidden(env):
    admin = _setup_admin(env)
    r = admin.post("/api/targets", headers=H, json=AD_TARGET)
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["ad"]["password_set"] is True and "password" not in view["ad"]
    assert "Sup3r-S3cret!" not in json.dumps(admin.get("/api/targets").json())
    for f in (env.tmp / "state").rglob("*"):
        if f.is_file():
            assert "Sup3r-S3cret!" not in f.read_text(errors="ignore"), f
    store = env.config.SecretStore()
    assert store.get("corp-ad") == "Sup3r-S3cret!"

    # Modification sans ressaisir le mot de passe : conservé
    upd = {**AD_TARGET, "schedule": "", "ad": {**AD_TARGET["ad"], "password": None, "dc": "dc1.corp.example"}}
    r = admin.put("/api/targets/corp", headers=H, json=upd)
    assert r.status_code == 200, r.text
    assert r.json()["schedule"] is None and r.json()["ad"]["dc"] == "dc1.corp.example"
    assert store.get("corp-ad") == "Sup3r-S3cret!"

    assert admin.delete("/api/targets/corp", headers=H).status_code == 200
    assert not store.has("corp-ad")


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"name": "Corp Prod"}, "Nom de cible invalide"),
        ({"schedule": "61 * * * *"}, "Planification invalide"),
        ({"ad": None}, "au moins une source"),
        ({"ad": {**AD_TARGET["ad"], "password": None}}, "Mot de passe"),
        ({"entra": {"tenant_id": "t", "client_id": "c", "auth": "certificate", "thumbprint": "AB"}}, "Certificat PEM"),
    ],
)
def test_target_validation(env, patch, message):
    admin = _setup_admin(env)
    r = admin.post("/api/targets", headers=H, json={**AD_TARGET, **patch})
    assert r.status_code == 400 and message in r.json()["detail"], r.text


def test_entra_certificate_stored_as_secret(env):
    admin = _setup_admin(env)
    pem = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"
    body = {
        "name": "cloud",
        "entra": {
            "tenant_id": "t",
            "client_id": "c",
            "auth": "certificate",
            "thumbprint": "ab:cd",
            "certificate_pem": pem,
        },
    }
    r = admin.post("/api/targets", headers=H, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["entra"]["certificate_set"] is True and r.json()["entra"]["thumbprint"] == "ABCD"
    target = env.config.load_targets()[0]
    with env.runner._entra_cert(target.entra, env.config.SecretStore()) as path:
        assert path.read_text() == pem and oct(path.stat().st_mode)[-3:] == "600"
    assert not path.exists()


# ----------------------------------------------------------------------------- tâches


def test_scan_job_from_console(env, monkeypatch):
    admin = _setup_admin(env)
    admin.post("/api/targets", headers=H, json=AD_TARGET)
    snap = Snapshot.model_validate(load_raw("vulnerable"))

    def fake_collect(target, secrets, progress):
        assert secrets.get(target.ad.password_secret) == "Sup3r-S3cret!"
        progress(10, "Collecte simulée")
        progress.warn("SYSVOL simulé indisponible")
        return snap

    monkeypatch.setattr(env.runner, "collect_target", fake_collect)
    r = admin.post("/api/targets/corp/scan", headers=H)
    assert r.status_code == 200 and r.json()["status"] == "queued"
    assert admin.post("/api/targets/corp/scan", headers=H).status_code == 409  # déjà en file
    assert admin.get("/api/jobs").json()["worker"]["online"] is False

    store = env.jobs.JobStore()
    job = env.runner.execute_job(store.claim_next(), store)
    assert job.status == "succeeded" and job.progress == 100 and job.scan_id
    assert any(e["level"] == "warning" for e in job.log)

    done = admin.get(f"/api/jobs/{job.id}").json()
    assert done["result"]["findings"] > 0
    assert admin.get("/api/scans").json()[0]["id"] == job.scan_id
    assert admin.get("/api/targets").json()[0]["last_scan"]["id"] == job.id


def test_failed_test_job_and_cancel(env, monkeypatch):
    admin = _setup_admin(env)
    admin.post("/api/targets", headers=H, json=AD_TARGET)
    monkeypatch.setattr(env.runner, "test_target", lambda *a: {"ad": {"ok": False, "detail": "invalidCredentials"}})
    admin.post("/api/targets/corp/test", headers=H)
    store = env.jobs.JobStore()
    job = env.runner.execute_job(store.claim_next(), store)
    assert job.status == "failed" and "invalidCredentials" in job.error

    queued = admin.post("/api/targets/corp/scan", headers=H).json()
    assert admin.post(f"/api/jobs/{queued['id']}/cancel", headers=H).json()["status"] == "cancelled"
    assert store.claim_next() is None


def test_schedule_creates_job(env):
    store = env.jobs.JobStore()
    env.config.save_targets(
        [env.config.Target.model_validate({**AD_TARGET, "ad": {**AD_TARGET["ad"], "password_secret": "x"}})]
    )
    store.create(env.jobs.JobKind.scan, target="corp", trigger="schedule")
    with pytest.raises(env.jobs.JobConflict):
        store.create(env.jobs.JobKind.scan, target="corp", trigger="schedule")
    job = store.claim_next()
    assert job.trigger == "schedule" and job.status == "running"
    assert store.recover_interrupted() == 1 and store.get(job.id).status == "failed"
