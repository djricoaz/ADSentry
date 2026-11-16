"""API FastAPI de la console web.

Authentification par session (cookie HttpOnly) et deux rôles :
- viewer (« Lecteur ») : consultation des évaluations (scans, constats, tableaux de bord, catalogue) ;
- admin (« Administrateur ») : en plus, cibles d'audit et leurs secrets, lancement des scans, IA, comptes.

L'API ne sort jamais du réseau interne : scans, tests de connexion et analyses IA sont déposés dans une file
(appliance/jobs.py) exécutée par le worker. Stockage v0.1 : fichiers JSON dans ADSENTRY_DATA.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field, ValidationError

from ..appliance import auth as A
from ..appliance.config import (
    DATA_DIR as _DEFAULT_DATA,
)
from ..appliance.config import (
    STATE_DIR,
    TARGET_NAME_RE,
    AdTarget,
    EntraTarget,
    SecretStore,
    Target,
    load_targets,
    save_targets,
)
from ..appliance.jobs import JobConflict, JobKind, JobStore, job_summary
from ..mitre.navigator import build_layer
from ..models import ScanResult, Snapshot
from ..rules.engine import analyze, load_rules

log = logging.getLogger("adsentry.api")
DATA_DIR = Path(os.environ.get("ADSENTRY_DATA") or _DEFAULT_DATA)
DATA_DIR.mkdir(parents=True, exist_ok=True)
COOKIE = "adsentry_session"
CSRF_HEADER = "x-adsentry"

users = A.UserStore()
sessions = A.SessionStore()
throttle = A.LoginThrottle()
jobs = JobStore()


def secret_store() -> SecretStore:
    return SecretStore()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if users.count() == 0:
        token = A.ensure_setup_token()
        log.warning(
            "\n%s\n  ADSentry : aucun compte. Ouvrez la console et créez l'administrateur avec ce jeton :\n"
            "      %s\n  (également dans %s)\n%s",
            "=" * 72,
            token,
            A.setup_token_path(),
            "=" * 72,
        )
    stop = threading.Event()
    if os.environ.get("ADSENTRY_EMBEDDED_WORKER") == "1":
        from ..appliance.runner import worker_loop

        threading.Thread(target=worker_loop, kwargs={"stop": stop}, name="adsentry-worker", daemon=True).start()
    yield
    stop.set()


app = FastAPI(title="ADSentry API", version="0.2.0", lifespan=lifespan, docs_url=None, redoc_url=None)


# ----------------------------------------------------------------------------- sécurité


@app.middleware("http")
async def csrf_and_headers(request: Request, call_next):
    # Toute requête modifiante doit porter l'en-tête X-ADSentry (impossible à poser depuis un autre site
    # sans pré-vol CORS, que l'API n'autorise pas) ; le cookie est en outre SameSite=Strict.
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path.startswith("/api/"):
        if request.headers.get(CSRF_HEADER) != "1":
            return Response(
                '{"detail":"Requête refusée (en-tête X-ADSentry manquant)"}', 403, media_type="application/json"
            )
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _client_ip(request: Request) -> str:
    return (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0]


def _secure_cookie(request: Request) -> bool:
    mode = os.environ.get("ADSENTRY_COOKIE_SECURE", "auto")
    if mode in ("0", "1"):
        return mode == "1"
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def _set_session(response: Response, request: Request, username: str) -> None:
    response.set_cookie(
        COOKIE,
        sessions.create(username),
        httponly=True,
        samesite="strict",
        secure=_secure_cookie(request),
        max_age=A.SESSION_TTL,
        path="/",
    )


def current_user(request: Request) -> A.User:
    username = sessions.resolve(request.cookies.get(COOKIE))
    user = users.get(username) if username else None
    if user is None or user.disabled:
        raise HTTPException(401, "Session absente ou expirée")
    return user


def require_admin(user: Annotated[A.User, Depends(current_user)]) -> A.User:
    if user.role != A.Role.admin:
        raise HTTPException(403, "Action réservée aux administrateurs")
    return user


Viewer = Annotated[A.User, Depends(current_user)]
Admin = Annotated[A.User, Depends(require_admin)]


def _auth_error(exc: A.AuthError) -> HTTPException:
    return HTTPException(400, str(exc))


# ----------------------------------------------------------------------------- authentification


class Credentials(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class SetupRequest(Credentials):
    token: str = Field(max_length=128)
    display_name: str = ""


class PasswordChange(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/auth/status")
def auth_status(request: Request):
    username = sessions.resolve(request.cookies.get(COOKIE))
    user = users.get(username) if username else None
    return {
        "setup_required": users.count() == 0,
        "user": user.public() if user and not user.disabled else None,
        "min_password": A.MIN_PASSWORD,
    }


@app.post("/api/auth/setup")
def auth_setup(body: SetupRequest, request: Request, response: Response):
    if users.count() > 0:
        raise HTTPException(409, "L'appliance est déjà initialisée")
    ip = _client_ip(request)
    if throttle.locked(f"ip:{ip}"):
        raise HTTPException(429, "Trop de tentatives ; réessayez dans 15 minutes")
    if not A.check_setup_token(body.token):
        throttle.fail(f"ip:{ip}")
        raise HTTPException(403, "Jeton d'installation incorrect")
    try:
        user = users.create(body.username, body.password, A.Role.admin, body.display_name)
    except A.AuthError as exc:
        raise _auth_error(exc) from exc
    A.setup_token_path().unlink(missing_ok=True)
    A.audit("setup", user.username, ip=ip)
    _set_session(response, request, user.username)
    return user.public()


@app.post("/api/auth/login")
def login(body: Credentials, request: Request, response: Response):
    ip = _client_ip(request)
    keys = (f"user:{body.username.lower()}", f"ip:{ip}")
    if throttle.locked(*keys):
        A.audit("login_locked", body.username, ip=ip)
        raise HTTPException(429, "Trop de tentatives ; réessayez dans 15 minutes")
    user = users.authenticate(body.username, body.password)
    if user is None:
        throttle.fail(*keys)
        A.audit("login_failed", body.username, ip=ip)
        time.sleep(0.5)
        raise HTTPException(401, "Identifiant ou mot de passe incorrect")
    throttle.success(*keys)
    A.audit("login", user.username, ip=ip)
    _set_session(response, request, user.username)
    return user.public()


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if username := sessions.resolve(token):
        A.audit("logout", username)
    sessions.revoke(token)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/password")
def change_password(body: PasswordChange, user: Viewer, request: Request):
    if not A.verify_password(body.current, user.password_hash):
        raise HTTPException(400, "Mot de passe actuel incorrect")
    try:
        users.update(user.username, password=body.new)
    except A.AuthError as exc:
        raise _auth_error(exc) from exc
    sessions.revoke_user(user.username, keep=request.cookies.get(COOKIE))
    A.audit("password_changed", user.username)
    return {"ok": True}


# ----------------------------------------------------------------------------- comptes (admin)


class UserCreate(Credentials):
    role: A.Role = A.Role.viewer
    display_name: str = ""


class UserUpdate(BaseModel):
    role: A.Role | None = None
    display_name: str | None = None
    password: str | None = Field(None, max_length=256)
    disabled: bool | None = None


@app.get("/api/users")
def list_users(_: Admin):
    return [u.public() for u in users.list()]


@app.post("/api/users")
def create_user(body: UserCreate, admin: Admin):
    try:
        user = users.create(body.username, body.password, body.role, body.display_name)
    except A.AuthError as exc:
        raise _auth_error(exc) from exc
    A.audit("user_created", admin.username, target=user.username, role=user.role.value)
    return user.public()


@app.patch("/api/users/{username}")
def update_user(username: str, body: UserUpdate, admin: Admin):
    if username.lower() == admin.username.lower() and (body.disabled or body.role == A.Role.viewer):
        raise HTTPException(400, "Vous ne pouvez pas désactiver ou rétrograder votre propre compte")
    try:
        user = users.update(username, **body.model_dump(exclude_none=True))
    except A.AuthError as exc:
        raise _auth_error(exc) from exc
    if body.password or body.disabled or body.role:
        sessions.revoke_user(username)
    changes = sorted(k for k, v in body.model_dump().items() if v is not None)
    A.audit("user_updated", admin.username, target=username, changes=changes)
    return user.public()


@app.delete("/api/users/{username}")
def delete_user(username: str, admin: Admin):
    if username.lower() == admin.username.lower():
        raise HTTPException(400, "Vous ne pouvez pas supprimer votre propre compte")
    try:
        users.delete(username)
    except A.AuthError as exc:
        raise _auth_error(exc) from exc
    sessions.revoke_user(username)
    A.audit("user_deleted", admin.username, target=username)
    return {"ok": True}


@app.get("/api/audit")
def audit_log(_: Admin, limit: int = 200):
    return A.read_audit(min(max(limit, 1), 2000))


# ----------------------------------------------------------------------------- cibles d'audit (admin)


class AdInput(BaseModel):
    domain: str = Field(min_length=1, max_length=255)
    dc: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=256)
    password: str | None = Field(None, max_length=512)  # vide en modification = inchangé
    ldaps: bool = False
    sysvol: bool = True
    probes: bool = True


class EntraInput(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=64)
    auth: Literal["certificate", "secret"] = "certificate"
    client_secret: str | None = Field(None, max_length=1024)
    certificate_pem: str | None = Field(None, max_length=64_000)
    thumbprint: str | None = Field(None, max_length=128)
    connect_version: str | None = Field(None, max_length=32)


class TargetInput(BaseModel):
    name: str
    schedule: str | None = None
    ai_analysis: bool = False
    ad: AdInput | None = None
    entra: EntraInput | None = None


def _target_view(t: Target, store: SecretStore, all_jobs) -> dict:
    data = t.model_dump(mode="json")
    if t.ad:
        data["ad"]["password_set"] = store.has(t.ad.password_secret)
        data["ad"].pop("password_secret", None)
    if t.entra:
        e = data["entra"]
        e["auth"] = "secret" if t.entra.client_secret_secret else "certificate"
        e["client_secret_set"] = bool(t.entra.client_secret_secret and store.has(t.entra.client_secret_secret))
        e["certificate_set"] = bool(
            (t.entra.certificate_secret and store.has(t.entra.certificate_secret)) or t.entra.certificate
        )
        for k in ("client_secret_secret", "certificate_secret"):
            e.pop(k, None)
    mine = [j for j in all_jobs if j.target == t.name]
    scans = [j for j in mine if j.kind == JobKind.scan]
    data["active_job"] = next((job_summary(j) for j in mine if j.active), None)
    data["last_scan"] = next((job_summary(j) for j in scans if not j.active), None)
    return data


def _apply(body: TargetInput, existing: Target | None, store: SecretStore) -> Target:
    if not TARGET_NAME_RE.match(body.name):
        raise HTTPException(400, "Nom de cible invalide (minuscules, chiffres et tirets ; 40 caractères max.)")
    if not body.ad and not body.entra:
        raise HTTPException(400, "Renseignez au moins une source : Active Directory ou Entra ID")
    pending: dict[str, str] = {}
    ad = entra = None
    if body.ad:
        name = f"{body.name}-ad"
        if body.ad.password:
            pending[name] = body.ad.password
        elif not (existing and existing.ad and store.has(existing.ad.password_secret)):
            raise HTTPException(400, "Mot de passe du compte d'audit AD requis")
        else:
            name = existing.ad.password_secret
        ad = AdTarget(**body.ad.model_dump(exclude={"password"}), password_secret=name)
    if body.entra:
        e, old = body.entra, existing.entra if existing else None
        kw = {
            "tenant_id": e.tenant_id.strip(),
            "client_id": e.client_id.strip(),
            "connect_version": e.connect_version or None,
        }
        if e.auth == "secret":
            name = f"{body.name}-entra-secret"
            if e.client_secret:
                pending[name] = e.client_secret
            elif old and old.client_secret_secret and store.has(old.client_secret_secret):
                name = old.client_secret_secret
            else:
                raise HTTPException(400, "Secret client de l'application Entra requis")
            kw["client_secret_secret"] = name
        else:
            if not e.thumbprint:
                raise HTTPException(400, "Empreinte (thumbprint) du certificat Entra requise")
            kw["thumbprint"] = e.thumbprint.replace(":", "").replace(" ", "").upper()
            name = f"{body.name}-entra-cert"
            if e.certificate_pem:
                if "PRIVATE KEY" not in e.certificate_pem or "CERTIFICATE" not in e.certificate_pem:
                    raise HTTPException(400, "Le fichier PEM doit contenir la clé privée et le certificat")
                pending[name] = e.certificate_pem
                kw["certificate_secret"] = name
            elif old and old.certificate_secret and store.has(old.certificate_secret):
                kw["certificate_secret"] = old.certificate_secret
            elif old and old.certificate:
                kw["certificate"] = old.certificate
            else:
                raise HTTPException(400, "Certificat PEM de l'application Entra requis")
        entra = EntraTarget(**kw)
    try:
        target = Target(name=body.name, schedule=body.schedule, ai_analysis=body.ai_analysis, ad=ad, entra=entra)
    except ValidationError as exc:
        raise HTTPException(400, exc.errors()[0]["msg"].removeprefix("Value error, ")) from exc
    for k, v in pending.items():
        store.set(k, v)
    return target


@app.get("/api/targets")
def list_targets(_: Admin):
    store, all_jobs = secret_store(), jobs.list(limit=500)
    return [_target_view(t, store, all_jobs) for t in load_targets()]


@app.post("/api/targets")
def create_target(body: TargetInput, admin: Admin):
    targets = load_targets()
    if any(t.name == body.name for t in targets):
        raise HTTPException(409, "Une cible porte déjà ce nom")
    target = _apply(body, None, secret_store())
    save_targets([*targets, target])
    A.audit("target_created", admin.username, target=target.name)
    return _target_view(target, secret_store(), [])


@app.put("/api/targets/{name}")
def update_target(name: str, body: TargetInput, admin: Admin):
    targets = load_targets()
    existing = next((t for t in targets if t.name == name), None)
    if existing is None:
        raise HTTPException(404, "Cible introuvable")
    if body.name != name:
        raise HTTPException(400, "Le nom d'une cible ne peut pas être modifié")
    store = secret_store()
    target = _apply(body, existing, store)
    save_targets([target if t.name == name else t for t in targets])
    _drop_unused_secrets(existing, target, store)
    A.audit("target_updated", admin.username, target=name)
    return _target_view(target, store, jobs.list(limit=500))


def _secret_names(t: Target | None) -> set[str]:
    if t is None:
        return set()
    names = {t.ad.password_secret} if t.ad else set()
    if t.entra:
        names |= {n for n in (t.entra.client_secret_secret, t.entra.certificate_secret) if n}
    return names


def _drop_unused_secrets(old: Target | None, new: Target | None, store: SecretStore) -> None:
    for n in _secret_names(old) - _secret_names(new):
        store.delete(n)


@app.delete("/api/targets/{name}")
def delete_target(name: str, admin: Admin):
    targets = load_targets()
    existing = next((t for t in targets if t.name == name), None)
    if existing is None:
        raise HTTPException(404, "Cible introuvable")
    save_targets([t for t in targets if t.name != name])
    _drop_unused_secrets(existing, None, secret_store())
    A.audit("target_deleted", admin.username, target=name)
    return {"ok": True}


def _enqueue(kind: JobKind, admin: A.User, **kw) -> dict:
    try:
        job = jobs.create(kind, user=admin.username, **kw)
    except JobConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    A.audit(f"job_{kind.value}", admin.username, job=job.id, **{k: v for k, v in kw.items() if v})
    return job_summary(job)


@app.post("/api/targets/{name}/scan")
def scan_target(name: str, admin: Admin):
    if not any(t.name == name for t in load_targets()):
        raise HTTPException(404, "Cible introuvable")
    return _enqueue(JobKind.scan, admin, target=name)


@app.post("/api/targets/{name}/test")
def test_target(name: str, admin: Admin):
    if not any(t.name == name for t in load_targets()):
        raise HTTPException(404, "Cible introuvable")
    return _enqueue(JobKind.test, admin, target=name)


# ----------------------------------------------------------------------------- tâches (admin)


def worker_status() -> dict:
    hb = STATE_DIR / "worker.heartbeat"
    age = time.time() - hb.stat().st_mtime if hb.exists() else None
    return {"online": age is not None and age < 90, "last_seen_seconds": round(age) if age is not None else None}


@app.get("/api/jobs")
def list_jobs(_: Admin, limit: int = 50):
    return {"worker": worker_status(), "jobs": [job_summary(j) for j in jobs.list(limit=min(limit, 500))]}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, _: Admin):
    try:
        job = jobs.get(job_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if job is None:
        raise HTTPException(404, "Tâche introuvable")
    return job_summary(job)


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, admin: Admin):
    try:
        job = jobs.cancel(job_id)
    except KeyError as exc:
        raise HTTPException(404, "Tâche introuvable") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    A.audit("job_cancelled", admin.username, job=job_id)
    return job_summary(job)


# ----------------------------------------------------------------------------- IA locale (admin)


class AiSettingsInput(BaseModel):
    base_model: str = Field(max_length=160)
    analyst_model: str = Field(max_length=160)
    embed_model: str = Field(max_length=160)
    use_rag: bool = True
    rag_snippets: int = Field(8, ge=0, le=20)


class KnowledgeInput(BaseModel):
    content: str = Field(max_length=250_000)


class Question(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


@app.get("/api/ai/status")
def ai_status(_: Admin):
    from ..ai import admin as ai

    data = ai.status()
    active = [j for j in jobs.list(limit=200) if j.kind in (JobKind.ai_setup, JobKind.ai_index)]
    data["last_jobs"] = {
        k.value: next((job_summary(j) for j in active if j.kind == k), None)
        for k in (JobKind.ai_setup, JobKind.ai_index)
    }
    data["worker"] = worker_status()
    return data


@app.put("/api/ai/settings")
def ai_save_settings(body: AiSettingsInput, admin: Admin):
    from ..ai import admin as ai

    try:
        saved = ai.save_settings(ai.AiSettings(**body.model_dump()))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    A.audit(
        "ai_settings_updated", admin.username, **{k: v for k, v in body.model_dump().items() if k != "rag_snippets"}
    )
    return saved.model_dump()


@app.post("/api/ai/setup")
def ai_setup(admin: Admin):
    return _enqueue(JobKind.ai_setup, admin)


@app.post("/api/ai/index")
def ai_index(admin: Admin):
    return _enqueue(JobKind.ai_index, admin)


@app.get("/api/ai/knowledge")
def ai_knowledge_list(_: Admin):
    from ..ai import admin as ai

    return ai.list_knowledge()


@app.get("/api/ai/knowledge/{name}")
def ai_knowledge_read(name: str, _: Admin):
    from ..ai import admin as ai

    try:
        return {"name": name, "content": ai.read_knowledge(name)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, "Document introuvable") from exc


@app.put("/api/ai/knowledge/{name}")
def ai_knowledge_write(name: str, body: KnowledgeInput, admin: Admin):
    from ..ai import admin as ai

    try:
        ai.write_knowledge(name, body.content)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    A.audit("knowledge_saved", admin.username, document=name)
    return {"ok": True, "index": ai.index_info()}


@app.delete("/api/ai/knowledge/{name}")
def ai_knowledge_delete(name: str, admin: Admin):
    from ..ai import admin as ai

    try:
        ai.delete_knowledge(name)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(404, "Document introuvable") from exc
    A.audit("knowledge_deleted", admin.username, document=name)
    return {"ok": True, "index": ai.index_info()}


@app.post("/api/ai/ask")
def ai_ask(body: Question, admin: Admin):
    import httpx

    from ..ai import admin as ai

    A.audit("ai_question", admin.username)
    try:
        return ai.ask(body.question)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            502, f"Ollama a refusé la requête ({exc.response.status_code}) : modèle installé ?"
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Ollama injoignable : {exc}") from exc


@app.get("/api/ai/dataset")
def ai_dataset(admin: Admin, n: int = 500):
    from fastapi.responses import StreamingResponse

    from ..ai.dataset import iter_samples

    n = min(max(n, 10), 5000)
    gold = STATE_DIR / "ai" / "gold"
    A.audit("ai_dataset_downloaded", admin.username, samples=n)
    lines = (json.dumps(x, ensure_ascii=False) + "\n" for x in iter_samples(n, gold_dir=gold))
    return StreamingResponse(
        lines,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="adsentry-train-{n}.jsonl"'},
    )


# ----------------------------------------------------------------------------- évaluations (lecture)


def _load(scan_id: str) -> ScanResult:
    if not scan_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "Identifiant invalide")
    path = DATA_DIR / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(404, "Scan introuvable")
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))


@app.get("/api/dashboard")
def dashboard_view(_: Viewer, domain: str | None = None, days: int | None = None):
    from ..history import dashboard, load_all

    return dashboard(load_all(DATA_DIR), domain, days if days and days > 0 else None)


@app.get("/api/compare")
def compare_view(base: str, target: str, _: Viewer):
    from ..history import compare

    a, b = _load(base), _load(target)
    if a.collected_at > b.collected_at:
        a, b = b, a
    return compare(a, b)


@app.get("/api/mitre")
def mitre_reference(_: Viewer):
    from ..mitre.attack import EXPORT_PATH

    if not EXPORT_PATH.exists():
        raise HTTPException(404, "Référentiel ATT&CK absent : lancer « adsentry mitre-check »")
    return json.loads(EXPORT_PATH.read_text(encoding="utf-8"))


@app.get("/api/rules")
def list_rules(_: Viewer):
    return [r.model_dump(mode="json") for r in load_rules()]


@app.get("/api/scans")
def list_scans(_: Viewer):
    from ..history import maturity

    out = []
    for p in DATA_DIR.glob("*.json"):
        if p.name.endswith((".ai.json", ".graph.json")):
            continue
        r = ScanResult.model_validate_json(p.read_text(encoding="utf-8"))
        out.append(
            {
                "id": p.stem,
                "domain": r.domain,
                "collected_at": r.collected_at.isoformat(),
                "analyzed_at": r.analyzed_at.isoformat(),
                "global_score": r.global_score,
                "findings": len(r.findings),
                "maturity": maturity(r.findings),
                "ai": (DATA_DIR / f"{p.stem}.ai.json").exists(),
            }
        )
    return sorted(out, key=lambda x: x["collected_at"], reverse=True)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, _: Viewer):
    return _load(scan_id).model_dump(mode="json")


@app.get("/api/scans/{scan_id}/navigator")
def get_navigator_layer(scan_id: str, _: Viewer):
    return build_layer(_load(scan_id))


@app.get("/api/scans/{scan_id}/topology")
def get_topology(scan_id: str, _: Viewer):
    _load(scan_id)
    path = DATA_DIR / f"{scan_id}.graph.json"
    if not path.exists():
        raise HTTPException(404, "Topologie indisponible pour ce rapport (antérieur à la fonction) : relancez un scan")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/scans/{scan_id}/ai-analysis")
def get_ai_analysis(scan_id: str, _: Viewer):
    _load(scan_id)  # valide l'identifiant et l'existence du scan
    path = DATA_DIR / f"{scan_id}.ai.json"
    if not path.exists():
        raise HTTPException(404, "Pas encore d'analyse IA pour ce scan")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/catalog-stats")
def catalog_stats(_: Viewer):
    from collections import Counter

    rules = load_rules()
    return {
        "rules": len(rules),
        "by_category": dict(Counter(r.category.value for r in rules)),
        "by_source": dict(Counter(r.source for r in rules)),
        "adcs_escalations": len([r for r in rules if r.id.startswith("PKI-ESC")]),
    }


# ----------------------------------------------------------------------------- évaluations (admin)


@app.post("/api/scans")
async def create_scan(snapshot: UploadFile, admin: Admin):
    try:
        snap = Snapshot.model_validate_json(await snapshot.read())
    except ValidationError as exc:
        raise HTTPException(400, "Fichier non reconnu : ce n'est pas un snapshot ADSentry") from exc
    result = analyze(snap)
    scan_id = uuid.uuid4().hex[:12]
    (DATA_DIR / f"{scan_id}.json").write_text(result.model_dump_json(indent=1), encoding="utf-8")
    from ..appliance.runner import save_topology

    save_topology(snap, scan_id)
    A.audit("snapshot_imported", admin.username, scan=scan_id, domain=result.domain)
    return {"id": scan_id, "global_score": result.global_score}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, admin: Admin):
    _load(scan_id)
    (DATA_DIR / f"{scan_id}.json").unlink()
    (DATA_DIR / f"{scan_id}.ai.json").unlink(missing_ok=True)
    (DATA_DIR / f"{scan_id}.graph.json").unlink(missing_ok=True)
    A.audit("scan_deleted", admin.username, scan=scan_id)
    return {"ok": True}


@app.post("/api/scans/{scan_id}/ai-analysis")
def ai_analysis(scan_id: str, admin: Admin):
    _load(scan_id)
    return _enqueue(JobKind.ai, admin, scan_id=scan_id)


# Mode sans Caddy (monté en dernier pour ne pas masquer /api) :
#   ADSENTRY_WEB_DIR=appliance/web adsentry serve --worker
if os.environ.get("ADSENTRY_WEB_DIR"):
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=os.environ["ADSENTRY_WEB_DIR"], html=True), name="web")
