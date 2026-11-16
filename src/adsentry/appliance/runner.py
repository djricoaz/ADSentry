"""Exécution d'une cible (collecte AD + Entra -> analyse -> stockage) et boucle de planification."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ..models import ScanResult, Snapshot
from ..rules.engine import analyze
from .config import DATA_DIR, STATE_DIR, SecretStore, Target, cron_matches, load_targets
from .jobs import Job, JobConflict, JobKind, JobStatus, JobStore, Progress

log = logging.getLogger("adsentry.worker")


class _NoProgress:
    def __call__(self, _percent: int, _step: str, _level: str = "info", log: bool = True) -> None:
        pass

    def warn(self, _msg: str) -> None:
        pass


_noop = _NoProgress()


@contextmanager
def _entra_cert(e, secrets: SecretStore):
    """Chemin du certificat Entra : fichier déclaré, ou PEM du SecretStore écrit le temps de la collecte (0600)."""
    if e.certificate_secret:
        fd, name = tempfile.mkstemp(prefix="entra-", suffix=".pem")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(secrets.get(e.certificate_secret))
            yield Path(name)
        finally:
            Path(name).unlink(missing_ok=True)
    else:
        yield Path(e.certificate) if e.certificate else None


def _entra_collector(e, secrets: SecretStore, cert_path: Path | None):
    from ..collectors.entra_collector import EntraCollector

    return EntraCollector(
        e.tenant_id,
        e.client_id,
        cert_path=cert_path,
        cert_thumbprint=e.thumbprint,
        client_secret=secrets.get(e.client_secret_secret) if e.client_secret_secret else None,
        connect_version=e.connect_version,
    )


def collect_target(target: Target, secrets: SecretStore, progress=_noop) -> Snapshot:
    snap: Snapshot | None = None
    if target.ad:
        from ..collectors.ldap_collector import LdapCollector

        ad = target.ad
        password = secrets.get(ad.password_secret)
        progress(5, f"Connexion LDAP{'S' if ad.ldaps else ''} à {ad.dc}")
        ldap = LdapCollector(ad.dc, ad.domain, ad.username, password, use_ldaps=ad.ldaps)
        ldap.connect()
        progress(10, "Collecte de l'annuaire (comptes, groupes, ACL, PKI, approbations)")
        snap = ldap.collect()
        if ldap.missing_attributes:
            progress.warn(
                "Attributs absents du schéma (extension non installée), non collectés : "
                + ", ".join(sorted(ldap.missing_attributes))
            )
        if ad.sysvol:
            from ..collectors.sysvol_collector import SysvolCollector

            progress(45, "Lecture des GPO dans SYSVOL")
            try:
                snap.gpos = SysvolCollector(ldap, ad.dc, ad.domain, ad.username, password).collect(ldap.gpo_writers())
            except Exception as exc:
                msg = f"Lecture SYSVOL impossible ({exc}) — règles GPO non évaluées"
                log.warning("%s : %s", target.name, msg)
                progress.warn(msg)
        if ad.probes:
            from ..collectors import probes

            dcs = snap.dcs()
            for i, dc in enumerate(dcs):
                host = dc.dns_hostname or dc.name
                progress(55 + int(15 * i / max(1, len(dcs))), f"Sondes réseau sur {dc.name}")
                try:
                    snap.dc_probes.append(
                        probes.probe_dc(dc.name, host, ad.domain, ad.username, password, ldap.base_dn)
                    )
                except Exception as exc:
                    msg = f"Sondes sur {dc.name} impossibles ({exc})"
                    log.warning("%s : %s", target.name, msg)
                    progress.warn(msg)
            snap.tls_probes += _wsus_probes(snap)
    if target.entra:
        progress(72, "Collecte Entra ID (Microsoft Graph)")
        with _entra_cert(target.entra, secrets) as cert_path:
            entra = _entra_collector(target.entra, secrets, cert_path).collect()
        if snap is None:
            snap = entra
        else:
            snap.entra = entra.entra
    if snap is None:
        raise ValueError(f"La cible {target.name} ne définit ni 'ad' ni 'entra'")
    return snap


def test_target(target: Target, secrets: SecretStore, progress=_noop) -> dict:
    """Vérifie l'authentification sans rien collecter. Retourne un état par source."""
    out: dict[str, dict] = {}
    if target.ad:
        from ..collectors.ldap_collector import LdapCollector

        ad = target.ad
        progress(20, f"Connexion LDAP{'S' if ad.ldaps else ''} à {ad.dc}")
        try:
            ldap = LdapCollector(ad.dc, ad.domain, ad.username, secrets.get(ad.password_secret), use_ldaps=ad.ldaps)
            ldap.connect()
            out["ad"] = {"ok": True, "detail": f"Authentifié ; contexte {ldap.base_dn}"}
            ldap.conn.unbind()
        except Exception as exc:
            out["ad"] = {"ok": False, "detail": str(exc)[:300]}
    if target.entra:
        progress(60, "Authentification Microsoft Graph")
        try:
            with _entra_cert(target.entra, secrets) as cert_path:
                _entra_collector(target.entra, secrets, cert_path)._token()
            out["entra"] = {"ok": True, "detail": "Jeton Microsoft Graph obtenu"}
        except Exception as exc:
            out["entra"] = {"ok": False, "detail": str(exc)[:300]}
    return out


def _wsus_probes(snap: Snapshot):
    from urllib.parse import urlparse

    from ..collectors.probes import probe_tls_service

    key = r"machine\software\policies\microsoft\windows\windowsupdate\wuserver"
    urls = {g.registry[key] for g in snap.gpos or [] if key in g.registry}
    out = []
    for url in urls:
        u = urlparse(str(url))
        if u.scheme == "https" and u.hostname:
            try:
                out.append(probe_tls_service(u.hostname, u.port or 8531, "wsus"))
            except Exception as exc:
                log.warning("Sonde TLS WSUS %s impossible (%s)", url, exc)
    return out


def _ai(result_path: Path, scan_id: str) -> dict:
    from ..ai.admin import context_for, load_settings
    from ..ai.ollama_client import OllamaClient, analyze_with_llm

    settings = load_settings()
    client = OllamaClient(model=settings.analyst_model)
    result = ScanResult.model_validate_json(result_path.read_text(encoding="utf-8"))
    try:
        context = context_for(result, settings, client)
    except Exception as exc:  # la base de connaissances est un plus : la synthèse se fait sans elle
        log.warning("Base de connaissances indisponible (%s)", exc)
        context = []
    analysis = analyze_with_llm(result, client=client, context_snippets=context)
    analysis["_contexte"] = {"extraits": len(context), "modele": settings.analyst_model}
    (DATA_DIR / f"{scan_id}.ai.json").write_text(json.dumps(analysis, ensure_ascii=False, indent=1), encoding="utf-8")
    return analysis


def save_topology(snap: Snapshot, scan_id: str) -> None:
    """Graphe des comptes/groupes et carte des approbations, à côté du rapport (non bloquant)."""
    from ..topology import build

    try:
        (DATA_DIR / f"{scan_id}.graph.json").write_text(json.dumps(build(snap), ensure_ascii=False), encoding="utf-8")
    except Exception:
        log.exception("Topologie non calculée pour %s", scan_id)


def run_target(target: Target, secrets: SecretStore | None = None, progress=_noop) -> Path:
    secrets = secrets or SecretStore()
    started = datetime.now()
    snap = collect_target(target, secrets, progress)
    progress(85, "Analyse : application du catalogue de règles")
    result = analyze(snap)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = f"{started:%Y%m%d-%H%M%S}-{target.name}"
    path = DATA_DIR / f"{scan_id}.json"
    path.write_text(result.model_dump_json(indent=1), encoding="utf-8")
    save_topology(snap, scan_id)
    log.info("%s : score %s/100, %s constats -> %s", target.name, result.global_score, len(result.findings), path)
    if target.ai_analysis:
        progress(90, "Synthèse par l'IA locale")
        try:
            _ai(path, scan_id)
        except Exception as exc:
            msg = f"Analyse IA indisponible ({exc})"
            log.warning("%s : %s", target.name, msg)
            progress.warn(msg)
    return path


# ----------------------------------------------------------------------------- tâches de la console


def execute_job(job: Job, store: JobStore, secrets: SecretStore | None = None) -> Job:
    secrets = secrets or SecretStore()
    progress = Progress(store, job)
    try:
        if job.kind == JobKind.ai:
            progress(10, "Synthèse par l'IA locale (1 à 5 minutes sur CPU)")
            _ai(DATA_DIR / f"{job.scan_id}.json", job.scan_id)
        elif job.kind == JobKind.ai_setup:
            job.result = setup_ai(progress)
        elif job.kind == JobKind.ai_script:
            from ..remediation.ai import draft_script

            progress(10, f"Rédaction d'un brouillon de script pour {job.target} par l'IA locale")
            result = ScanResult.model_validate_json((DATA_DIR / f"{job.scan_id}.json").read_text(encoding="utf-8"))
            job.result = draft_script(job.scan_id, result, job.target, DATA_DIR)
        elif job.kind == JobKind.notify:
            progress(20, "Notifications et intégrations")
            job.result = _integrations_after_scan(job.scan_id)
        elif job.kind == JobKind.ticket:
            from ..integrations.dispatch import create_ticket

            progress(20, f"Création d'un ticket pour {job.target}")
            job.result = create_ticket(job.scan_id, job.target)
        elif job.kind == JobKind.integration_test:
            from ..integrations.dispatch import test

            progress(20, f"Test de l'intégration {job.target}")
            job.result = {"detail": test(job.target)}
        elif job.kind == JobKind.ai_index:
            from ..ai.admin import build_index

            progress(10, "Calcul des embeddings du catalogue et des documents")
            job.result = {"chunks": build_index()}
        else:
            target = next((t for t in load_targets() if t.name == job.target), None)
            if target is None:
                raise ValueError(f"Cible inconnue : {job.target}")
            if job.kind == JobKind.test:
                job.result = test_target(target, secrets, progress)
                if not all(v["ok"] for v in job.result.values()):
                    raise RuntimeError(
                        "Échec de connexion : "
                        + " ; ".join(f"{k.upper()} : {v['detail']}" for k, v in job.result.items() if not v["ok"])
                    )
            else:
                path = run_target(target, secrets, progress)
                job.scan_id = path.stem
                r = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
                job.result = {"global_score": r.global_score, "findings": len(r.findings), "domain": r.domain}
                progress(97, "Notifications et intégrations")
                job.result["integrations"] = _integrations_after_scan(job.scan_id)
        job.status, job.progress, job.step = JobStatus.succeeded, 100, "Terminé"
    except Exception as exc:
        log.exception("Tâche %s (%s %s) en échec", job.id, job.kind, job.target or job.scan_id)
        job.status, job.error, job.step = JobStatus.failed, str(exc)[:500], "Échec"
        if job.kind == JobKind.scan:
            try:
                from ..integrations.dispatch import on_scan_failed

                on_scan_failed(job.target or "?", job.error)
            except Exception:
                log.exception("Notification d'échec impossible")
    job.finished_at = datetime.now(UTC)
    job.log.append(
        {
            "at": job.finished_at.isoformat(),
            "level": "info" if job.status == "succeeded" else "error",
            "msg": job.step if job.status == "succeeded" else job.error,
        }
    )
    return store.save(job)


def setup_ai(progress=_noop) -> dict:
    """Télécharge le modèle de base et le modèle d'embeddings, puis crée le modèle analyste."""
    from ..ai.admin import OllamaAdmin, load_settings

    s = load_settings()
    admin = OllamaAdmin()
    progress(2, f"Connexion à Ollama (version {admin.version()})")
    last = {"pct": -1}

    def phase(start: int, span: int):
        def report(frac: float, label: str) -> None:
            pct = start + int(span * frac) if frac >= 0 else start
            if frac < 0:  # changement d'état (manifeste, vérification, succès) : journalisé
                progress(pct, label)
            elif pct != last["pct"]:  # avancement du téléchargement : étape mise à jour, non journalisée
                last["pct"] = pct
                progress(pct, label, log=False)

        return report

    admin.pull(s.base_model, phase(5, 70))
    admin.pull(s.embed_model, phase(76, 14))
    progress(92, f"Création du modèle {s.analyst_model} à partir de {s.base_model}")
    admin.create_analyst(s.analyst_model, s.base_model, lambda st: None)
    return {"base_model": s.base_model, "embed_model": s.embed_model, "analyst_model": s.analyst_model}


def _integrations_after_scan(scan_id: str) -> dict:
    """Notifications, SIEM et tickets après un scan ; une erreur ici ne fait jamais échouer le scan."""
    try:
        from ..integrations.dispatch import on_scan_finished

        return on_scan_finished(scan_id)
    except Exception as exc:
        log.exception("Intégrations après le scan %s", scan_id)
        return {"error": str(exc)[:300]}


def _start_heartbeat(stop: threading.Event | None) -> None:
    """Signale à la console que le worker tourne, y compris pendant un long scan."""
    path = STATE_DIR / "worker.heartbeat"

    def beat():
        while not (stop and stop.is_set()):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            except OSError as exc:
                log.warning("Battement de cœur impossible : %s", exc)
            time.sleep(20)

    threading.Thread(target=beat, name="adsentry-heartbeat", daemon=True).start()


def worker_loop(poll_seconds: int = 3, stop: threading.Event | None = None) -> None:
    """Exécute les tâches déposées par la console et lance les scans planifiés (cron)."""
    log.info("Planificateur ADSentry démarré")
    store = JobStore()
    if n := store.recover_interrupted():
        log.warning("%s tâche(s) interrompue(s) marquée(s) en échec", n)
    last_minute = ""
    _start_heartbeat(stop)
    while not (stop and stop.is_set()):
        now = datetime.now()
        minute_key = now.strftime("%Y%m%d%H%M")
        if minute_key != last_minute:
            last_minute = minute_key
            for target in load_targets():
                if target.schedule and cron_matches(target.schedule, now):
                    try:
                        store.create(JobKind.scan, target=target.name, trigger="schedule")
                    except JobConflict:
                        log.info("%s : scan déjà en cours, planification ignorée", target.name)
            if now.minute == 0:
                store.purge()
            try:  # journal d'audit de la console vers le SIEM
                from ..integrations.dispatch import forward_audit

                forward_audit()
            except Exception:
                log.exception("Transfert du journal d'audit au SIEM impossible")
        job = store.claim_next()
        if job is not None:
            execute_job(job, store)
            continue
        if stop:
            stop.wait(poll_seconds)
        else:
            time.sleep(poll_seconds)
