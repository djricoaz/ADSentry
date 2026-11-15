"""Exécution d'une cible (collecte AD + Entra -> analyse -> stockage) et boucle de planification."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

from ..models import Snapshot
from ..rules.engine import analyze
from .config import SecretStore, Target, cron_matches, load_targets

log = logging.getLogger("adsentry.worker")
DATA_DIR = Path(os.environ.get("ADSENTRY_DATA", "/var/lib/adsentry/scans"))


def collect_target(target: Target, secrets: SecretStore) -> Snapshot:
    snap: Snapshot | None = None
    if target.ad:
        from ..collectors.ldap_collector import LdapCollector

        ad = target.ad
        password = secrets.get(ad.password_secret)
        ldap = LdapCollector(ad.dc, ad.domain, ad.username, password, use_ldaps=ad.ldaps)
        snap = ldap.collect()
        if ad.sysvol:
            from ..collectors.sysvol_collector import SysvolCollector

            try:
                snap.gpos = SysvolCollector(ldap, ad.dc, ad.domain, ad.username, password).collect(ldap.gpo_writers())
            except Exception as exc:
                log.warning("%s : lecture SYSVOL impossible (%s) — règles GPO non évaluées", target.name, exc)
        if ad.probes:
            from ..collectors import probes

            for dc in snap.dcs():
                host = dc.dns_hostname or dc.name
                try:
                    snap.dc_probes.append(
                        probes.probe_dc(dc.name, host, ad.domain, ad.username, password, ldap.base_dn)
                    )
                except Exception as exc:
                    log.warning("%s : sondes sur %s impossibles (%s)", target.name, dc.name, exc)
            snap.tls_probes += _wsus_probes(snap)
    if target.entra:
        from pathlib import Path as _P

        from ..collectors.entra_collector import EntraCollector

        e = target.entra
        entra = EntraCollector(
            e.tenant_id,
            e.client_id,
            cert_path=_P(e.certificate) if e.certificate else None,
            cert_thumbprint=e.thumbprint,
            client_secret=secrets.get(e.client_secret_secret) if e.client_secret_secret else None,
            connect_version=e.connect_version,
        ).collect()
        if snap is None:
            snap = entra
        else:
            snap.entra = entra.entra
    if snap is None:
        raise ValueError(f"La cible {target.name} ne définit ni 'ad' ni 'entra'")
    return snap


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


def run_target(target: Target, secrets: SecretStore | None = None) -> Path:
    secrets = secrets or SecretStore()
    started = datetime.now()
    snap = collect_target(target, secrets)
    result = analyze(snap)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = f"{started:%Y%m%d-%H%M}-{target.name}"
    path = DATA_DIR / f"{scan_id}.json"
    path.write_text(result.model_dump_json(indent=1), encoding="utf-8")
    log.info("%s : score %s/100, %s constats -> %s", target.name, result.global_score, len(result.findings), path)
    if target.ai_analysis:
        try:
            from ..ai.ollama_client import analyze_with_llm

            analysis = analyze_with_llm(result)
            (DATA_DIR / f"{scan_id}.ai.json").write_text(json.dumps(analysis, ensure_ascii=False, indent=1))
        except Exception as exc:
            log.warning("%s : analyse IA indisponible (%s)", target.name, exc)
    return path


def worker_loop(poll_seconds: int = 30) -> None:
    """Vérifie chaque minute les plannings cron des cibles et lance les scans dus."""
    log.info("Planificateur ADSentry démarré")
    last_run: dict[str, str] = {}
    while True:
        now = datetime.now()
        minute_key = now.strftime("%Y%m%d%H%M")
        for target in load_targets():
            if cron_matches(target.schedule, now) and last_run.get(target.name) != minute_key:
                last_run[target.name] = minute_key
                try:
                    run_target(target)
                except Exception:
                    log.exception("Échec du scan %s", target.name)
        time.sleep(poll_seconds)
