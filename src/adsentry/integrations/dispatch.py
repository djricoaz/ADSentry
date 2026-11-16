"""Répartiteur des intégrations : appelé par le worker après chaque scan, en cas d'échec, pour un ticket manuel,
un test ou le transfert du journal d'audit vers le SIEM."""

from __future__ import annotations

import json
import logging

from ..appliance import config as _cfg
from ..appliance.config import SecretStore
from ..models import Finding, ScanResult
from . import notifications as N
from . import senders as S
from .settings import SEVERITIES, at_least, load, record_status, secret_name

log = logging.getLogger("adsentry.integrations")


def _secret(kind: str) -> str | None:
    try:
        return SecretStore().get(secret_name(kind))
    except KeyError:
        return None


def _link(console: str, path: str) -> str | None:
    return f"{console}/{path}" if console else None


def _guard(kind: str, fn, *args) -> bool:
    try:
        detail = fn(*args)
        record_status(kind, True, f"Envoyé ({detail})" if isinstance(detail, int) else "Envoyé")
        return True
    except Exception as exc:  # une intégration en échec n'interrompt jamais le scan
        log.warning("Intégration %s en échec : %s", kind, exc)
        record_status(kind, False, str(exc))
        N.add(f"Intégration {kind} en échec", str(exc)[:500], "warning", audience="admin")
        return False


# ----------------------------------------------------------------------------- événements


def _previous(result: ScanResult, scan_id: str) -> ScanResult | None:
    from ..history import load_all

    same = [(sid, r) for sid, r in load_all(_cfg.DATA_DIR) if r.domain == result.domain and sid != scan_id]
    older = [x for x in same if x[1].collected_at <= result.collected_at]
    return older[-1][1] if older else None


def _finding_event(f: Finding, result: ScanResult, scan_id: str, change: str) -> dict:
    return {
        "type": "finding",
        "change": change,  # new | resolved | present
        "at": result.collected_at.isoformat(),
        "domain": result.ad_domain or result.domain,
        "scan_id": scan_id,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category.value,
        "points": f.points,
        "affected": f.affected[:200],
        "mitre": [m.technique for m in f.mitre],
        "summary": f.description[:500],
    }


def diff(result: ScanResult, prev: ScanResult | None) -> tuple[list[Finding], list[Finding]]:
    before = {f.rule_id: f for f in prev.findings} if prev else {}
    now = {f.rule_id: f for f in result.findings}
    new = [f for rid, f in now.items() if rid not in before] if prev else list(now.values())
    resolved = [f for rid, f in before.items() if rid not in now]
    return new, resolved


def _sorted(fs: list[Finding]) -> list[Finding]:
    return sorted(fs, key=lambda f: (-SEVERITIES.index(f.severity.value), -f.points))


# ----------------------------------------------------------------------------- fin de scan


def on_scan_finished(scan_id: str) -> dict:
    result = ScanResult.model_validate_json((_cfg.DATA_DIR / f"{scan_id}.json").read_text(encoding="utf-8"))
    prev = _previous(result, scan_id)
    new, resolved = diff(result, prev)
    cfg = load()
    crit = sum(1 for f in result.findings if f.severity.value == "critical")
    link = _link(cfg.console_url, "#/overview")
    first = prev is None
    summary = {
        "title": f"Scan terminé : {result.domain} — score {result.global_score}/100",
        "body": f"{len(result.findings)} constats, dont {crit} critiques. "
        + ("Premier scan de ce périmètre." if first else f"Nouveaux : {len(new)}, corrigés : {len(resolved)}."),
        "link": link,
    }
    N.add(summary["title"], summary["body"], "warning" if crit else "success", link)

    report: dict = {"new": len(new), "resolved": len(resolved)}
    # Notifications : résumé + nouveaux constats graves
    for kind, c in (("email", cfg.email), ("webhook", cfg.webhook)):
        if not c.enabled:
            continue
        grave = (
            [f for f in _sorted(new) if at_least(f.severity.value, c.events.min_severity)]
            if c.events.new_findings
            else []
        )
        if not (c.events.scan_finished or grave):
            continue
        body = summary["body"]
        if grave:
            body += "\n\nNouveaux constats :\n" + "\n".join(
                f"- [{S.SEV_LABEL[f.severity.value]}] {f.rule_id} — {f.title}" for f in grave[:30]
            )
        notice = {**summary, "body": body, "level": "warning" if grave else "info"}
        if kind == "email":
            report[kind] = _guard(kind, S.send_email, c, _secret(kind), notice)
        else:
            report[kind] = _guard(kind, S.send_webhook, c, _secret(kind) or c.url, notice)
    if new and not first:
        grave = [f for f in _sorted(new) if f.severity.value in ("critical", "high")]
        if grave:
            N.add(
                f"{len(grave)} nouveau(x) constat(s) grave(s) sur {result.domain}",
                "\n".join(f"{f.rule_id} — {f.title}" for f in grave[:10]),
                "critical",
                _link(cfg.console_url, "#/findings"),
            )

    # SIEM : résumé du scan + constats nouveaux/corrigés (ou tous)
    scan_event = {
        "type": "scan",
        "at": result.collected_at.isoformat(),
        "domain": result.ad_domain or result.domain,
        "scan_id": scan_id,
        "title": summary["title"],
        "severity": "critical" if crit else "info",
        "score": result.global_score,
        "findings": len(result.findings),
        "new": len(new),
        "resolved": len(resolved),
        "summary": summary["body"],
    }
    for kind, c in (("syslog", cfg.syslog), ("splunk", cfg.splunk)):
        if not c.enabled:
            continue
        if c.send == "all":
            events = [_finding_event(f, result, scan_id, "new" if f in new else "present") for f in result.findings]
        else:
            events = [_finding_event(f, result, scan_id, "new") for f in new]
        events += [{**_finding_event(f, result, scan_id, "resolved"), "severity": "info"} for f in resolved]
        events.insert(0, scan_event)
        if kind == "syslog":
            report[kind] = _guard(kind, S.send_syslog, c, events)
        else:
            report[kind] = _guard(kind, S.send_splunk, c, _secret(kind) or "", events)

    # ITSM : tickets automatiques pour les nouveaux constats graves (sans doublon)
    created = []
    for f in _sorted(new):
        for system, c in (("jira", cfg.jira), ("servicenow", cfg.servicenow)):
            if c.enabled and at_least(f.severity.value, c.auto_min_severity) and not ticket_for(result, f.rule_id):
                t = _create(system, result, f, scan_id)
                if t:
                    created.append(t["key"])
                break
    if created:
        report["tickets"] = created
    return report


def on_scan_failed(target: str, error: str) -> None:
    cfg = load()
    notice = {"title": f"Échec du scan « {target} »", "body": error[:800], "link": _link(cfg.console_url, "#/jobs")}
    N.add(notice["title"], notice["body"], "critical", notice["link"], audience="admin")
    if cfg.email.enabled and cfg.email.events.scan_failed:
        _guard("email", S.send_email, cfg.email, _secret("email"), notice)
    if cfg.webhook.enabled and cfg.webhook.events.scan_failed:
        _guard("webhook", S.send_webhook, cfg.webhook, _secret("webhook") or cfg.webhook.url, notice)


# ----------------------------------------------------------------------------- tickets


def _tickets_path():
    return _cfg.STATE_DIR / "tickets.json"


def _tickets() -> dict:
    p = _tickets_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _key(result: ScanResult, rule_id: str) -> str:
    return f"{result.ad_domain or result.domain}|{rule_id}"


def ticket_for(result: ScanResult, rule_id: str) -> dict | None:
    return _tickets().get(_key(result, rule_id))


def tickets_for_scan(result: ScanResult) -> dict:
    all_t = _tickets()
    return {f.rule_id: all_t[_key(result, f.rule_id)] for f in result.findings if _key(result, f.rule_id) in all_t}


def _create(system: str, result: ScanResult, f: Finding, scan_id: str) -> dict | None:
    cfg = load()
    finding = json.loads(f.model_dump_json())
    domain = result.ad_domain or result.domain
    try:
        if system == "jira":
            t = S.create_jira(cfg.jira, _secret("jira") or "", finding, domain, cfg.console_url)
        else:
            t = S.create_servicenow(cfg.servicenow, _secret("servicenow") or "", finding, domain, cfg.console_url)
    except Exception as exc:
        record_status(system, False, str(exc))
        N.add(f"Ticket {system} non créé pour {f.rule_id}", str(exc)[:500], "warning", audience="admin")
        return None
    t.update(created_at=S.now_iso(), scan_id=scan_id, rule_id=f.rule_id)
    data = _tickets()
    data[_key(result, f.rule_id)] = t
    _tickets_path().write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    record_status(system, True, f"Ticket {t['key']} créé")
    N.add(f"Ticket {t['key']} créé : {f.rule_id}", f.title, "info", t["url"], audience="admin")
    return t


def create_ticket(scan_id: str, rule_id: str) -> dict:
    result = ScanResult.model_validate_json((_cfg.DATA_DIR / f"{scan_id}.json").read_text(encoding="utf-8"))
    f = next((x for x in result.findings if x.rule_id == rule_id), None)
    if f is None:
        raise ValueError("Constat introuvable")
    existing = ticket_for(result, rule_id)
    if existing:
        return existing
    cfg = load()
    system = "jira" if cfg.jira.enabled else "servicenow" if cfg.servicenow.enabled else None
    if system is None:
        raise ValueError("Aucun outil de tickets activé (Jira ou ServiceNow)")
    t = _create(system, result, f, scan_id)
    if t is None:
        raise RuntimeError(f"Création du ticket {system} impossible : voir Administration > Intégrations")
    return t


# ----------------------------------------------------------------------------- tests et journal d'audit


def test(kind: str) -> str:
    cfg = load()
    c = getattr(cfg, kind)
    notice = {
        "title": "Test de l'intégration ADSentry",
        "body": "Si vous lisez ce message, l'intégration fonctionne.",
        "link": cfg.console_url or None,
    }
    event = {
        "type": "test",
        "at": S.now_iso(),
        "domain": "-",
        "title": notice["title"],
        "severity": "info",
        "summary": notice["body"],
    }
    if kind == "email":
        S.send_email(c, _secret(kind), notice)
    elif kind == "webhook":
        S.send_webhook(c, _secret(kind) or c.url, notice)
    elif kind == "syslog":
        S.send_syslog(c, [event])
    elif kind == "splunk":
        S.send_splunk(c, _secret(kind) or "", [event])
    elif kind in ("jira", "servicenow"):
        S.check_itsm(kind, c, _secret(kind) or "")
    record_status(kind, True, "Test réussi")
    return "Test réussi"


def forward_audit() -> int:
    """Transfère au SIEM les nouvelles lignes du journal d'audit de la console (connexions, cibles, scans…)."""
    cfg = load()
    targets = [
        k for k, c in (("syslog", cfg.syslog), ("splunk", cfg.splunk)) if c.enabled and getattr(c, "audit_log", True)
    ]
    audit_path = _cfg.STATE_DIR / "audit.log"
    marker = _cfg.STATE_DIR / "audit-forwarded.offset"
    if not targets or not audit_path.exists():
        return 0
    offset = int(marker.read_text() or 0) if marker.exists() else 0
    size = audit_path.stat().st_size
    if size < offset:
        offset = 0  # journal tourné
    with audit_path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    lines = [json.loads(x) for x in chunk.decode("utf-8", "replace").splitlines() if x.strip()]
    if not lines:
        return 0
    severity = {"login_failed": "medium", "login_locked": "high"}
    events = [
        {
            "type": "audit",
            "at": e["at"],
            "domain": "console",
            "title": e["event"],
            "rule_id": e["event"],
            "severity": severity.get(e["event"], "info"),
            "summary": json.dumps(e, ensure_ascii=False),
        }
        for e in lines
    ]
    ok = True
    for kind in targets:
        c = getattr(cfg, kind)
        ok &= (
            _guard(kind, S.send_syslog, c, events)
            if kind == "syslog"
            else _guard(kind, S.send_splunk, c, _secret(kind) or "", events)
        )
    if ok:
        marker.write_text(str(offset + len(chunk)))
    return len(events)
