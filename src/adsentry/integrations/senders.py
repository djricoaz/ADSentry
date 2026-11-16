"""Envois vers les systèmes externes. Exécutés uniquement par le worker (seul conteneur avec accès sortant).

Chaque fonction lève une exception explicite en cas d'échec ; le répartiteur la journalise et la signale dans le
centre de notifications sans interrompre le scan.
"""

from __future__ import annotations

import json
import smtplib
import socket
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage

import httpx

from .. import __version__ as VERSION
from .settings import (
    EmailSettings,
    JiraSettings,
    ServiceNowSettings,
    SplunkSettings,
    SyslogSettings,
    WebhookSettings,
)

SEV_LABEL = {"critical": "Critique", "high": "Élevé", "medium": "Moyen", "low": "Faible", "info": "Info"}
CEF_SEVERITY = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
FACILITY_LOCAL4 = 20
TIMEOUT = httpx.Timeout(15)


def _client(verify: bool = True) -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, verify=verify)


# ----------------------------------------------------------------------------- formats SIEM


def _cef_header(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", "\\n")


def to_cef(event: dict) -> str:
    """Common Event Format : CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Ext."""
    sev = event.get("severity", "info")
    ext = {
        "rt": int(datetime.fromisoformat(event["at"]).timestamp() * 1000),
        "dvchost": event.get("domain", ""),
        "cat": event.get("type", ""),
        "act": event.get("change", ""),
        "msg": event.get("summary", ""),
        "cs1Label": "objets",
        "cs1": ", ".join(event.get("affected", [])[:20]),
        "cn1Label": "nbObjets",
        "cn1": len(event.get("affected", [])),
        "cs2Label": "mitre",
        "cs2": ",".join(event.get("mitre", [])),
        "cs3Label": "scan",
        "cs3": event.get("scan_id", ""),
    }
    body = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in ("", None))
    sig, name = event.get("rule_id") or event.get("type", "event"), event.get("title", "")
    head = "|".join(["CEF:0", "ADSentry", "ADSentry", _cef_header(VERSION), _cef_header(sig), _cef_header(name)])
    return f"{head}|{CEF_SEVERITY.get(sev, 1)}|{body}"


def to_syslog(event: dict, fmt: str) -> bytes:
    """RFC 5424 : <PRI>1 HORODATAGE HÔTE APPLICATION PROCID MSGID - MESSAGE"""
    pri = FACILITY_LOCAL4 * 8 + SYSLOG_SEVERITY.get(event.get("severity", "info"), 6)
    msg = to_cef(event) if fmt == "cef" else json.dumps(event, ensure_ascii=False)
    host = socket.gethostname()[:255] or "-"
    return f"<{pri}>1 {event['at']} {host} ADSentry - {event.get('type', 'event')} - {msg}\n".encode()


def send_syslog(cfg: SyslogSettings, events: list[dict]) -> int:
    if not events:
        return 0
    lines = [to_syslog(e, cfg.format) for e in events]
    if cfg.protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for line in lines:
                s.sendto(line[:8192], (cfg.host, cfg.port))
        return len(lines)
    raw = socket.create_connection((cfg.host, cfg.port), timeout=15)
    try:
        if cfg.protocol == "tls":
            ctx = ssl.create_default_context()
            if not cfg.verify_tls:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=cfg.host)
        for line in lines:
            raw.sendall(line)
    finally:
        raw.close()
    return len(lines)


def send_splunk(cfg: SplunkSettings, token: str, events: list[dict]) -> int:
    if not events:
        return 0
    payload = "\n".join(
        json.dumps(
            {
                "time": datetime.fromisoformat(e["at"]).timestamp(),
                "sourcetype": "adsentry:" + e.get("type", "event"),
                "source": "adsentry",
                **({"index": cfg.index} if cfg.index else {}),
                "event": e,
            },
            ensure_ascii=False,
        )
        for e in events
    )
    with _client(cfg.verify_tls) as c:
        r = c.post(f"{cfg.url}/services/collector/event", content=payload, headers={"Authorization": f"Splunk {token}"})
    if r.status_code >= 300:
        raise RuntimeError(f"Splunk HEC : {r.status_code} {r.text[:200]}")
    return len(events)


# ----------------------------------------------------------------------------- notifications


def message_text(notice: dict) -> str:
    lines = [notice["title"], "", notice.get("body", "")]
    if notice.get("link"):
        lines += ["", notice["link"]]
    return "\n".join(lines).strip()


def send_webhook(cfg: WebhookSettings, url: str, notice: dict) -> None:
    if cfg.format == "slack":
        payload = {"text": message_text(notice)}
    elif cfg.format == "teams":
        payload = {"text": message_text(notice).replace("\n", "<br>"), "title": notice["title"]}
    else:
        payload = {"source": "ADSentry", **notice}
    with _client() as c:
        r = c.post(url, json=payload)
    if r.status_code >= 300:
        raise RuntimeError(f"Webhook : {r.status_code} {r.text[:200]}")


def send_email(cfg: EmailSettings, password: str | None, notice: dict) -> None:
    if not cfg.recipients:
        raise ValueError("Aucun destinataire")
    msg = EmailMessage()
    msg["Subject"] = f"[ADSentry] {notice['title']}"
    msg["From"] = cfg.sender or cfg.username
    msg["To"] = ", ".join(cfg.recipients)
    msg.set_content(message_text(notice) + "\n\n-- \nMessage automatique d'ADSentry.")
    ctx = ssl.create_default_context()
    smtp_cls = smtplib.SMTP_SSL if cfg.security == "ssl" else smtplib.SMTP
    kwargs = {"context": ctx} if cfg.security == "ssl" else {}
    with smtp_cls(cfg.host, cfg.port, timeout=20, **kwargs) as s:
        if cfg.security == "starttls":
            s.starttls(context=ctx)
        if cfg.username and password:
            s.login(cfg.username, password)
        s.send_message(msg)


# ----------------------------------------------------------------------------- tickets (ITSM)


def ticket_text(finding: dict, domain: str, console_url: str) -> tuple[str, str]:
    summary = f"[ADSentry] {finding['rule_id']} — {finding['title']} ({domain})"[:250]
    affected = finding.get("affected", [])
    parts = [
        f"Domaine : {domain}",
        f"Sévérité : {SEV_LABEL.get(finding['severity'], finding['severity'])}",
        f"Règle : {finding['rule_id']}",
        "",
        "Risque :",
        finding.get("description", ""),
        "",
        "Correction recommandée :",
        finding.get("remediation", ""),
    ]
    if finding.get("detection"):
        parts += ["", "Détection :", finding["detection"]]
    parts += ["", f"Objets concernés ({len(affected)}) :", *[f"- {a}" for a in affected[:50]]]
    if len(affected) > 50:
        parts.append(f"… et {len(affected) - 50} autres")
    if finding.get("mitre"):
        parts += ["", "MITRE ATT&CK : " + ", ".join(m["technique"] for m in finding["mitre"])]
    parts += ["", "Un script PowerShell de correction (simulation par défaut) est disponible dans la fiche du constat."]
    if console_url:
        parts.append(f"Console : {console_url}")
    return summary, "\n".join(parts)


def create_jira(cfg: JiraSettings, token: str, finding: dict, domain: str, console_url: str) -> dict:
    summary, description = ticket_text(finding, domain, console_url)
    fields = {
        "project": {"key": cfg.project},
        "summary": summary,
        "description": description,
        "issuetype": {"name": cfg.issue_type or "Task"},
        "labels": ["adsentry", finding["rule_id"].lower()],
    }
    headers = {"Accept": "application/json"}
    auth = None
    if cfg.auth == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    else:
        auth = (cfg.username, token)
    with _client() as c:
        r = c.post(f"{cfg.url}/rest/api/2/issue", json={"fields": fields}, headers=headers, auth=auth)
    if r.status_code >= 300:
        raise RuntimeError(f"Jira : {r.status_code} {r.text[:300]}")
    key = r.json()["key"]
    return {"system": "jira", "key": key, "url": f"{cfg.url}/browse/{key}"}


SNOW_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}
SNOW_IMPACT = {"critical": "1", "high": "2", "medium": "2", "low": "3", "info": "3"}


def create_servicenow(cfg: ServiceNowSettings, password: str, finding: dict, domain: str, console_url: str) -> dict:
    summary, description = ticket_text(finding, domain, console_url)
    body = {
        "short_description": summary,
        "description": description,
        "urgency": SNOW_URGENCY.get(finding["severity"], "3"),
        "impact": SNOW_IMPACT.get(finding["severity"], "3"),
        "category": "security",
        **({"assignment_group": cfg.assignment_group} if cfg.assignment_group else {}),
    }
    with _client() as c:
        r = c.post(
            f"{cfg.url}/api/now/table/incident",
            json=body,
            auth=(cfg.username, password),
            headers={"Accept": "application/json"},
        )
    if r.status_code >= 300:
        raise RuntimeError(f"ServiceNow : {r.status_code} {r.text[:300]}")
    res = r.json()["result"]
    return {
        "system": "servicenow",
        "key": res.get("number", res.get("sys_id")),
        "url": f"{cfg.url}/nav_to.do?uri=incident.do?sys_id={res.get('sys_id')}",
    }


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def check_itsm(kind: str, cfg, secret: str) -> None:
    """Vérifie l'authentification Jira / ServiceNow sans rien créer."""
    with _client() as c:
        if kind == "jira":
            headers = {"Accept": "application/json"}
            auth = None
            if cfg.auth == "bearer":
                headers["Authorization"] = f"Bearer {secret}"
            else:
                auth = (cfg.username, secret)
            r = c.get(f"{cfg.url}/rest/api/2/project/{cfg.project}", headers=headers, auth=auth)
        else:
            r = c.get(
                f"{cfg.url}/api/now/table/incident",
                params={"sysparm_limit": "1"},
                auth=(cfg.username, secret),
                headers={"Accept": "application/json"},
            )
    if r.status_code >= 300:
        raise RuntimeError(f"{kind} : {r.status_code} {r.text[:200]}")
