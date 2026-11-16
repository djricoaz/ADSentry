"""Réglages des intégrations (notifications, SIEM, ITSM), modifiables par les administrateurs dans la console.

Les secrets (mots de passe SMTP, jetons Splunk / Jira, mots de passe ServiceNow) sont chiffrés dans le SecretStore
sous le nom « integration-<type> » ; ils ne sont jamais renvoyés au navigateur.
"""

from __future__ import annotations

import json
import os
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ..appliance import config as _cfg

SEVERITIES = ["info", "low", "medium", "high", "critical"]
Severity = Literal["info", "low", "medium", "high", "critical"]


def _https(v: str) -> str:
    v = v.strip()
    if v and not v.lower().startswith(("https://", "http://")):
        raise ValueError("L'adresse doit commencer par https://")
    return v.rstrip("/")


class Events(BaseModel):
    scan_finished: bool = True
    new_findings: bool = True
    scan_failed: bool = True
    min_severity: Severity = "high"  # constats nouveaux signalés à partir de ce niveau


class EmailSettings(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str = ""
    sender: str = ""
    recipients: list[str] = []
    events: Events = Events()


class WebhookSettings(BaseModel):
    enabled: bool = False
    url: str = ""
    format: Literal["json", "teams", "slack"] = "json"
    events: Events = Events()

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)


class SyslogSettings(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(514, ge=1, le=65535)
    protocol: Literal["udp", "tcp", "tls"] = "udp"
    format: Literal["cef", "json"] = "cef"
    verify_tls: bool = True
    send: Literal["new", "all"] = "new"  # constats nouveaux et corrigés, ou tous les constats à chaque scan
    audit_log: bool = True


class SplunkSettings(BaseModel):
    enabled: bool = False
    url: str = ""  # https://splunk:8088
    index: str = ""
    verify_tls: bool = True
    send: Literal["new", "all"] = "new"

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)


class JiraSettings(BaseModel):
    enabled: bool = False
    url: str = ""
    auth: Literal["basic", "bearer"] = "basic"  # Cloud : e-mail + jeton d'API ; Data Center : jeton personnel
    username: str = ""
    project: str = ""
    issue_type: str = "Task"
    auto_min_severity: Severity | None = None  # création automatique pour les nouveaux constats à partir de ce niveau

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)


class ServiceNowSettings(BaseModel):
    enabled: bool = False
    url: str = ""  # https://instance.service-now.com
    username: str = ""
    assignment_group: str = ""
    auto_min_severity: Severity | None = None

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)


class IntegrationSettings(BaseModel):
    console_url: str = ""  # adresse de la console, pour les liens dans les messages et tickets
    email: EmailSettings = EmailSettings()
    webhook: WebhookSettings = WebhookSettings()
    syslog: SyslogSettings = SyslogSettings()
    splunk: SplunkSettings = SplunkSettings()
    jira: JiraSettings = JiraSettings()
    servicenow: ServiceNowSettings = ServiceNowSettings()

    @field_validator("console_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)


KINDS = ("email", "webhook", "syslog", "splunk", "jira", "servicenow")
SECRET_FIELDS = {
    "email": "mot de passe SMTP",
    "webhook": "adresse secrète",
    "splunk": "jeton HEC",
    "jira": "jeton",
    "servicenow": "mot de passe",
}


def secret_name(kind: str) -> str:
    return f"integration-{kind}"


def _path():
    return _cfg.STATE_DIR / "integrations.json"


def load() -> IntegrationSettings:
    path = _path()
    if path.exists():
        try:
            return IntegrationSettings.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return IntegrationSettings()


def save(s: IntegrationSettings) -> IntegrationSettings:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(s.model_dump_json(indent=1), encoding="utf-8")
    os.replace(tmp, path)
    return s


def at_least(severity: str, minimum: str | None) -> bool:
    return minimum is not None and SEVERITIES.index(severity) >= SEVERITIES.index(minimum)


# ----------------------------------------------------------------------------- état des derniers envois


def record_status(kind: str, ok: bool, detail: str) -> None:
    from datetime import UTC, datetime

    path = _cfg.STATE_DIR / "integrations-status.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data[kind] = {"ok": ok, "detail": detail[:300], "at": datetime.now(UTC).isoformat()}
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def statuses() -> dict:
    path = _cfg.STATE_DIR / "integrations-status.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
