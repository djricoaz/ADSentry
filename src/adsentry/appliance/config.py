"""Configuration de l'appliance : cibles à auditer, planification, secrets chiffrés.

/etc/adsentry/targets.yaml :

    targets:
      - name: corp
        schedule: "17 2 * * *"          # cron (minute heure jour mois jour_semaine), heure de l'appliance
        ai_analysis: true
        ad:
          domain: corp.local
          dc: 10.0.0.10
          username: svc-adsentry          # compte standard, sans privilège
          password_secret: corp-ad        # nom du secret (adsentry secret set corp-ad)
          ldaps: false
          sysvol: true
          probes: true
        entra:
          tenant_id: 00000000-0000-0000-0000-000000000000
          client_id: 00000000-0000-0000-0000-000000000000
          certificate: /etc/adsentry/certs/entra.pem   # clé privée + certificat (PEM)
          thumbprint: 0123456789ABCDEF...
          connect_version: 2.4.27.0      # facultatif (non exposé par Graph)
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel

CONFIG_DIR = Path(os.environ.get("ADSENTRY_CONFIG", "/etc/adsentry"))
STATE_DIR = Path(os.environ.get("ADSENTRY_STATE", "/var/lib/adsentry"))


class AdTarget(BaseModel):
    domain: str
    dc: str
    username: str
    password_secret: str
    ldaps: bool = False
    sysvol: bool = True
    probes: bool = True


class EntraTarget(BaseModel):
    tenant_id: str
    client_id: str
    certificate: str | None = None
    thumbprint: str | None = None
    client_secret_secret: str | None = None
    connect_version: str | None = None


class Target(BaseModel):
    name: str
    schedule: str = "17 2 * * *"
    ai_analysis: bool = False
    ad: AdTarget | None = None
    entra: EntraTarget | None = None


def load_targets(path: Path | None = None) -> list[Target]:
    path = path or CONFIG_DIR / "targets.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [Target.model_validate(t) for t in data.get("targets", [])]


# ----------------------------------------------------------------------------- secrets


class SecretStore:
    """Secrets chiffrés (Fernet/AES) ; la clé maître est un fichier 0400 lisible du seul service."""

    def __init__(self, key_path: Path | None = None, store_path: Path | None = None):
        self.key_path = key_path or CONFIG_DIR / "master.key"
        self.store_path = store_path or STATE_DIR / "secrets.json"

    def _fernet(self):
        from cryptography.fernet import Fernet

        if not self.key_path.exists():
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(Fernet.generate_key())
            self.key_path.chmod(0o400)
        return Fernet(self.key_path.read_bytes())

    def _load(self) -> dict:
        return json.loads(self.store_path.read_text()) if self.store_path.exists() else {}

    def set(self, name: str, value: str) -> None:
        data = self._load()
        data[name] = self._fernet().encrypt(value.encode()).decode()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(data))
        self.store_path.chmod(0o600)

    def get(self, name: str) -> str:
        data = self._load()
        if name not in data:
            raise KeyError(f"Secret inconnu : {name} (adsentry secret set {name})")
        return self._fernet().decrypt(data[name].encode()).decode()

    def names(self) -> list[str]:
        return sorted(self._load())


# ----------------------------------------------------------------------------- cron minimal


def _field_matches(expr: str, value: int, low: int, high: int) -> bool:
    for part in expr.split(","):
        step = 1
        if "/" in part:
            part, step_s = part.split("/")
            step = int(step_s)
        if part == "*":
            start, end = low, high
        elif "-" in part:
            start, end = map(int, part.split("-"))
        else:
            start = end = int(part)
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def cron_matches(expr: str, when: datetime) -> bool:
    minute, hour, dom, month, dow = expr.split()
    return (
        _field_matches(minute, when.minute, 0, 59)
        and _field_matches(hour, when.hour, 0, 23)
        and _field_matches(dom, when.day, 1, 31)
        and _field_matches(month, when.month, 1, 12)
        and _field_matches(dow, when.isoweekday() % 7, 0, 6)
    )
