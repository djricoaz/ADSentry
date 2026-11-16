"""Configuration de l'appliance : cibles à auditer, planification, secrets chiffrés.

Les cibles sont gérées depuis la console web (administrateur) et enregistrées dans
/var/lib/adsentry/targets.yaml ; à défaut, /etc/adsentry/targets.yaml (fichier historique) est lu.
Format :

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
          # ou certificate_secret: corp-entra-cert  (PEM importé depuis la console, chiffré)
          connect_version: 2.4.27.0      # facultatif (non exposé par Graph)
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator


def _default_state() -> Path:
    appliance = Path("/var/lib/adsentry")
    if appliance.is_dir() and os.access(appliance, os.W_OK):
        return appliance
    return Path.home() / ".local/share/adsentry"  # installation hors appliance (développement, poste Linux)


CONFIG_DIR = Path(os.environ.get("ADSENTRY_CONFIG", "/etc/adsentry"))
STATE_DIR = Path(os.environ.get("ADSENTRY_STATE") or _default_state())
DATA_DIR = Path(os.environ.get("ADSENTRY_DATA") or STATE_DIR / "scans")


class AdTarget(BaseModel):
    domain: str
    dc: str
    username: str
    password_secret: str
    ldaps: bool = False
    sysvol: bool = True
    probes: bool = True

    @field_validator("username")
    @classmethod
    def _bare_account(cls, v: str) -> str:
        """Accepte « DOMAINE\\compte », « compte@domaine.local » ou « compte » ; conserve le seul nom du compte.

        Les collecteurs ajoutent eux-mêmes le domaine de la cible (NTLM « domaine\\compte », SMB compte + domaine) :
        un préfixe saisi par l'utilisateur produirait « domaine\\DOMAINE\\compte », refusé à l'authentification.
        """
        v = v.strip()
        if "\\" in v:
            v = v.rsplit("\\", 1)[1]
        elif "@" in v:
            v = v.split("@", 1)[0]
        if not v:
            raise ValueError("Compte d'audit vide")
        return v


class EntraTarget(BaseModel):
    tenant_id: str
    client_id: str
    certificate: str | None = None
    certificate_secret: str | None = None  # PEM (clé privée + certificat) chiffré dans le SecretStore
    thumbprint: str | None = None
    client_secret_secret: str | None = None
    connect_version: str | None = None


TARGET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


class Target(BaseModel):
    name: str
    schedule: str | None = "17 2 * * *"  # None ou "" : lancement manuel uniquement
    ai_analysis: bool = False
    ad: AdTarget | None = None
    entra: EntraTarget | None = None

    @field_validator("schedule")
    @classmethod
    def _valid_cron(cls, v: str | None) -> str | None:
        if not v or not v.strip():
            return None
        validate_cron(v)
        return " ".join(v.split())


def targets_path() -> Path:
    """Fichier modifiable par la console ; repli sur l'ancien emplacement en lecture seule."""
    writable = STATE_DIR / "targets.yaml"
    legacy = CONFIG_DIR / "targets.yaml"
    return writable if writable.exists() or not legacy.exists() else legacy


def load_targets(path: Path | None = None) -> list[Target]:
    path = path or targets_path()
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [Target.model_validate(t) for t in data.get("targets", [])]


def save_targets(targets: list[Target], path: Path | None = None) -> Path:
    path = path or STATE_DIR / "targets.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"targets": [t.model_dump(mode="json", exclude_none=True) for t in targets]}
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    tmp.chmod(0o640)
    os.replace(tmp, path)
    return path


# ----------------------------------------------------------------------------- secrets


class SecretStore:
    """Secrets chiffrés (Fernet/AES) ; la clé maître est un fichier 0400 lisible du seul service."""

    def __init__(self, key_path: Path | None = None, store_path: Path | None = None):
        # Appliance : clé créée par adsentry-setup dans /etc/adsentry ; ailleurs : à côté des données.
        self.key_path = key_path or next(
            (p for p in (CONFIG_DIR / "master.key", STATE_DIR / "master.key") if p.exists()),
            CONFIG_DIR / "master.key" if os.access(CONFIG_DIR, os.W_OK) else STATE_DIR / "master.key",
        )
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

    def has(self, name: str) -> bool:
        return name in self._load()

    def delete(self, name: str) -> None:
        data = self._load()
        if data.pop(name, None) is not None:
            self.store_path.write_text(json.dumps(data))


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


_CRON_BOUNDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


def validate_cron(expr: str) -> None:
    """Lève ValueError si l'expression n'est pas un cron à 5 champs pris en charge."""
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError("Planification invalide : 5 champs attendus (minute heure jour mois jour_semaine)")
    for f, (low, high) in zip(fields, _CRON_BOUNDS, strict=True):
        for part in f.split(","):
            base, _, step = part.partition("/")
            if step and (not step.isdigit() or int(step) == 0):
                raise ValueError(f"Planification invalide : pas « {step} »")
            if base == "*":
                continue
            bounds = base.split("-")
            if len(bounds) > 2 or not all(b.isdigit() and low <= int(b) <= high for b in bounds):
                raise ValueError(f"Planification invalide : « {part} » hors de [{low}-{high}]")


def cron_matches(expr: str, when: datetime) -> bool:
    minute, hour, dom, month, dow = expr.split()
    return (
        _field_matches(minute, when.minute, 0, 59)
        and _field_matches(hour, when.hour, 0, 23)
        and _field_matches(dom, when.day, 1, 31)
        and _field_matches(month, when.month, 1, 12)
        and _field_matches(dow, when.isoweekday() % 7, 0, 6)
    )
