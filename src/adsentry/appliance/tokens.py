"""Jetons d'API pour les automatisations (SIEM qui interroge l'API, scripts, Swagger).

Un jeton porte un rôle (viewer ou admin), n'est affiché qu'une fois à sa création et n'est conservé que sous forme
d'empreinte SHA-256. En-tête : « Authorization: Bearer ads_… ».
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta

from . import config as _cfg
from .auth import Role

PREFIX = "ads_"
_lock = threading.Lock()


def _path():
    return _cfg.STATE_DIR / "api-tokens.json"


def _load() -> list[dict]:
    path = _path()
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def _save(items: list[dict]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, path)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def public(t: dict) -> dict:
    return {k: v for k, v in t.items() if k != "digest"}


def create(name: str, role: Role, created_by: str, days: int | None = None) -> tuple[dict, str]:
    name = name.strip()
    if not re.fullmatch(r"[\w .\-À-ÿ]{2,60}", name):
        raise ValueError("Nom de jeton invalide (2 à 60 caractères)")
    token = PREFIX + secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    item = {
        "id": secrets.token_hex(6),
        "name": name,
        "role": role.value,
        "created_by": created_by,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat() if days else None,
        "last_used": None,
        "prefix": token[:10],
        "digest": _digest(token),
    }
    with _lock:
        _save([*_load(), item])
    return public(item), token


def list_tokens() -> list[dict]:
    return [public(t) for t in _load()]


def revoke(token_id: str) -> bool:
    with _lock:
        items = _load()
        kept = [t for t in items if t["id"] != token_id]
        _save(kept)
        return len(kept) != len(items)


def resolve(token: str) -> dict | None:
    """Jeton valide → {name, role} ; met à jour la date de dernière utilisation."""
    if not token.startswith(PREFIX):
        return None
    d = _digest(token)
    now = datetime.now(UTC)
    with _lock:
        items = _load()
        for t in items:
            if hmac.compare_digest(t["digest"], d):
                if t["expires_at"] and t["expires_at"] < now.isoformat():
                    return None
                t["last_used"] = now.isoformat()
                _save(items)
                return public(t)
    return None
