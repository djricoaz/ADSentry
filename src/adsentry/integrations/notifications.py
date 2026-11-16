"""Centre de notifications de la console (cloche) : scans terminés ou en échec, nouveaux constats graves,
tickets créés, intégrations en erreur. Un marqueur de lecture par utilisateur."""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import UTC, datetime

from ..appliance import config as _cfg

MAX_ITEMS = 300
_lock = threading.Lock()


def _path():
    return _cfg.STATE_DIR / "notifications.json"


def _read() -> list[dict]:
    path = _path()
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def add(title: str, body: str = "", level: str = "info", link: str | None = None, audience: str = "all") -> dict:
    """level : info | success | warning | critical ; audience : all | admin."""
    item = {
        "id": secrets.token_hex(6),
        "at": datetime.now(UTC).isoformat(),
        "level": level,
        "title": title[:200],
        "body": body[:1000],
        "link": link,
        "audience": audience,
    }
    with _lock:
        items = [item, *_read()][:MAX_ITEMS]
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    return item


def _markers() -> dict:
    path = _cfg.STATE_DIR / "notifications-read.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def for_user(username: str, is_admin: bool, limit: int = 50) -> dict:
    seen = _markers().get(username.lower(), "")
    items = [i for i in _read() if i["audience"] == "all" or is_admin][:limit]
    return {
        "items": [{**i, "unread": i["at"] > seen} for i in items],
        "unread": sum(1 for i in items if i["at"] > seen),
    }


def mark_read(username: str) -> None:
    with _lock:
        data = _markers()
        data[username.lower()] = datetime.now(UTC).isoformat()
        path = _cfg.STATE_DIR / "notifications-read.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
