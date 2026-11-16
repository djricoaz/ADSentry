"""Comptes de la console web : rôles, mots de passe, sessions, limitation des tentatives.

- Deux rôles : « admin » (cibles, secrets, scans, comptes) et « viewer » (consultation des évaluations).
- Mots de passe hachés avec scrypt (bibliothèque standard), jamais stockés ni journalisés en clair.
- Sessions côté serveur : jeton aléatoire dans un cookie HttpOnly ; seul son empreinte SHA-256 est conservée.
- Premier démarrage : tant qu'aucun compte n'existe, un jeton d'installation à usage unique est écrit dans
  STATE_DIR/setup-token (0600) et dans le journal du service ; il est exigé pour créer le premier administrateur.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from .config import STATE_DIR

MIN_PASSWORD = 12
SESSION_TTL = 8 * 3600  # 8 h d'inactivité maximum
LOCK_AFTER = 5  # échecs consécutifs
LOCK_SECONDS = 15 * 60
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,64}$")


class Role(StrEnum):
    admin = "admin"
    viewer = "viewer"


ROLE_LABELS = {Role.admin: "Administrateur", Role.viewer: "Lecteur"}


class User(BaseModel):
    username: str
    role: Role
    display_name: str = ""
    password_hash: str
    created_at: datetime
    last_login: datetime | None = None
    disabled: bool = False

    def public(self) -> dict:
        return {
            "username": self.username,
            "role": self.role.value,
            "role_label": ROLE_LABELS[self.role],
            "display_name": self.display_name or self.username,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "disabled": self.disabled,
        }


class AuthError(Exception):
    """Erreur présentable à l'utilisateur (message en français)."""


# ----------------------------------------------------------------------------- mots de passe

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), dk)
    except (ValueError, TypeError):
        return False


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"Mot de passe trop court ({MIN_PASSWORD} caractères minimum)")
    if username and username.lower() in password.lower():
        raise AuthError("Le mot de passe ne doit pas contenir l'identifiant")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z\d]"))
    if classes < 3:
        raise AuthError(
            "Le mot de passe doit mêler au moins 3 types de caractères (minuscules, majuscules, chiffres, symboles)"
        )


# ----------------------------------------------------------------------------- stockage


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(mode)
    os.replace(tmp, path)


class UserStore:
    def __init__(self, path: Path | None = None):
        self.path = path or STATE_DIR / "users.json"
        self._lock = threading.Lock()

    def _load(self) -> dict[str, User]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return {u["username"].lower(): User.model_validate(u) for u in raw.get("users", [])}

    def _save(self, users: dict[str, User]) -> None:
        data = {"users": [u.model_dump(mode="json") for u in users.values()]}
        _atomic_write(self.path, json.dumps(data, indent=1, ensure_ascii=False))

    def list(self) -> list[User]:
        return sorted(self._load().values(), key=lambda u: u.username.lower())

    def get(self, username: str) -> User | None:
        return self._load().get(username.lower())

    def count(self) -> int:
        return len(self._load())

    def _admins(self, users: dict[str, User]) -> int:
        return sum(1 for u in users.values() if u.role == Role.admin and not u.disabled)

    def create(self, username: str, password: str, role: Role, display_name: str = "") -> User:
        if not USERNAME_RE.match(username):
            raise AuthError("Identifiant invalide (2 à 64 caractères : lettres, chiffres, . _ -)")
        check_password_policy(password, username)
        with self._lock:
            users = self._load()
            if username.lower() in users:
                raise AuthError("Ce compte existe déjà")
            user = User(
                username=username,
                role=role,
                display_name=display_name.strip()[:80],
                password_hash=hash_password(password),
                created_at=datetime.now(UTC),
            )
            users[username.lower()] = user
            self._save(users)
            return user

    def update(
        self,
        username: str,
        *,
        role: Role | None = None,
        display_name: str | None = None,
        password: str | None = None,
        disabled: bool | None = None,
    ) -> User:
        with self._lock:
            users = self._load()
            user = users.get(username.lower())
            if user is None:
                raise AuthError("Compte introuvable")
            if role is not None:
                user.role = role
            if display_name is not None:
                user.display_name = display_name.strip()[:80]
            if disabled is not None:
                user.disabled = disabled
            if password is not None:
                check_password_policy(password, user.username)
                user.password_hash = hash_password(password)
            if self._admins(users) == 0:
                raise AuthError("Il doit rester au moins un administrateur actif")
            self._save(users)
            return user

    def delete(self, username: str) -> None:
        with self._lock:
            users = self._load()
            if users.pop(username.lower(), None) is None:
                raise AuthError("Compte introuvable")
            if self._admins(users) == 0:
                raise AuthError("Impossible de supprimer le dernier administrateur")
            self._save(users)

    def authenticate(self, username: str, password: str) -> User | None:
        user = self.get(username)
        if user is None:
            verify_password(password, _DUMMY_HASH)  # temps constant : ne révèle pas l'existence du compte
            return None
        if user.disabled or not verify_password(password, user.password_hash):
            return None
        with self._lock:
            users = self._load()
            user = users[username.lower()]
            user.last_login = datetime.now(UTC)
            self._save(users)
        return user


_DUMMY_HASH = hash_password(secrets.token_hex(8))


# ----------------------------------------------------------------------------- sessions


class SessionStore:
    """Sessions en mémoire (un seul processus API). Un redémarrage de l'API déconnecte tout le monde."""

    def __init__(self, ttl: int = SESSION_TTL):
        self.ttl = ttl
        self._s: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._s[self._key(token)] = (username.lower(), time.monotonic())
        return token

    def resolve(self, token: str | None) -> str | None:
        if not token:
            return None
        key, now = self._key(token), time.monotonic()
        with self._lock:
            entry = self._s.get(key)
            if entry is None:
                return None
            if now - entry[1] > self.ttl:
                del self._s[key]
                return None
            self._s[key] = (entry[0], now)
            return entry[0]

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._s.pop(self._key(token), None)

    def revoke_user(self, username: str, keep: str | None = None) -> None:
        keep_key = self._key(keep) if keep else None
        with self._lock:
            for k in [k for k, (u, _) in self._s.items() if u == username.lower() and k != keep_key]:
                del self._s[k]


class LoginThrottle:
    """Verrouillage temporaire après LOCK_AFTER échecs pour un même identifiant ou une même adresse."""

    def __init__(self):
        self._fails: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def locked(self, *keys: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return any((e := self._fails.get(k)) and e[0] >= LOCK_AFTER and now - e[1] < LOCK_SECONDS for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for k in keys:
                n, last = self._fails.get(k, (0, now))
                if now - last > LOCK_SECONDS:
                    n = 0
                self._fails[k] = (n + 1, now)

    def success(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)


# ----------------------------------------------------------------------------- premier démarrage


def setup_token_path() -> Path:
    return STATE_DIR / "setup-token"


def ensure_setup_token() -> str:
    """Crée (ou relit) le jeton d'installation à usage unique."""
    path = setup_token_path()
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(18)
    _atomic_write(path, token + "\n")
    return token


def check_setup_token(candidate: str) -> bool:
    path = setup_token_path()
    if not path.exists() or not candidate.strip():
        return False
    return hmac.compare_digest(path.read_text(encoding="utf-8").strip(), candidate.strip())


# ----------------------------------------------------------------------------- journal d'audit


def audit(event: str, user: str | None, **details) -> None:
    """Journal des actions de la console (JSON par ligne). Ne jamais y passer de secret."""
    line = {"at": datetime.now(UTC).isoformat(), "event": event, "user": user, **details}
    path = STATE_DIR / "audit.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, ensure_ascii=False) + "\n")


def read_audit(limit: int = 200) -> list[dict]:
    path = STATE_DIR / "audit.log"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(x) for x in reversed(lines) if x.strip()]
