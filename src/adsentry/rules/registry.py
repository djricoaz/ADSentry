"""Registre des fonctions de contrôle.

Chaque règle YAML référence une fonction par son nom (champ ``check``). Une fonction de
contrôle reçoit le Snapshot et les ``params`` de la règle, et retourne un ``CheckResult``
(vide si rien n'est trouvé). Elle ne doit JAMAIS faire d'appel réseau : tout vient du Snapshot.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..models import Snapshot


@dataclass
class CheckResult:
    affected: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.affected)


CheckFn = Callable[[Snapshot, dict[str, Any]], CheckResult]
CHECKS: dict[str, CheckFn] = {}


def check(name: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if name in CHECKS:
            raise ValueError(f"Contrôle déjà enregistré : {name}")
        CHECKS[name] = fn
        return fn

    return decorator


def load_all_checks() -> dict[str, CheckFn]:
    """Importe les modules de contrôles (l'import déclenche l'enregistrement)."""
    from .checks import adcs, anomalies, entra, privileged, stale, trusts  # noqa: F401

    return CHECKS
