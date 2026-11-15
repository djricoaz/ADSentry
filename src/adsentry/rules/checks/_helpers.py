"""Fonctions utilitaires partagées par les contrôles (GPO, dates, principaux « tout le monde »)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

from ... import constants as c
from ...models import Gpo, Snapshot

EVERYONE_NAMES = {
    "everyone",
    "tout le monde",
    "authenticated users",
    "utilisateurs authentifiés",
    "domain users",
    "utilisateurs du domaine",
    "domain computers",
    "ordinateurs du domaine",
    "users",
    "utilisateurs",
    "anonymous logon",
    "ouverture de session anonyme",
    "guests",
    "invités",
}


def older_than(snap: Snapshot, when: datetime | None, days: int) -> bool:
    """True si la date est connue et plus ancienne que ``days`` jours (None = inconnu = False)."""
    return when is not None and when < snap.collected_at - timedelta(days=days)


def never_or_older(snap: Snapshot, when: datetime | None, days: int) -> bool:
    return when is None or when < snap.collected_at - timedelta(days=days)


def is_everyone_like(snap: Snapshot, principal: str) -> bool:
    """SID ou nom (les GPO contiennent parfois des noms) d'un groupe très large."""
    if principal.startswith("S-1-"):
        return snap.is_low_privileged(principal)
    return principal.split("\\")[-1].strip().lower() in EVERYONE_NAMES


def effective_gpos(snap: Snapshot, scope: str = "any") -> list[Gpo]:
    gpos = [g for g in (snap.gpos or []) if g.is_effective]
    if scope == "dcs":
        return [g for g in gpos if g.applies_to_dcs or g.applies_to_domain]
    if scope == "domain":
        return [g for g in gpos if g.applies_to_domain]
    if scope == "non_dc":
        return [g for g in gpos if not g.applies_to_dcs]
    return gpos


def gpo_values(snap: Snapshot, key: str, scope: str = "any") -> list[tuple[Gpo, Any]]:
    key = key.lower()
    return [(g, g.registry[key]) for g in effective_gpos(snap, scope) if key in g.registry]


def gpo_sys_access(snap: Snapshot, name: str, scope: str = "any") -> list[tuple[Gpo, str]]:
    return [
        (g, g.security["System Access"][name])
        for g in effective_gpos(snap, scope)
        if name in g.security.get("System Access", {})
    ]


def gpo_privilege(snap: Snapshot, privilege: str, scope: str = "any") -> list[tuple[Gpo, list[str]]]:
    from ...collectors.gpo_parsers import sids_from_privilege

    out = []
    for g in effective_gpos(snap, scope):
        raw = g.security.get("Privilege Rights", {}).get(privilege)
        if raw is not None:
            out.append((g, sids_from_privilege(raw)))
    return out


def gpos_known(snap: Snapshot) -> bool:
    return snap.gpos is not None


def ds_heuristic(snap: Snapshot, position: int) -> str | None:
    """Caractère à la position (1-based) de dSHeuristics, None si absent."""
    value = snap.domain.ds_heuristics if snap.domain else None
    if not value or len(value) < position:
        return None
    return value[position - 1]


def unc_host(path: str) -> str | None:
    p = path.replace("/", "\\")
    if not p.startswith("\\\\"):
        return None
    return p[2:].split("\\", 1)[0].lower()


def in_domain(snap: Snapshot, host: str) -> bool:
    dom = snap.domain.name.lower() if snap.domain else ""
    netbios = (snap.domain.netbios or "").lower() if snap.domain else ""
    names = {cp.name.lower() for cp in snap.computers} | {(cp.dns_hostname or "").lower() for cp in snap.computers}
    return host in (dom, netbios) or host.endswith("." + dom) or host in names


def names(snap: Snapshot, sids: Iterable[str]) -> list[str]:
    return [snap.principal_name(s) for s in sids]


def tier0_group_sids(snap: Snapshot) -> set[str]:
    d = snap.domain.sid if snap.domain else ""
    return {
        c.SID_BUILTIN_ADMINS,
        f"{d}-{c.RID_DOMAIN_ADMINS}",
        f"{d}-{c.RID_ENTERPRISE_ADMINS}",
        f"{d}-{c.RID_SCHEMA_ADMINS}",
        *c.OPERATOR_GROUPS,
    }
