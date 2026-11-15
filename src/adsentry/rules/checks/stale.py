"""Objets obsolètes : comptes, OS, mots de passe machines, DC, schéma, configuration héritée."""

from __future__ import annotations

import ipaddress
from datetime import datetime

from ... import constants as c
from ...models import Snapshot
from ..registry import CheckResult, check
from ._helpers import ds_heuristic, never_or_older, older_than  # noqa: F401

# Marqueurs d'OS en fin de support (au 2026-11). Windows 10 : fin de support le 14/10/2025 (hors LTSC/ESU).
OBSOLETE_OS_MARKERS = (
    "Windows NT",
    "Windows 2000",
    "Windows XP",
    "Windows Vista",
    "Windows 7",
    "Windows 8",
    "Server 2003",
    "Server 2008",
    "Server 2012",
    "Windows 10",
)
# Fin de support prochaine : (marqueur, date)
EOL_SOON = (("Server 2016", datetime(2027, 1, 12)), ("Windows 10 Enterprise LTSC 2021", datetime(2027, 1, 12)))


def _obsolete(os: str | None, build: int | None, params: dict) -> bool:
    if not os:
        return False
    if "Windows 10" in os and any(x in os for x in params.get("lts_exceptions", ["LTSC", "LTSB"])):
        return False
    if any(m in os for m in OBSOLETE_OS_MARKERS):
        return True
    if "Windows 11" in os and build is not None:
        table = params.get("win11_min_build", {"Enterprise": 26100, "Education": 26100, "default": 26200})
        edition = next((e for e in table if e != "default" and e in os), "default")
        return build < table[edition]
    return False


@check("stale_inactive_users")
def inactive_users(snap: Snapshot, params: dict) -> CheckResult:
    days = params.get("days", 180)
    return CheckResult(
        affected=[u.sam for u in snap.users if u.enabled and never_or_older(snap, u.last_logon, days)],
        details={"seuil_jours": days},
    )


@check("stale_inactive_computers")
def inactive_computers(snap: Snapshot, params: dict) -> CheckResult:
    days = params.get("days", 90)
    return CheckResult(
        affected=[
            cp.name
            for cp in snap.computers
            if cp.enabled and not cp.is_dc and never_or_older(snap, cp.last_logon, days)
        ]
    )


@check("stale_obsolete_os")
def obsolete_os(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for cp in snap.computers:
        if cp.enabled and not cp.is_dc and _obsolete(cp.os, cp.os_build, params):
            res.affected.append(cp.name)
            res.details[cp.name] = cp.os
    return res


@check("stale_obsolete_dc")
def obsolete_dc(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for cp in snap.dcs():
        if _obsolete(cp.os, cp.os_build, params):
            res.affected.append(cp.name)
            res.details[cp.name] = cp.os
    return res


@check("stale_os_eol_soon")
def os_eol_soon(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    horizon = params.get("days", 180)
    for cp in snap.computers:
        for marker, eol in EOL_SOON:
            if cp.enabled and cp.os and marker in cp.os:
                remaining = (eol.date() - snap.collected_at.date()).days
                if 0 <= remaining <= horizon:
                    res.affected.append(cp.name)
                    res.details[cp.name] = f"{cp.os} – fin de support le {eol:%d/%m/%Y}"
    return res


@check("stale_pwd_never_expires")
def pwd_never_expires(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in snap.users if u.enabled and u.password_never_expires])


@check("stale_pwd_not_required")
def pwd_not_required(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in snap.users if u.enabled and u.pwd_not_required])


@check("stale_no_laps")
def no_laps(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[cp.name for cp in snap.computers if cp.enabled and not cp.is_dc and not cp.laps])


@check("stale_recycle_bin")
def recycle_bin(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[snap.domain.name] if not snap.domain.recycle_bin else [])


@check("stale_functional_level")
def functional_level(snap: Snapshot, params: dict) -> CheckResult:
    minimum = params.get("min_level", 7)
    res = CheckResult()
    if snap.domain.functional_level < minimum:
        res.affected.append(f"domaine ({snap.domain.functional_level})")
    ffl = snap.domain.forest_functional_level
    if ffl is not None and ffl < minimum:
        res.affected.append(f"forêt ({ffl})")
    return res


@check("stale_primary_group")
def primary_group(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for u in snap.users:
        rid = snap.rid(u.sid)
        if u.enabled and u.primary_group_id not in (c.RID_DOMAIN_USERS, c.RID_DOMAIN_GUESTS) and rid != c.RID_GUEST:
            res.affected.append(u.sam)
            res.details[u.sam] = u.primary_group_id
    for cp in snap.computers:
        ok = (c.RID_DOMAIN_COMPUTERS, c.RID_DOMAIN_CONTROLLERS, c.RID_RODCS)
        if cp.enabled and cp.primary_group_id is not None and cp.primary_group_id not in ok:
            res.affected.append(cp.name)
            res.details[cp.name] = cp.primary_group_id
    return res


@check("stale_sid_history")
def sid_history(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in snap.users if u.sid_history] + [cp.name for cp in snap.computers if cp.sid_history]
    )


@check("stale_duplicate")
def duplicate(snap: Snapshot, params: dict) -> CheckResult:
    def dup(name: str, dn: str | None) -> bool:
        return name.upper().startswith("$DUPLICATE-") or "CNF:" in (dn or "")

    return CheckResult(
        affected=[u.sam for u in snap.users if dup(u.sam, u.dn)]
        + [cp.name for cp in snap.computers if dup(cp.name, cp.dn)]
    )


@check("stale_domain_migration")
def domain_migration(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in snap.users if u.sam.endswith("$$$")])


@check("stale_aes_not_enabled")
def aes_not_enabled(snap: Snapshot, params: dict) -> CheckResult:
    aes = c.ENC_AES128 | c.ENC_AES256
    return CheckResult(
        affected=[
            u.sam
            for u in snap.users
            if u.enabled and u.spns and u.supported_enc_types is not None and not u.supported_enc_types & aes
        ]
    )


@check("stale_computer_pwd_age")
def computer_pwd_age(snap: Snapshot, params: dict) -> CheckResult:
    low, high = params.get("min_days", 45), params.get("max_days")
    res = CheckResult()
    for cp in snap.computers:
        if not cp.enabled or cp.is_dc or cp.pwd_last_set is None or older_than(snap, cp.last_logon, 90):
            continue
        age = (snap.collected_at - cp.pwd_last_set).days
        if age > low and (high is None or age <= high):
            res.affected.append(cp.name)
            res.details[cp.name] = age
    return res


@check("stale_cluster_pwd")
def cluster_pwd(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            cp.name
            for cp in snap.computers
            if cp.enabled
            and any(s.lower().startswith("msclustervirtualserver/") for s in cp.spns)
            and older_than(snap, cp.pwd_last_set, params.get("days", 90))
        ]
    )


@check("stale_dc_pwd")
def dc_pwd(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[d.name for d in snap.dcs() if older_than(snap, d.pwd_last_set, params.get("days", 45))]
    )


@check("stale_dc_inactive")
def dc_inactive(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[d.name for d in snap.dcs() if older_than(snap, d.last_logon, params.get("days", 45))])


@check("stale_dc_not_updated")
def dc_not_updated(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[d.name for d in snap.dcs() if older_than(snap, d.last_update, params.get("days", 120))]
    )


@check("stale_dc_subnet_missing")
def dc_subnet_missing(snap: Snapshot, params: dict) -> CheckResult:
    nets = [ipaddress.ip_network(s, strict=False) for s in snap.domain.subnets]
    res = CheckResult()
    for d in snap.dcs():
        if d.ip and not any(ipaddress.ip_address(d.ip) in n for n in nets):
            res.affected.append(d.name)
            res.details[d.name] = d.ip
    return res


@check("stale_dc_registration")
def dc_registration(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for d in snap.dcs():
        if d.registration_issues:
            res.affected.append(d.name)
            res.details[d.name] = d.registration_issues
    return res


@check("stale_default_ou_changed")
def default_ou_changed(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for label, value, default in (
        ("utilisateurs", snap.domain.default_users_container, "CN=Users,"),
        ("ordinateurs", snap.domain.default_computers_container, "CN=Computers,"),
    ):
        if value and not value.upper().startswith(default.upper()):
            res.affected.append(f"{label} → {value}")
    return res


@check("stale_java_schema")
def java_schema(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=["schéma"] if snap.domain.java_schema else [])


@check("stale_schema_vuln_class")
def schema_vuln_class(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=list(snap.domain.vulnerable_schema_classes))


@check("stale_smb1")
def smb1(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[p.name for p in snap.dc_probes if p.smb1])


@check("stale_ms17_010")
def ms17_010(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[p.name for p in snap.dc_probes if p.ms17_010])


@check("stale_ms14_068")
def ms14_068(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[p.name for p in snap.dc_probes if p.ms14_068])
