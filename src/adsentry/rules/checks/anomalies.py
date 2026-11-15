"""Anomalies : Kerberos, comptes, dsHeuristics, GPO de sécurité, DNS, sondes réseau."""

from __future__ import annotations

import unicodedata

from ... import constants as c
from ...models import Snapshot
from ..registry import CheckResult, check
from ._helpers import (
    ds_heuristic,
    effective_gpos,
    gpo_sys_access,
    gpo_values,
    gpos_known,
    is_everyone_like,
    older_than,
)

LSA = r"machine\system\currentcontrolset\control\lsa"


# ----------------------------------------------------------------------------- comptes


@check("anom_asrep_roastable")
def asrep_roastable(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in snap.users if u.enabled and u.dont_require_preauth and not snap.user_is_privileged(u)]
    )


@check("anom_kerberoastable_users")
def kerberoastable_users(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            u.sam
            for u in snap.users
            if u.enabled and u.spns and not snap.user_is_privileged(u) and u.sam.lower() != "krbtgt"
        ]
    )


@check("anom_reversible_encryption")
def reversible_encryption(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in snap.users if u.enabled and u.reversible_encryption]
        + [cp.name for cp in snap.computers if cp.enabled and cp.reversible_encryption]
    )


@check("anom_des_enabled")
def des_enabled(snap: Snapshot, params: dict) -> CheckResult:
    des = c.ENC_DES_CBC_CRC | c.ENC_DES_CBC_MD5
    return CheckResult(
        affected=[u.sam for u in snap.users if u.enabled and (u.use_des_only or (u.supported_enc_types or 0) & des)]
    )


@check("anom_adminsdholder_orphans")
def adminsdholder_orphans(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            u.sam
            for u in snap.users
            if u.enabled
            and u.admin_count
            and not any(snap.is_tier0(g) for g in u.member_of)
            and snap.rid(u.sid) not in (c.RID_ADMINISTRATOR, c.RID_KRBTGT)
        ]
    )


@check("anom_guest_enabled")
def guest_enabled(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in snap.users if snap.rid(u.sid) == c.RID_GUEST and u.enabled])


@check("anom_unix_password")
def unix_password(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in snap.users if u.has_unix_password])


@check("anom_smartcard_old_pwd")
def smartcard_old_pwd(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            u.sam
            for u in snap.users
            if u.enabled and u.smartcard_required and older_than(snap, u.pwd_last_set, params.get("days", 365))
        ]
    )


@check("anom_smartcard_rotation")
def smartcard_rotation(snap: Snapshot, params: dict) -> CheckResult:
    if snap.domain.functional_level < 7 or snap.domain.smartcard_pwd_rotation is not False:
        return CheckResult()
    if not any(u.smartcard_required and u.enabled for u in snap.users):
        return CheckResult()
    return CheckResult(affected=["msDS-ExpirePasswordsOnSmartCardOnlyAccounts désactivé"])


@check("anom_spn_unicode")
def spn_unicode(snap: Snapshot, params: dict) -> CheckResult:
    def suspicious(s: str) -> bool:
        return any(unicodedata.category(ch) in ("Cf", "Cc", "Zs") or ord(ch) > 0x7E for ch in s)

    return CheckResult(
        affected=[
            o.sam if hasattr(o, "sam") else o.name
            for o in [*snap.users, *snap.computers]
            if any(suspicious(s) for s in o.spns)
        ]
    )


@check("anom_upn_sam_collision")
def upn_sam_collision(snap: Snapshot, params: dict) -> CheckResult:
    sams = {u.sam.lower(): u.sid for u in snap.users} | {cp.name.lower() + "$": cp.sid for cp in snap.computers}
    res = CheckResult()
    for u in snap.users:
        if u.upn:
            prefix = u.upn.split("@")[0].lower()
            other = sams.get(prefix)
            if other and other != u.sid:
                res.affected.append(u.sam)
                res.details[u.sam] = u.upn
    return res


@check("anom_dns_hostname_mismatch")
def dns_hostname_mismatch(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            cp.name
            for cp in snap.computers
            if cp.dns_hostname and cp.dns_hostname.split(".")[0].lower() != cp.name.lower()
        ]
    )


@check("anom_laps_joined_computers")
def laps_joined_computers(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[cp.name for cp in snap.computers if cp.enabled and cp.laps and cp.creator_sid])


# ----------------------------------------------------------------------------- domaine


@check("anom_machine_account_quota")
def machine_account_quota(snap: Snapshot, params: dict) -> CheckResult:
    q = snap.domain.machine_account_quota
    return (
        CheckResult(affected=[snap.domain.name], details={"ms-DS-MachineAccountQuota": q}) if q > 0 else CheckResult()
    )


@check("anom_protected_users_missing")
def protected_users_missing(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[snap.domain.name] if not snap.domain.protected_users_exists else [])


@check("anom_not_enough_dc")
def not_enough_dc(snap: Snapshot, params: dict) -> CheckResult:
    writable = [d.name for d in snap.dcs() if not d.is_rodc]
    return CheckResult(affected=writable or ["aucun DC"]) if len(writable) < params.get("min", 2) else CheckResult()


@check("anom_ntfrs_sysvol")
def ntfrs_sysvol(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=["SYSVOL"] if snap.domain.sysvol_replication == "ntfrs" else [])


@check("anom_backup")
def backup(snap: Snapshot, params: dict) -> CheckResult:
    last = snap.domain.last_backup
    if older_than(snap, last, params.get("days", 7)):
        return CheckResult(affected=[snap.domain.name], details={"derniere_sauvegarde": last.date().isoformat()})
    return CheckResult()


@check("anom_min_pwd_len")
def min_pwd_len(snap: Snapshot, params: dict) -> CheckResult:
    v = snap.domain.min_pwd_length
    return (
        CheckResult(affected=[f"longueur minimale = {v}"])
        if v is not None and v < params.get("min", 8)
        else CheckResult()
    )


@check("anom_no_service_policy")
def no_service_policy(snap: Snapshot, params: dict) -> CheckResult:
    if any(p.min_length >= params.get("min", 20) for p in snap.domain.psos):
        return CheckResult()
    return CheckResult(affected=["aucune PSO dédiée aux comptes de service"])


@check("anom_pre2k")
def pre2k(snap: Snapshot, params: dict) -> CheckResult:
    mode = params.get("mode", "anonymous")
    members = snap.domain.pre2k_compat_members
    if mode == "anonymous":
        hits = [s for s in members if s in (c.SID_ANONYMOUS, c.SID_EVERYONE)]
    elif mode == "authenticated_users":
        hits = [s for s in members if s == c.SID_AUTHENTICATED_USERS]
    else:
        hits = [s for s in members if s not in (c.SID_ANONYMOUS, c.SID_EVERYONE, c.SID_AUTHENTICATED_USERS)]
    return CheckResult(affected=[snap.principal_name(s) for s in hits])


@check("anom_dsheuristics")
def dsheuristics(snap: Snapshot, params: dict) -> CheckResult:
    pos, bad = params["position"], set(params["bad_values"])
    v = ds_heuristic(snap, pos)
    return CheckResult(affected=[f"dSHeuristics[{pos}] = {v}"]) if v in bad else CheckResult()


# ----------------------------------------------------------------------------- GPO de sécurité


def _gpo_eq(snap: Snapshot, key: str, bad: set, scope: str = "any") -> CheckResult:
    return CheckResult(affected=[g.name for g, v in gpo_values(snap, key, scope) if str(v) in bad])


def _gpo_missing(snap: Snapshot, key: str, good: set, scope: str, label: str) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    if any(str(v) in good for _, v in gpo_values(snap, key, scope)):
        return CheckResult()
    return CheckResult(affected=[label])


@check("anom_gpo_password_files")
def gpo_password_files(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[f for g in snap.gpos or [] for f in g.cpassword_files])


@check("anom_gpo_registry_bad")
def gpo_registry_bad(snap: Snapshot, params: dict) -> CheckResult:
    """Une GPO positionne une valeur dangereuse (params.key, params.bad, params.scope)."""
    return _gpo_eq(snap, params["key"], {str(b) for b in params["bad"]}, params.get("scope", "any"))


@check("anom_gpo_registry_missing")
def gpo_registry_missing(snap: Snapshot, params: dict) -> CheckResult:
    """Aucune GPO ne positionne la valeur sûre attendue (params.key, params.good, params.scope)."""
    return _gpo_missing(
        snap,
        params["key"],
        {str(g) for g in params["good"]},
        params.get("scope", "any"),
        params.get("label", params["key"]),
    )


@check("anom_gpo_ntlmv1")
def gpo_ntlmv1(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    values = gpo_values(snap, LSA + r"\lmcompatibilitylevel", "dcs")
    if not values:
        return CheckResult(affected=["LmCompatibilityLevel non défini pour les DC"])
    weak = [f"{g.name} = {v}" for g, v in values if int(v) < params.get("min", 5)]
    return CheckResult(affected=weak)


@check("anom_gpo_reversible")
def gpo_reversible(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[g.name for g, v in gpo_sys_access(snap, "ClearTextPassword") if v.strip() == "1"])


@check("anom_gpo_weak_pwd_policy")
def gpo_weak_pwd_policy(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            g.name
            for g, v in gpo_sys_access(snap, "MinimumPasswordLength")
            if not g.applies_to_domain and v.isdigit() and int(v) < params.get("min", 8)
        ]
    )


@check("anom_gpo_anonymous")
def gpo_anonymous(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for key, bad in (
        (LSA + r"\restrictanonymous", {"0"}),
        (LSA + r"\restrictanonymoussam", {"0"}),
        (LSA + r"\everyoneincludesanonymous", {"1"}),
    ):
        for g, v in gpo_values(snap, key):
            if str(v) in bad:
                res.affected.append(g.name)
                res.details.setdefault(g.name, []).append(key.rsplit("\\", 1)[1])
    for g, v in gpo_sys_access(snap, "LSAAnonymousNameLookup"):
        if v.strip() == "1":
            res.affected.append(g.name)
            res.details.setdefault(g.name, []).append("LSAAnonymousNameLookup")
    return res


@check("anom_gpo_membership_everyone")
def gpo_membership_everyone(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for g in effective_gpos(snap):
        for group, members in g.local_group_members.items():
            bad = [m for m in members if is_everyone_like(snap, m)]
            if bad:
                res.affected.append(g.name)
                res.details[g.name] = {group: bad}
    return res


@check("anom_gpo_audit_dc")
def gpo_audit_dc(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    configured: dict[str, int] = {}
    for g in effective_gpos(snap, "dcs"):
        configured.update(g.audit)
    missing = [s for s in params["subcategories"] if not configured.get(s, 0) & 1]
    return CheckResult(affected=missing)


@check("anom_gpo_hardened_paths")
def gpo_hardened_paths(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for g in effective_gpos(snap):
        for k, v in g.registry.items():
            if "\\hardenedpaths\\" in k and ("sysvol" in k or "netlogon" in k) and "=0" in str(v).replace(" ", ""):
                res.affected.append(g.name)
                res.details[g.name] = f"{k.rsplit(chr(92), 2)[-2:]} = {v}"
    return res


@check("anom_gpo_folder_options")
def gpo_folder_options(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    mapped = {}
    for g in effective_gpos(snap):
        mapped.update(g.folder_options)
    missing = [
        e
        for e in params.get("extensions", ["js", "jse", "vbs", "vbe", "wsf", "wsh", "hta"])
        if "notepad" not in mapped.get(e, "").lower()
    ]
    return CheckResult(affected=missing)


@check("anom_gpo_firewall_scripts")
def gpo_firewall_scripts(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    blocked = set()
    for g in effective_gpos(snap):
        for r in g.firewall_rules:
            if r.get("action", "").lower() == "block" and r.get("dir", "").lower() == "out":
                blocked.add(r.get("app", "").lower().rsplit("\\", 1)[-1])
    engines = params.get("engines", ["wscript.exe", "cscript.exe", "mshta.exe"])
    return CheckResult(affected=[e for e in engines if e not in blocked])


@check("anom_gpo_asr")
def gpo_asr(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    prefix = r"machine\software\policies\microsoft\windows defender\windows defender exploit guard\asr\rules"
    configured = {}
    for g in effective_gpos(snap):
        configured.update({k.rsplit("\\", 1)[1]: str(v) for k, v in g.registry.items() if k.startswith(prefix)})
    missing = [r for r in params["rules"] if configured.get(r.lower()) not in ("1", "6")]
    return CheckResult(affected=missing)


# ----------------------------------------------------------------------------- DNS


@check("anom_dns_zone")
def dns_zone(snap: Snapshot, params: dict) -> CheckResult:
    what = params["what"]
    res = CheckResult()
    for z in snap.dns_zones or []:
        if what == "update_critical" and z.critical and z.dynamic_update == "nonsecure_and_secure":
            res.affected.append(z.name)
        elif what == "update_other" and not z.critical and z.dynamic_update == "nonsecure_and_secure":
            res.affected.append(z.name)
        elif what == "transfer" and z.zone_transfer:
            res.affected.append(z.name)
        elif what == "au_create_child" and z.authenticated_users_create_child:
            res.affected.append(z.name)
    return res


# ----------------------------------------------------------------------------- sondes réseau


@check("anom_probe")
def probe(snap: Snapshot, params: dict) -> CheckResult:
    """Sonde DC : params.field et params.bad (valeur qui déclenche)."""
    field, bad = params["field"], params.get("bad", True)
    res = CheckResult()
    for p in snap.dc_probes:
        value = getattr(p, field)
        if value is None:
            continue
        if isinstance(value, list):
            hit = [v for v in value if v in params.get("bad_items", value)]
            if hit:
                res.affected.append(p.name)
                res.details[p.name] = hit
        elif value == bad:
            res.affected.append(p.name)
    return res


@check("anom_tls_probe")
def tls_probe(snap: Snapshot, params: dict) -> CheckResult:
    bad = set(params["bad_protocols"])
    res = CheckResult()
    for t in snap.tls_probes:
        if t.service == params["service"] and bad & set(t.protocols):
            res.affected.append(f"{t.host}:{t.port}")
            res.details[f"{t.host}:{t.port}"] = sorted(bad & set(t.protocols))
    return res


@check("anom_gpo_registry_prefix")
def gpo_registry_prefix(snap: Snapshot, params: dict) -> CheckResult:
    """Une GPO positionne une valeur texte commençant par params.prefix (ex: http://)."""
    prefix = params["prefix"].lower()
    return CheckResult(
        affected=[
            f"{g.name}: {v}"
            for g, v in gpo_values(snap, params["key"], params.get("scope", "any"))
            if str(v).lower().startswith(prefix)
        ]
    )
