"""Comptes à privilèges : Kerberos, délégations, DCSync, groupes sensibles, ACL, RODC, GPO de droits."""

from __future__ import annotations

from collections import deque

from ... import constants as c
from ...models import Snapshot
from ..registry import CheckResult, check
from ._helpers import (
    gpo_privilege,
    gpo_values,
    gpos_known,
    is_everyone_like,
    names,
    never_or_older,
    older_than,
    tier0_group_sids,
)

DCSYNC_RIGHTS = {"DS-Replication-Get-Changes-All", "GenericAll", c.GUID_DS_REPLICATION_GET_CHANGES_ALL}
WRITE_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owner",
    "WriteProperty",
    "AllExtendedRights",
    "AddMember",
    "User-Force-Change-Password",
    "CreateChild",
}
EXCHANGE_GROUPS = {"exchange windows permissions", "exchange trusted subsystem", "organization management"}


def _privileged_users(snap: Snapshot):
    return [u for u in snap.users if u.enabled and snap.user_is_privileged(u)]


# ----------------------------------------------------------------------------- comptes admins


@check("priv_admin_kerberoastable")
def admin_kerberoastable(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in _privileged_users(snap) if u.spns])


@check("priv_admin_no_preauth")
def admin_no_preauth(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in _privileged_users(snap) if u.dont_require_preauth])


@check("priv_admin_delegatable")
def admin_delegatable(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in _privileged_users(snap) if not u.sensitive_no_delegation and not u.in_protected_users]
    )


@check("priv_admin_not_protected_users")
def admin_not_protected_users(snap: Snapshot, params: dict) -> CheckResult:
    if not snap.domain.protected_users_exists:
        return CheckResult()
    return CheckResult(
        affected=[
            u.sam
            for u in _privileged_users(snap)
            if not u.in_protected_users and snap.rid(u.sid) != c.RID_ADMINISTRATOR
        ]
    )


@check("priv_too_many_admins")
def too_many_admins(snap: Snapshot, params: dict) -> CheckResult:
    maximum = params.get("max", 10)
    admins = [u.sam for u in _privileged_users(snap) if any(g in tier0_group_sids(snap) for g in u.member_of)]
    return (
        CheckResult(affected=admins, details={"nombre": len(admins), "maximum": maximum})
        if len(admins) > maximum
        else CheckResult()
    )


@check("priv_admin_login")
def admin_login(snap: Snapshot, params: dict) -> CheckResult:
    days = params.get("days", 35)
    return CheckResult(
        affected=[
            u.sam
            for u in snap.users
            if snap.rid(u.sid) == c.RID_ADMINISTRATOR and u.last_logon and not older_than(snap, u.last_logon, days)
        ]
    )


@check("priv_admin_inactive")
def admin_inactive(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in _privileged_users(snap) if never_or_older(snap, u.last_logon, params.get("days", 180))]
    )


@check("priv_admin_pwd_old")
def admin_pwd_old(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[u.sam for u in _privileged_users(snap) if older_than(snap, u.pwd_last_set, params.get("days", 1095))]
    )


@check("priv_service_domain_admin")
def service_domain_admin(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in _privileged_users(snap) if u.password_never_expires])


@check("priv_admin_email")
def admin_email(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[u.sam for u in _privileged_users(snap) if u.mail])


@check("priv_fake_pwd_change")
def fake_pwd_change(snap: Snapshot, params: dict) -> CheckResult:
    only_admins = params.get("privileged_only", False)
    res = CheckResult()
    for u in snap.users:
        if not u.enabled or (only_admins and not snap.user_is_privileged(u)):
            continue
        if not only_admins and snap.user_is_privileged(u):
            continue  # couvert par la règle dédiée aux admins
        if u.pwd_last_set and u.unicode_pwd_last_change and (u.pwd_last_set - u.unicode_pwd_last_change).days > 1:
            res.affected.append(u.sam)
    return res


# ----------------------------------------------------------------------------- groupes


@check("priv_schema_admins_not_empty")
def schema_admins_not_empty(snap: Snapshot, params: dict) -> CheckResult:
    g = snap.group(f"{snap.domain.sid}-{c.RID_SCHEMA_ADMINS}")
    return CheckResult(affected=names(snap, g.members) if g else [])


@check("priv_operators_not_empty")
def operators_not_empty(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for sid in c.OPERATOR_GROUPS:
        g = snap.group(sid)
        if g and g.members:
            res.affected.append(g.name)
            res.details[g.name] = names(snap, g.members)
    return res


@check("priv_dnsadmins_not_empty")
def dnsadmins_not_empty(snap: Snapshot, params: dict) -> CheckResult:
    g = next((g for g in snap.groups if g.name.lower() == "dnsadmins"), None)
    return CheckResult(affected=names(snap, g.members) if g else [])


@check("priv_krbtgt_old")
def krbtgt_old(snap: Snapshot, params: dict) -> CheckResult:
    last = snap.domain.krbtgt_pwd_last_set
    if older_than(snap, last, params.get("days", 180)):
        return CheckResult(affected=["krbtgt"], details={"age_jours": (snap.collected_at - last).days})
    return CheckResult()


# ----------------------------------------------------------------------------- délégations


@check("priv_unconstrained_delegation")
def unconstrained_delegation(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    res.affected += [cp.name for cp in snap.computers if cp.enabled and cp.trusted_for_delegation and not cp.is_dc]
    res.affected += [u.sam for u in snap.users if u.enabled and u.trusted_for_delegation]
    return res


@check("priv_rbcd_on_dc")
def rbcd_on_dc(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for cp in snap.dcs():
        if cp.rbcd_principals:
            res.affected.append(cp.name)
            res.details[cp.name] = names(snap, cp.rbcd_principals)
    return res


@check("priv_dc_constrained_delegation")
def dc_constrained_delegation(snap: Snapshot, params: dict) -> CheckResult:
    transition = params.get("protocol_transition", False)
    return CheckResult(
        affected=[d.name for d in snap.dcs() if d.allowed_to_delegate_to and d.protocol_transition == transition]
    )


@check("priv_delegation_krbtgt")
def delegation_krbtgt(snap: Snapshot, params: dict) -> CheckResult:
    objs = [(u.sam, u.allowed_to_delegate_to) for u in snap.users] + [
        (cp.name, cp.allowed_to_delegate_to) for cp in snap.computers
    ]
    return CheckResult(affected=[n for n, targets in objs if any(t.lower().startswith("krbtgt/") for t in targets)])


@check("priv_unknown_delegation")
def unknown_delegation(snap: Snapshot, params: dict) -> CheckResult:
    known = {cp.name.lower() for cp in snap.computers} | {(cp.dns_hostname or "").lower() for cp in snap.computers}
    for obj in [*snap.users, *snap.computers]:
        known |= {s.split("/")[1].split(":")[0].lower() for s in obj.spns if "/" in s}
    res = CheckResult()
    for name, targets in [(u.sam, u.allowed_to_delegate_to) for u in snap.users] + [
        (cp.name, cp.allowed_to_delegate_to) for cp in snap.computers
    ]:
        missing = [t for t in targets if "/" in t and t.split("/")[1].split(":")[0].lower() not in known]
        if missing:
            res.affected.append(name)
            res.details[name] = missing
    return res


# ----------------------------------------------------------------------------- ACL


def _edges(snap: Snapshot, target_types: set[str], rights: set[str] | None = None):
    for e in snap.acl_edges:
        if e.target_type in target_types and (rights is None or e.right in rights):
            yield e


@check("priv_dcsync_non_dc")
def dcsync_non_dc(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"domain"}, DCSYNC_RIGHTS):
        if not snap.is_tier0(e.principal_sid):
            name = snap.principal_name(e.principal_sid)
            res.affected.append(name)
            res.details[name] = e.right
    return res


@check("priv_delegation_everyone")
def delegation_everyone(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"domain", "ou", "container"}, WRITE_RIGHTS):
        if snap.is_low_privileged(e.principal_sid):
            res.affected.append(e.target)
            res.details.setdefault(e.target, []).append(f"{snap.principal_name(e.principal_sid)}: {e.right}")
    return res


@check("priv_dangerous_extended_right")
def dangerous_extended_right(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"domain", "ou"}, {"AllExtendedRights", "User-Force-Change-Password"}):
        if not snap.is_tier0(e.principal_sid) and not snap.is_low_privileged(e.principal_sid):
            res.affected.append(e.target)
            res.details.setdefault(e.target, []).append(f"{snap.principal_name(e.principal_sid)}: {e.right}")
    return res


@check("priv_dns_delegation")
def dns_delegation(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"dns"}, WRITE_RIGHTS):
        if not snap.is_tier0(e.principal_sid):
            res.affected.append(snap.principal_name(e.principal_sid))
    return res


@check("priv_exchange_privesc")
def exchange_privesc(snap: Snapshot, params: dict) -> CheckResult:
    target = params.get("target_type", "domain")
    res = CheckResult()
    for e in _edges(snap, {target}, {"WriteDacl", "GenericAll", "WriteOwner", "GenericWrite"}):
        if snap.principal_name(e.principal_sid).lower() in EXCHANGE_GROUPS:
            res.affected.append(snap.principal_name(e.principal_sid))
    return res


@check("priv_adminsdholder_backdoor")
def adminsdholder_backdoor(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"adminsdholder"}, WRITE_RIGHTS):
        n = snap.principal_name(e.principal_sid)
        if not snap.is_tier0(e.principal_sid) and n.lower() not in EXCHANGE_GROUPS:
            res.affected.append(n)
            res.details[n] = e.right
    return res


@check("priv_key_admins_delegation")
def key_admins_delegation(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for e in _edges(snap, {"domain"}, {"GenericAll", "WriteProperty"}):
        if snap.rid(e.principal_sid) in (c.RID_KEY_ADMINS, c.RID_ENTERPRISE_KEY_ADMINS):
            res.affected.append(snap.principal_name(e.principal_sid))
    return res


@check("priv_dc_owner")
def dc_owner(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for d in snap.dcs():
        if d.owner_sid and not snap.is_tier0(d.owner_sid):
            res.affected.append(d.name)
            res.details[d.name] = snap.principal_name(d.owner_sid)
    return res


@check("priv_bad_successor")
def bad_successor(snap: Snapshot, params: dict) -> CheckResult:
    has_2025 = any((d.os_build or 0) >= 26100 or "2025" in (d.os or "") for d in snap.dcs())
    if not has_2025:
        return CheckResult()
    res = CheckResult()
    for e in _edges(snap, {"ou", "container", "domain"}, {"CreateChild-dMSA", "CreateChild", "GenericAll"}):
        if not snap.is_tier0(e.principal_sid):
            res.affected.append(f"{e.target} ({snap.principal_name(e.principal_sid)})")
    return res


@check("priv_control_path")
def control_path(snap: Snapshot, params: dict) -> CheckResult:
    """Chemins de contrôle vers les groupes Tier 0 (ACL + appartenance), parcours en largeur inverse."""
    targets = tier0_group_sids(snap) | {u.sid for u in snap.users if snap.user_is_privileged(u)}
    preds: dict[str, set[str]] = {}
    for e in snap.acl_edges:
        if e.target_sid and e.right in WRITE_RIGHTS:
            preds.setdefault(e.target_sid, set()).add(e.principal_sid)
    for g in snap.groups:
        for m in g.members:
            preds.setdefault(g.sid, set()).add(m)
    for u in snap.users:  # appartenance transitive déjà résolue
        for g in u.member_of:
            preds.setdefault(g, set()).add(u.sid)

    reach, queue = set(), deque(targets)
    while queue:
        node = queue.popleft()
        for p in preds.get(node, ()):
            if p not in reach and p not in targets:
                reach.add(p)
                queue.append(p)
    controllers = [s for s in reach if not snap.is_tier0(s)]

    if params.get("mode") == "everyone":
        hits = [snap.principal_name(s) for s in controllers if snap.is_low_privileged(s)]
        return CheckResult(affected=hits)
    count = len([s for s in controllers if any(u.sid == s for u in snap.users)])
    if count > params.get("max", 50):
        return CheckResult(affected=[f"{count} comptes non administrateurs"], details={"nombre": count})
    return CheckResult()


# ---------------------------------------------------------------------- appartenance et délégation vers le Tier 0


def _admin_group_members(snap: Snapshot) -> set[str]:
    """SIDs membres (directs, ou via member_of des utilisateurs) des groupes d'administration."""
    tier0 = tier0_group_sids(snap)
    members = {m for g in snap.groups if g.sid in tier0 for m in g.members}
    members |= {u.sid for u in snap.users if tier0 & set(u.member_of)}
    return members


@check("priv_foreign_admins")
def foreign_admins(snap: Snapshot, params: dict) -> CheckResult:
    """Comptes ou groupes d'un autre domaine (SID S-1-5-21 étranger) dans les groupes d'administration."""
    if snap.domain is None:
        return CheckResult()
    own = snap.domain.sid + "-"
    foreign = sorted(s for s in _admin_group_members(snap) if s.startswith("S-1-5-21-") and not s.startswith(own))
    return CheckResult(affected=[snap.principal_name(s) for s in foreign])


@check("priv_disabled_admins")
def disabled_admins(snap: Snapshot, params: dict) -> CheckResult:
    members = _admin_group_members(snap)
    return CheckResult(affected=sorted(u.sam for u in snap.users if not u.enabled and u.sid in members))


@check("priv_delegation_to_dc")
def delegation_to_dc(snap: Snapshot, params: dict) -> CheckResult:
    """Délégation contrainte d'un compte non Tier 0 vers un service d'un contrôleur de domaine."""
    dc_hosts = {h.lower() for d in snap.dcs() for h in filter(None, (d.name, d.dns_hostname))}
    dc_hosts |= {h.split(".", 1)[0] for h in dc_hosts}
    out = []
    for p in [*snap.users, *[cp for cp in snap.computers if not cp.is_dc]]:
        name = getattr(p, "sam", None) or p.name
        if snap.is_tier0(p.sid) or not getattr(p, "enabled", True):
            continue
        for spn in p.allowed_to_delegate_to:
            host = spn.split("/", 1)[-1].split(":", 1)[0].split("/", 1)[0].lower()
            if host in dc_hosts:
                out.append(f"{name} → {spn}")
    return CheckResult(affected=out)


# ----------------------------------------------------------------------------- RODC


def _rodcs(snap: Snapshot):
    return [cp for cp in snap.computers if cp.is_rodc and cp.enabled]


@check("priv_rodc_allowed_group")
def rodc_allowed_group(snap: Snapshot, params: dict) -> CheckResult:
    g = snap.group(f"{snap.domain.sid}-{c.RID_RODC_ALLOWED}")
    return CheckResult(affected=names(snap, g.members) if g else [])


@check("priv_rodc_denied_group")
def rodc_denied_group(snap: Snapshot, params: dict) -> CheckResult:
    g = snap.group(f"{snap.domain.sid}-{c.RID_RODC_DENIED}")
    if g is None:
        return CheckResult()
    d = snap.domain.sid
    expected = {
        f"{d}-{r}"
        for r in (
            c.RID_DOMAIN_ADMINS,
            c.RID_DOMAIN_CONTROLLERS,
            c.RID_CERT_PUBLISHERS,
            c.RID_SCHEMA_ADMINS,
            c.RID_ENTERPRISE_ADMINS,
            c.RID_GPO_CREATOR_OWNERS,
            c.RID_RODCS,
            c.RID_KRBTGT,
        )
    }
    return CheckResult(affected=names(snap, sorted(expected - set(g.members))))


@check("priv_rodc_reveal_on_demand")
def rodc_reveal_on_demand(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[r.name for r in _rodcs(snap) if any(snap.is_tier0(s) for s in r.reveal_on_demand_sids)]
    )


@check("priv_rodc_never_reveal")
def rodc_never_reveal(snap: Snapshot, params: dict) -> CheckResult:
    denied = f"{snap.domain.sid}-{c.RID_RODC_DENIED}"
    return CheckResult(affected=[r.name for r in _rodcs(snap) if denied not in r.never_reveal_sids])


@check("priv_rodc_admin_revealed")
def rodc_admin_revealed(snap: Snapshot, params: dict) -> CheckResult:
    admins = {u.sid for u in snap.users if snap.user_is_privileged(u)}
    res = CheckResult()
    for r in _rodcs(snap):
        leaked = [s for s in r.revealed_sids if s in admins]
        if leaked:
            res.affected.append(r.name)
            res.details[r.name] = names(snap, leaked)
    return res


@check("priv_rodc_sysvol_write")
def rodc_sysvol_write(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[r.name for r in _rodcs(snap) if r.rodc_sysvol_write])


@check("priv_rodc_krbtgt_orphan")
def rodc_krbtgt_orphan(snap: Snapshot, params: dict) -> CheckResult:
    rodc_count = len(_rodcs(snap))
    krbtgts = [u.sam for u in snap.users if u.sam.lower().startswith("krbtgt_")]
    return CheckResult(affected=krbtgts) if len(krbtgts) > rodc_count else CheckResult()


# ----------------------------------------------------------------------------- GPO de droits


def _gpo_priv_hits(snap: Snapshot, privileges: set[str], scope: str, predicate) -> CheckResult:
    res = CheckResult()
    for priv in privileges:
        for gpo, principals in gpo_privilege(snap, priv, scope):
            bad = [p for p in principals if predicate(p)]
            if bad:
                res.affected.append(gpo.name)
                res.details.setdefault(gpo.name, {})[priv] = [
                    snap.principal_name(p) if p.startswith("S-1-") else p for p in bad
                ]
    return res


@check("priv_gpo_privilege_everyone")
def gpo_privilege_everyone(snap: Snapshot, params: dict) -> CheckResult:
    return _gpo_priv_hits(snap, c.DANGEROUS_PRIVILEGES, "any", lambda p: is_everyone_like(snap, p))


@check("priv_gpo_login_dc_everyone")
def gpo_login_dc_everyone(snap: Snapshot, params: dict) -> CheckResult:
    rights = {"SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight"}
    return _gpo_priv_hits(snap, rights, "dcs", lambda p: is_everyone_like(snap, p))


@check("priv_gpo_trusted_credman")
def gpo_trusted_credman(snap: Snapshot, params: dict) -> CheckResult:
    return _gpo_priv_hits(snap, {"SeTrustedCredManAccessPrivilege"}, "any", lambda p: True)


@check("priv_gpo_logon_denied")
def gpo_logon_denied(snap: Snapshot, params: dict) -> CheckResult:
    if not gpos_known(snap):
        return CheckResult()
    da = f"{snap.domain.sid}-{c.RID_DOMAIN_ADMINS}"
    for priv in ("SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyNetworkLogonRight"):
        for _, principals in gpo_privilege(snap, priv, "non_dc"):
            if da in principals or any("domain admins" in p.lower() for p in principals):
                return CheckResult()
    return CheckResult(affected=["Aucune GPO n'interdit la connexion des admins du domaine aux postes/serveurs"])


@check("priv_gpo_recovery_mode")
def gpo_recovery_mode(snap: Snapshot, params: dict) -> CheckResult:
    key = r"machine\software\microsoft\windows nt\currentversion\setup\recoveryconsole\securitylevel"
    return CheckResult(affected=[g.name for g, v in gpo_values(snap, key) if str(v) == "1"])


@check("priv_gpo_writable")
def gpo_writable(snap: Snapshot, params: dict) -> CheckResult:
    """GPO, scripts ou fichiers déployés modifiables par des groupes larges (selon params.what)."""
    what = params.get("what", "gpo")
    res = CheckResult()
    for g in snap.gpos or []:
        if what == "gpo":
            bad = [s for s in g.writers if snap.is_low_privileged(s)]
            if bad:
                res.affected.append(g.name)
                res.details[g.name] = names(snap, bad)
            continue
        for ref in g.scripts if what == "scripts" else g.files:
            if ref.writers and any(snap.is_low_privileged(s) for s in ref.writers):
                res.affected.append(ref.path)
    return res


@check("priv_display_specifier")
def display_specifier(snap: Snapshot, params: dict) -> CheckResult:
    dom = snap.domain.name.lower()
    ok = (f"\\\\{dom}\\sysvol", f"\\\\{dom}\\netlogon")
    return CheckResult(affected=[a for a in snap.domain.display_specifier_actions if not a.lower().startswith(ok)])


@check("priv_unprotected_ou")
def unprotected_ou(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=list(snap.domain.unprotected_ous))


@check("priv_dsheuristics_adminsdexmask")
def dsheuristics_adminsdexmask(snap: Snapshot, params: dict) -> CheckResult:
    from ._helpers import ds_heuristic

    v = ds_heuristic(snap, c.DSH_ADMINSD_EXMASK)
    return CheckResult(affected=[f"dwAdminSDExMask = {v}"]) if v not in (None, "0") else CheckResult()


@check("priv_dsheuristics_dolistobject")
def dsheuristics_dolistobject(snap: Snapshot, params: dict) -> CheckResult:
    from ._helpers import ds_heuristic

    return CheckResult(affected=["fDoListObject"]) if ds_heuristic(snap, c.DSH_DO_LIST_OBJECT) == "1" else CheckResult()
