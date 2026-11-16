"""Contrôles Entra ID (Microsoft Graph, lecture seule)."""

from __future__ import annotations

from datetime import timedelta

from ... import constants as c
from ...models import EntraTenant, Snapshot
from ..registry import CheckResult, check
from ._helpers import never_or_older


def _t(snap: Snapshot) -> EntraTenant:
    return snap.entra  # le moteur garantit que snap.entra existe pour les règles Entra


def _users_by_id(t: EntraTenant):
    return {u.id: u for u in t.users}


def _privileged_principals(t: EntraTenant, roles: set[str] | None = None, active_only: bool = False) -> dict[str, set]:
    roles = roles or set(c.ENTRA_PRIVILEGED_ROLES)
    out: dict[str, set] = {}
    for a in t.role_assignments:
        if a.role_template_id in roles and (not active_only or a.assignment == "active"):
            out.setdefault(a.principal_id, set()).add(a.role)
    return out


def _ca_enabled(t: EntraTenant):
    return [p for p in t.ca_policies or [] if p.state == "enabled"]


# ----------------------------------------------------------------------------- comptes et rôles


@check("entra_global_admins_count")
def global_admins_count(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    users = _users_by_id(t)
    gas = [
        users[p].upn if p in users else p
        for p in _privileged_principals(t, {c.ENTRA_ROLE_GLOBAL_ADMIN}, active_only=True)
    ]
    lo, hi = params.get("min", 2), params.get("max", 5)
    if len(gas) > hi or len(gas) < lo:
        return CheckResult(affected=gas or ["aucun"], details={"nombre": len(gas), "attendu": f"{lo}-{hi}"})
    return CheckResult()


@check("entra_admin_no_mfa")
def admin_no_mfa(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    users = _users_by_id(t)
    return CheckResult(
        affected=[users[p].upn for p in _privileged_principals(t) if p in users and users[p].mfa_registered is False]
    )


@check("entra_users_no_mfa")
def users_no_mfa(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    members = [u for u in t.users if u.enabled and u.user_type == "Member" and u.mfa_registered is not None]
    without = [u.upn for u in members if not u.mfa_registered]
    if members and len(without) / len(members) * 100 > params.get("max_percent", 5):
        return CheckResult(affected=without, details={"pourcentage": round(len(without) / len(members) * 100, 1)})
    return CheckResult()


@check("entra_synced_privileged")
def synced_privileged(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    users = _users_by_id(t)
    return CheckResult(
        affected=[users[p].upn for p in _privileged_principals(t) if p in users and users[p].on_prem_synced]
    )


@check("entra_permanent_privileged")
def permanent_privileged(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    if not t.pim_available:
        return CheckResult()
    users = _users_by_id(t)
    hits = {
        users[a.principal_id].upn if a.principal_id in users else a.principal_id
        for a in t.role_assignments
        if a.role_template_id in c.ENTRA_PRIVILEGED_ROLES
        and a.assignment == "active"
        and a.permanent
        and a.principal_type == "user"
    }
    return CheckResult(affected=sorted(hits)) if len(hits) > params.get("max", 2) else CheckResult()


@check("entra_privileged_guests")
def privileged_guests(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    users = _users_by_id(t)
    return CheckResult(
        affected=[users[p].upn for p in _privileged_principals(t) if p in users and users[p].user_type == "Guest"]
    )


@check("entra_stale_users")
def stale_users(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    kind, days = params.get("user_type", "Member"), params.get("days", 90)
    grace = snap.collected_at - timedelta(days=days)
    return CheckResult(
        affected=[
            u.upn
            for u in t.users
            if u.enabled
            and u.user_type == kind
            and (u.created is None or u.created < grace)
            and never_or_older(snap, u.last_sign_in, days)
        ]
    )


@check("entra_risky_users")
def risky_users(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    return CheckResult(affected=[u.upn for u in t.users if u.risk_level == "high" and u.risk_state == "atRisk"])


# ----------------------------------------------------------------------------- paramètres du tenant


@check("entra_setting")
def setting(snap: Snapshot, params: dict) -> CheckResult:
    """Paramètre du tenant égal à une valeur risquée (params.field, params.bad)."""
    value = getattr(_t(snap), params["field"])
    bad = params["bad"] if isinstance(params["bad"], list) else [params["bad"]]
    return (
        CheckResult(affected=[f"{params['field']} = {value}"]) if value is not None and value in bad else CheckResult()
    )


@check("entra_federated_domains")
def federated_domains(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=list(_t(snap).federated_domains))


@check("entra_connect_version")
def connect_version(snap: Snapshot, params: dict) -> CheckResult:
    v = _t(snap).connect_version
    if not v:
        return CheckResult()
    parts = tuple(int(x) for x in v.split(".")[:3] if x.isdigit())
    minimum = tuple(params.get("min", [2, 4, 0]))
    return (
        CheckResult(affected=[v], details={"minimum": ".".join(map(str, minimum))})
        if parts < minimum
        else CheckResult()
    )


# ----------------------------------------------------------------------------- accès conditionnel


@check("entra_ca")
def conditional_access(snap: Snapshot, params: dict) -> CheckResult:
    """params.what : no_policies | mfa_admins | mfa_all | legacy_auth | report_only
    | phishing_resistant_admins | device_code | risk"""
    t = _t(snap)
    if t.ca_policies is None:
        return CheckResult()
    what = params["what"]
    enabled = _ca_enabled(t)
    covered_by_defaults = bool(t.security_defaults)

    def requires_mfa(p) -> bool:
        return "mfa" in p.grant_controls or p.authentication_strength is not None

    if what == "no_policies":
        return CheckResult() if enabled or covered_by_defaults else CheckResult(affected=[t.name])
    if what == "report_only":
        return CheckResult(affected=[p.name for p in t.ca_policies if p.state == "enabledForReportingButNotEnforced"])
    # Les valeurs de sécurité par défaut n'offrent ni force d'authentification, ni blocage des flux, ni risque
    if what == "phishing_resistant_admins":
        ok = any(
            p.authentication_strength == c.ENTRA_AUTH_STRENGTH_PHISHING_RESISTANT
            and ("All" in p.include_users or c.ENTRA_ROLE_GLOBAL_ADMIN in p.include_roles)
            for p in enabled
        )
        return CheckResult() if ok else CheckResult(affected=["rôles d'administration"])
    if what == "device_code":
        ok = any(
            "block" in p.grant_controls and "deviceCodeFlow" in p.auth_flows and "All" in p.include_users
            for p in enabled
        )
        return CheckResult() if ok else CheckResult(affected=["flux d'authentification par code d'appareil"])
    if what == "risk":
        if not t.pim_available:  # les conditions de risque exigent la licence P2 (même indicateur que PIM)
            return CheckResult()
        has_user = any(p.user_risk_levels and "All" in p.include_users for p in enabled)
        has_signin = any(p.sign_in_risk_levels and "All" in p.include_users for p in enabled)
        missing = [x for x, ok in (("risque utilisateur", has_user), ("risque de connexion", has_signin)) if not ok]
        return CheckResult(affected=missing)
    if covered_by_defaults:
        return CheckResult()
    if what == "mfa_admins":
        ok = any(
            requires_mfa(p) and ("All" in p.include_users or c.ENTRA_ROLE_GLOBAL_ADMIN in p.include_roles)
            for p in enabled
        )
        return CheckResult() if ok else CheckResult(affected=["rôles d'administration"])
    if what == "mfa_all":
        ok = any(requires_mfa(p) and "All" in p.include_users for p in enabled)
        return CheckResult() if ok else CheckResult(affected=["tous les utilisateurs"])
    if what == "legacy_auth":
        ok = any(
            "block" in p.grant_controls
            and {"exchangeActiveSync", "other"} & set(p.client_app_types)
            and "All" in p.include_users
            for p in enabled
        )
        return CheckResult() if ok else CheckResult(affected=["authentification héritée"])
    raise ValueError(what)


@check("entra_weak_auth_methods")
def weak_auth_methods(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    labels = {"sms": "SMS", "voice": "Appel vocal"}
    return CheckResult(affected=[labels.get(m, m) for m in t.weak_auth_methods or []])


@check("entra_device_join")
def device_join(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    if t.device_join_all_users is None or t.device_join_mfa_required is None:
        return CheckResult()
    return (
        CheckResult(affected=["jonction Entra"])
        if t.device_join_all_users and not t.device_join_mfa_required
        else CheckResult()
    )


# ----------------------------------------------------------------------------- applications


@check("entra_app_dangerous_permissions")
def app_dangerous_permissions(snap: Snapshot, params: dict) -> CheckResult:
    level = params.get("level", "critical")
    res = CheckResult()
    for app in _t(snap).apps:
        perms = [p for p in app.graph_app_permissions if c.GRAPH_DANGEROUS_APP_PERMISSIONS.get(p) == level]
        if perms and not app.first_party:
            res.affected.append(app.name)
            res.details[app.name] = perms
    return res


@check("entra_app_privileged_role")
def app_privileged_role(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    apps = {a.id: a.name for a in t.apps}
    return CheckResult(
        affected=sorted(
            {
                apps.get(a.principal_id, a.principal_id)
                for a in t.role_assignments
                if a.principal_type == "servicePrincipal" and a.role_template_id in c.ENTRA_PRIVILEGED_ROLES
            }
        )
    )


@check("entra_app_owner_non_admin")
def app_owner_non_admin(snap: Snapshot, params: dict) -> CheckResult:
    t = _t(snap)
    admins = set(_privileged_principals(t))
    users = _users_by_id(t)
    res = CheckResult()
    for app in t.apps:
        risky = any(p in c.GRAPH_DANGEROUS_APP_PERMISSIONS for p in app.graph_app_permissions)
        owners = [users[o].upn if o in users else o for o in app.owners if o not in admins]
        if risky and owners:
            res.affected.append(app.name)
            res.details[app.name] = owners
    return res


@check("entra_app_credentials")
def app_credentials(snap: Snapshot, params: dict) -> CheckResult:
    """params.what : long_lived | expired | sp_password"""
    what = params["what"]
    res = CheckResult()
    for app in _t(snap).apps:
        for cred in app.credentials:
            if (
                what == "long_lived"
                and cred.kind == "password"
                and cred.start
                and cred.end
                and (cred.end - cred.start).days > params.get("max_days", 730)
            ):
                res.affected.append(app.name)
            elif what == "expired" and cred.end and cred.end < snap.collected_at:
                res.affected.append(app.name)
            elif (
                what == "sp_password"
                and app.kind == "servicePrincipal"
                and not app.first_party
                and cred.kind == "password"
            ):
                res.affected.append(app.name)
    return res
