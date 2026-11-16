"""Collecteur Entra ID — Microsoft Graph, application en LECTURE SEULE (authentification par certificat).

Permissions d'application à accorder (consentement administrateur) — toutes en lecture :
    Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory, Application.Read.All,
    AuditLog.Read.All, Reports.Read.All, IdentityRiskyUser.Read.All,
    RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory
Licences : signInActivity, accès conditionnel et rapports MFA nécessitent Entra ID P1 ; PIM et
Identity Protection nécessitent P2. Une donnée inaccessible (403/400) reste à None : les règles
concernées ne se déclenchent pas et sont signalées « non évaluées ».

⚠ Non validé contre un vrai tenant : à tester sur un tenant de développement (phase 1 bis).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .. import constants as c
from ..models import (
    ConditionalAccessPolicy,
    EntraApp,
    EntraCredential,
    EntraRoleAssignment,
    EntraTenant,
    EntraUser,
    Snapshot,
)

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"


class GraphUnavailable(Exception):
    """Ressource inaccessible (licence ou permission manquante)."""


def _dt(v: str | None) -> datetime | None:
    if not v:
        return None
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


class EntraCollector:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        cert_path: Path | None = None,
        cert_thumbprint: str | None = None,
        client_secret: str | None = None,
        connect_version: str | None = None,
    ):
        self.tenant_id, self.client_id = tenant_id, client_id
        self.cert_path, self.cert_thumbprint, self.client_secret = cert_path, cert_thumbprint, client_secret
        self.connect_version = connect_version
        self.http = httpx.Client(timeout=60)

    # -- authentification ------------------------------------------------------
    def _token(self) -> str:
        import msal

        if self.cert_path:
            credential: Any = {"private_key": self.cert_path.read_text(), "thumbprint": self.cert_thumbprint}
        else:
            credential = self.client_secret
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=credential,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise RuntimeError(f"Authentification Graph impossible : {result.get('error_description')}")
        return result["access_token"]

    def _get_all(self, path: str, params: dict | None = None) -> list[dict]:
        url, out = f"{GRAPH}{path}", []
        while url:
            r = self.http.get(url, params=params, headers={"ConsistencyLevel": "eventual"})
            if r.status_code in (400, 403, 404):
                raise GraphUnavailable(f"{path}: {r.status_code} {r.text[:200]}")
            r.raise_for_status()
            data = r.json()
            out.extend(data.get("value", [data] if "value" not in data else []))
            url, params = data.get("@odata.nextLink"), None
        return out

    def _try(self, path: str, params: dict | None = None) -> list[dict] | None:
        try:
            return self._get_all(path, params)
        except GraphUnavailable as exc:
            log.warning("Donnée Entra non collectée : %s", exc)
            return None

    # -- collecte --------------------------------------------------------------
    def collect(self) -> Snapshot:
        self.http.headers["Authorization"] = f"Bearer {self._token()}"
        org = (self._try("/organization") or [{}])[0]
        tenant = EntraTenant(
            tenant_id=self.tenant_id,
            name=org.get("displayName", self.tenant_id),
            connect_last_sync=_dt(org.get("onPremisesLastSyncDateTime")),
            connect_version=self.connect_version,
        )
        self._policies(tenant)
        tenant.users = self._users()
        tenant.role_assignments, tenant.pim_available = self._roles()
        tenant.apps = self._apps()
        tenant.ca_policies = self._ca()
        return Snapshot(collected_at=datetime.now(UTC), collector="graph", entra=tenant)

    def _policies(self, t: EntraTenant) -> None:
        sd = self._try("/policies/identitySecurityDefaultsEnforcementPolicy")
        t.security_defaults = sd[0].get("isEnabled") if sd else None
        auth = self._try("/policies/authorizationPolicy")
        if auth:
            a = auth[0]
            perms = a.get("defaultUserRolePermissions", {})
            t.users_can_register_apps = perms.get("allowedToCreateApps")
            t.users_can_create_tenants = perms.get("allowedToCreateTenants")
            grants = perms.get("permissionGrantPoliciesAssigned", [])
            t.users_can_consent = any(g.endswith("microsoft-user-default-legacy") for g in grants)
            t.guest_role = c.ENTRA_GUEST_ROLES.get(a.get("guestUserRoleId", ""))
            t.guest_invite_from = a.get("allowInvitesFrom")
        methods = self._try("/policies/authenticationMethodsPolicy")
        if methods:
            confs = methods[0].get("authenticationMethodConfigurations") or []
            t.weak_auth_methods = sorted(
                x["id"].lower()
                for x in confs
                if x.get("id", "").lower() in ("sms", "voice") and x.get("state") == "enabled"
            )
        devices = self._try("/policies/deviceRegistrationPolicy")  # Policy.Read.DeviceConfiguration
        if devices:
            dv = devices[0]
            members = ((dv.get("azureADJoin") or {}).get("allowedToJoin") or {}).get("@odata.type", "")
            t.device_join_all_users = members.endswith("allDeviceRegistrationMembership") if members else None
            mfa = dv.get("multiFactorAuthConfiguration")
            t.device_join_mfa_required = None if mfa is None else mfa == "required"
        domains = self._try("/domains") or []
        t.federated_domains = [d["id"] for d in domains if d.get("authenticationType") == "Federated"]

    def _users(self) -> list[EntraUser]:
        select = (
            "id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,onPremisesSecurityIdentifier,"
            "createdDateTime"
        )
        raw = self._try("/users", {"$select": select + ",signInActivity", "$top": "999"})
        if raw is None:  # signInActivity exige P1 + AuditLog.Read.All
            raw = self._try("/users", {"$select": select, "$top": "999"}) or []
        mfa = {
            r["id"]: r.get("isMfaRegistered")
            for r in self._try("/reports/authenticationMethods/userRegistrationDetails") or []
        }
        risk = {r["id"]: r for r in self._try("/identityProtection/riskyUsers") or []}
        users = []
        for u in raw:
            sign_in = u.get("signInActivity") or {}
            last = max(
                filter(
                    None, [_dt(sign_in.get("lastSignInDateTime")), _dt(sign_in.get("lastNonInteractiveSignInDateTime"))]
                ),
                default=None,
            )
            r = risk.get(u["id"], {})
            users.append(
                EntraUser(
                    id=u["id"],
                    upn=u.get("userPrincipalName", ""),
                    enabled=u.get("accountEnabled", True),
                    user_type=u.get("userType") or "Member",
                    on_prem_synced=bool(u.get("onPremisesSyncEnabled")),
                    on_prem_sid=u.get("onPremisesSecurityIdentifier"),
                    created=_dt(u.get("createdDateTime")),
                    last_sign_in=last,
                    mfa_registered=mfa.get(u["id"]),
                    risk_level=r.get("riskLevel"),
                    risk_state=r.get("riskState"),
                )
            )
        return users

    def _roles(self) -> tuple[list[EntraRoleAssignment], bool]:
        names = {
            d["templateId"]: d["displayName"] for d in self._try("/roleManagement/directory/roleDefinitions") or []
        }

        def kind(p: dict) -> str:
            return (p.get("@odata.type") or "#microsoft.graph.user").rsplit(".", 1)[-1]

        out: list[EntraRoleAssignment] = []
        active = self._try("/roleManagement/directory/roleAssignmentSchedules", {"$expand": "principal"})
        eligible = self._try("/roleManagement/directory/roleEligibilitySchedules", {"$expand": "principal"})
        pim = active is not None and eligible is not None
        if pim:
            for a in active:
                permanent = (a.get("scheduleInfo", {}).get("expiration", {}) or {}).get("type") == "noExpiration"
                out.append(
                    EntraRoleAssignment(
                        role=names.get(a["roleDefinitionId"], a["roleDefinitionId"]),
                        role_template_id=a["roleDefinitionId"],
                        principal_id=a["principalId"],
                        principal_type=kind(a.get("principal", {})),
                        permanent=permanent,
                    )
                )
            for a in eligible:
                out.append(
                    EntraRoleAssignment(
                        role=names.get(a["roleDefinitionId"], a["roleDefinitionId"]),
                        role_template_id=a["roleDefinitionId"],
                        principal_id=a["principalId"],
                        principal_type=kind(a.get("principal", {})),
                        assignment="eligible",
                        permanent=False,
                    )
                )
        else:
            for a in self._try("/roleManagement/directory/roleAssignments", {"$expand": "principal"}) or []:
                out.append(
                    EntraRoleAssignment(
                        role=names.get(a["roleDefinitionId"], a["roleDefinitionId"]),
                        role_template_id=a["roleDefinitionId"],
                        principal_id=a["principalId"],
                        principal_type=kind(a.get("principal", {})),
                    )
                )
        # Groupes assignables à des rôles : on développe les membres (utilisateurs) transitivement
        for a in [x for x in out if x.principal_type == "group"]:
            for m in self._try(f"/groups/{a.principal_id}/transitiveMembers", {"$select": "id"}) or []:
                out.append(a.model_copy(update={"principal_id": m["id"], "principal_type": kind(m)}))
        return out, pim

    def _apps(self) -> list[EntraApp]:
        sel = "id,appId,displayName,passwordCredentials,keyCredentials"
        apps = self._try("/applications", {"$select": sel, "$expand": "owners($select=id)"}) or []
        sps = (
            self._try(
                "/servicePrincipals", {"$select": sel + ",appOwnerOrganizationId", "$expand": "owners($select=id)"}
            )
            or []
        )
        perms: dict[str, list[str]] = {}
        candidates = (
            self._try("/servicePrincipals", {"$filter": f"appId eq '{c.GRAPH_APP_ID}'", "$select": "id,appId,appRoles"})
            or []
        )
        graph = next((s for s in candidates if s.get("appId") == c.GRAPH_APP_ID), None)
        if graph:
            roles = {r["id"]: r["value"] for r in graph.get("appRoles", [])}
            for a in self._try(f"/servicePrincipals/{graph['id']}/appRoleAssignedTo") or []:
                perms.setdefault(a["principalId"], []).append(roles.get(a["appRoleId"], a["appRoleId"]))
        sp_perm_by_appid = {s["appId"]: perms.get(s["id"], []) for s in sps}

        def creds(o: dict) -> list[EntraCredential]:
            return [
                EntraCredential(kind=k, start=_dt(x.get("startDateTime")), end=_dt(x.get("endDateTime")))
                for k, key in (("password", "passwordCredentials"), ("certificate", "keyCredentials"))
                for x in o.get(key) or []
            ]

        out = [
            EntraApp(
                id=a["id"],
                app_id=a["appId"],
                name=a.get("displayName", ""),
                credentials=creds(a),
                graph_app_permissions=sp_perm_by_appid.get(a["appId"], []),
                owners=[o["id"] for o in a.get("owners", [])],
            )
            for a in apps
        ]
        out += [
            EntraApp(
                id=s["id"],
                app_id=s["appId"],
                name=s.get("displayName", ""),
                kind="servicePrincipal",
                first_party=s.get("appOwnerOrganizationId") not in (None, self.tenant_id),
                credentials=creds(s),
                graph_app_permissions=perms.get(s["id"], []),
                owners=[o["id"] for o in s.get("owners", [])],
            )
            for s in sps
        ]
        return out

    def _ca(self) -> list[ConditionalAccessPolicy] | None:
        raw = self._try("/identity/conditionalAccess/policies")
        if raw is None:
            return None
        out = []
        for p in raw:
            cond, grant = p.get("conditions") or {}, p.get("grantControls") or {}
            users = cond.get("users") or {}
            out.append(
                ConditionalAccessPolicy(
                    name=p.get("displayName", ""),
                    state=p.get("state", "disabled"),
                    include_users=users.get("includeUsers") or [],
                    include_roles=users.get("includeRoles") or [],
                    exclude_users=users.get("excludeUsers") or [],
                    client_app_types=cond.get("clientAppTypes") or [],
                    grant_controls=grant.get("builtInControls") or [],
                    authentication_strength=(grant.get("authenticationStrength") or {}).get("id"),
                    auth_flows=[
                        x.strip()
                        for x in ((cond.get("authenticationFlows") or {}).get("transferMethods") or "").split(",")
                        if x.strip()
                    ],
                    user_risk_levels=cond.get("userRiskLevels") or [],
                    sign_in_risk_levels=cond.get("signInRiskLevels") or [],
                )
            )
        return out
