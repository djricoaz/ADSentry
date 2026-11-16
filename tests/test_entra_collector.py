"""Collecteur Entra ID contre un Graph simulé (aucun appel réseau)."""

from __future__ import annotations

import httpx

from adsentry.collectors.entra_collector import EntraCollector
from adsentry.rules.engine import analyze

GA = "62e90394-69f5-4237-9190-012177145e10"
GRAPH_SP = "graph-sp"

RESPONSES = {
    "/organization": {"value": [{"displayName": "Contoso", "onPremisesLastSyncDateTime": "2026-11-01T09:00:00Z"}]},
    "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
    "/policies/authorizationPolicy": {
        "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
        "allowInvitesFrom": "everyone",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": True,
            "allowedToCreateTenants": False,
            "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
        },
    },
    "/domains": {
        "value": [
            {"id": "contoso.com", "authenticationType": "Federated"},
            {"id": "contoso.onmicrosoft.com", "authenticationType": "Managed"},
        ]
    },
    "/users": {
        "value": [
            {
                "id": "u1",
                "userPrincipalName": "admin@contoso.com",
                "accountEnabled": True,
                "userType": "Member",
                "onPremisesSyncEnabled": True,
                "createdDateTime": "2024-01-01T00:00:00Z",
                "signInActivity": {"lastSignInDateTime": "2026-10-30T00:00:00Z"},
            },
            {
                "id": "u2",
                "userPrincipalName": "guest@ext.com",
                "accountEnabled": True,
                "userType": "Guest",
                "createdDateTime": "2024-01-01T00:00:00Z",
                "signInActivity": {},
            },
        ]
    },
    "/reports/authenticationMethods/userRegistrationDetails": {"value": [{"id": "u1", "isMfaRegistered": False}]},
    "/identityProtection/riskyUsers": None,  # 403 : pas de licence P2
    "/roleManagement/directory/roleDefinitions": {"value": [{"templateId": GA, "displayName": "Global Administrator"}]},
    "/roleManagement/directory/roleAssignmentSchedules": None,  # PIM indisponible
    "/roleManagement/directory/roleEligibilitySchedules": None,
    "/roleManagement/directory/roleAssignments": {
        "value": [
            {"roleDefinitionId": GA, "principalId": "u1", "principal": {"@odata.type": "#microsoft.graph.user"}},
            {
                "roleDefinitionId": GA,
                "principalId": "sp9",
                "principal": {"@odata.type": "#microsoft.graph.servicePrincipal"},
            },
        ]
    },
    "/applications": {
        "value": [
            {
                "id": "app1",
                "appId": "aaa",
                "displayName": "Automation",
                "passwordCredentials": [
                    {"startDateTime": "2024-01-01T00:00:00Z", "endDateTime": "2030-01-01T00:00:00Z"}
                ],
                "owners": [{"id": "u2"}],
            }
        ]
    },
    "/servicePrincipals": {
        "value": [
            {"id": "sp1", "appId": "aaa", "displayName": "Automation", "appOwnerOrganizationId": "tid"},
            {
                "id": GRAPH_SP,
                "appId": "00000003-0000-0000-c000-000000000000",
                "displayName": "Microsoft Graph",
                "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                "appRoles": [{"id": "r1", "value": "RoleManagement.ReadWrite.Directory"}],
            },
        ]
    },
    f"/servicePrincipals/{GRAPH_SP}/appRoleAssignedTo": {"value": [{"principalId": "sp1", "appRoleId": "r1"}]},
    "/identity/conditionalAccess/policies": {"value": []},
}


def handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path.removeprefix("/v1.0")
    if path not in RESPONSES:
        return httpx.Response(404, json={"error": path})
    body = RESPONSES[path]
    return httpx.Response(403, json={}) if body is None else httpx.Response(200, json=body)


def test_entra_collector_end_to_end(monkeypatch):
    col = EntraCollector("tid", "client", client_secret="x")
    col.http = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(col, "_token", lambda: "fake")
    snap = col.collect()
    t = snap.entra
    assert t.name == "Contoso" and t.security_defaults is False and t.users_can_consent is True
    assert t.guest_role == "same_as_member" and t.federated_domains == ["contoso.com"]
    assert t.pim_available is False
    assert next(a for a in t.apps if a.kind == "application").graph_app_permissions == [
        "RoleManagement.ReadWrite.Directory"
    ]

    fired = {f.rule_id for f in analyze(snap).findings}
    assert {
        "E-ADMIN-NO-MFA",
        "E-SYNCED-PRIVILEGED",
        "E-USER-CONSENT",
        "E-GUEST-SAME-AS-MEMBER",
        "E-APP-CRITICAL-PERMISSIONS",
        "E-APP-OWNER-NON-ADMIN",
        "E-APP-PRIVILEGED-ROLE",
        "E-FEDERATED-DOMAINS",
        "E-NO-CA-POLICIES",
        "E-APP-LONG-LIVED-SECRETS",
    } <= fired
    assert "E-RISKY-USERS" not in fired  # donnée P2 indisponible -> rien n'est inventé


def test_new_entra_controls_parsed(monkeypatch):
    extra = {
        "/policies/authenticationMethodsPolicy": {
            "authenticationMethodConfigurations": [
                {"id": "Sms", "state": "enabled"},
                {"id": "Voice", "state": "disabled"},
                {"id": "Fido2", "state": "enabled"},
            ]
        },
        "/policies/deviceRegistrationPolicy": {
            "azureADJoin": {"allowedToJoin": {"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"}},
            "multiFactorAuthConfiguration": "notRequired",
        },
        "/identity/conditionalAccess/policies": {
            "value": [
                {
                    "displayName": "Bloquer code d'appareil",
                    "state": "enabled",
                    "conditions": {
                        "users": {"includeUsers": ["All"]},
                        "authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"},
                    },
                    "grantControls": {"builtInControls": ["block"]},
                },
                {
                    "displayName": "Risque",
                    "state": "enabled",
                    "conditions": {"users": {"includeUsers": ["All"]}, "signInRiskLevels": ["high"]},
                    "grantControls": {"builtInControls": ["mfa"]},
                },
            ]
        },
    }
    monkeypatch.setitem(
        RESPONSES, "/policies/authenticationMethodsPolicy", extra["/policies/authenticationMethodsPolicy"]
    )
    monkeypatch.setitem(RESPONSES, "/policies/deviceRegistrationPolicy", extra["/policies/deviceRegistrationPolicy"])
    monkeypatch.setitem(
        RESPONSES, "/identity/conditionalAccess/policies", extra["/identity/conditionalAccess/policies"]
    )
    col = EntraCollector("tid", "client", client_secret="x")
    col.http = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(col, "_token", lambda: "fake")
    t = col.collect().entra
    assert t.weak_auth_methods == ["sms"]
    assert t.device_join_all_users is True and t.device_join_mfa_required is False
    block = next(p for p in t.ca_policies if p.name == "Bloquer code d'appareil")
    assert block.auth_flows == ["deviceCodeFlow", "authenticationTransfer"]
    assert next(p for p in t.ca_policies if p.name == "Risque").sign_in_risk_levels == ["high"]
    fired = {f.rule_id: f for f in analyze(col.collect()).findings}
    assert "E-WEAK-AUTH-METHODS" in fired and fired["E-WEAK-AUTH-METHODS"].affected == ["SMS"]
    assert "E-DEVICE-JOIN-NO-MFA" in fired and "E-CA-DEVICE-CODE" not in fired


def test_new_entra_controls_not_evaluated_without_data(monkeypatch):
    col = EntraCollector("tid", "client", client_secret="x")
    col.http = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(col, "_token", lambda: "fake")
    snap = col.collect()
    assert snap.entra.weak_auth_methods is None and snap.entra.device_join_all_users is None
    fired = {f.rule_id for f in analyze(snap).findings}
    # données non lisibles (404/403) ou sans licence P2 : rien n'est inventé
    assert not {"E-WEAK-AUTH-METHODS", "E-DEVICE-JOIN-NO-MFA", "E-CA-NO-RISK-POLICIES"} & fired
