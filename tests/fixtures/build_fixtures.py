"""Génère les deux domaines de test synthétiques (aucune donnée réelle).

* vulnerable_snapshot.json : chaque règle évaluable doit s'y déclencher (sauf liste documentée).
* hardened_snapshot.json   : domaine + tenant bien configurés, aucune règle ne doit se déclencher.

    python tests/fixtures/build_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

D = "S-1-5-21-1000-2000-3000"
TRUSTED = "S-1-5-21-7777-7777-7777"
NOW = "2026-11-01T10:00:00Z"
RECENT = "2026-10-30T08:00:00Z"
OLD = "2025-01-01T08:00:00Z"
AU, EVERYONE, ANON = "S-1-5-11", "S-1-1-0", "S-1-5-7"
DA, DU, DC_GRP = f"{D}-512", f"{D}-513", f"{D}-516"
LSA = r"machine\system\currentcontrolset\control\lsa"
WU = r"machine\software\policies\microsoft\windows\windowsupdate"
GA = "62e90394-69f5-4237-9190-012177145e10"
SEC_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
AUDIT = [
    "Audit Credential Validation",
    "Audit Kerberos Authentication Service",
    "Audit Kerberos Service Ticket Operations",
    "Audit Computer Account Management",
    "Audit Security Group Management",
    "Audit User Account Management",
    "Audit Directory Service Access",
    "Audit Directory Service Changes",
    "Audit Logon",
    "Audit Special Logon",
]
ASR = [
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
]
ASR_KEY = r"machine\software\policies\microsoft\windows defender\windows defender exploit guard\asr\rules"


def ds_heuristics(**chars: str) -> str:
    v = ["0"] * 29
    v[9], v[19] = "1", "2"  # caractères de contrôle obligatoires (10e et 20e)
    for pos, ch in chars.items():
        v[int(pos[1:]) - 1] = ch
    return "".join(v)


def user(sam, rid, **kw):
    return {
        "sam": sam,
        "sid": f"{D}-{rid}",
        "member_of": kw.pop("member_of", [DU]),
        "last_logon": kw.pop("last_logon", RECENT),
        "pwd_last_set": kw.pop("pwd_last_set", "2026-09-15T00:00:00Z"),
        **kw,
    }


def comp(name, rid, **kw):
    return {
        "name": name,
        "sid": f"{D}-{rid}",
        "dns_hostname": f"{name.lower()}.corp.local",
        "last_logon": kw.pop("last_logon", RECENT),
        "pwd_last_set": kw.pop("pwd_last_set", "2026-10-20T00:00:00Z"),
        "laps": kw.pop("laps", True),
        "os": kw.pop("os", "Windows 11 Enterprise"),
        "os_build": kw.pop("os_build", 26100),
        **kw,
    }


def edge(principal, target, right, ttype="object", tsid=None):
    return {"principal_sid": principal, "target": target, "right": right, "target_type": ttype, "target_sid": tsid}


# ============================================================================ PKI commune
TEMPLATES_VULN = [
    {
        "name": "User",
        "schema_version": 1,
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.4"],
        "enroll_principals": [DU],
        "write_principals": [DA],
    },
    {
        "name": "VulnAuth",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "name_flags": 1,
        "enroll_principals": [DU],
    },
    {"name": "AnyPurpose", "published_on": ["CORP-CA"], "ekus": ["2.5.29.37.0"], "enroll_principals": [AU]},
    {"name": "EnrollAgent", "published_on": ["CORP-CA"], "ekus": ["1.3.6.1.4.1.311.20.2.1"], "enroll_principals": [DU]},
    {
        "name": "WritableTpl",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.1"],
        "enroll_principals": [DA],
        "write_principals": [AU],
    },
    {
        "name": "NoSecExt",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "enrollment_flags": 524288,
        "enroll_principals": [DU],
    },
    {
        "name": "WebServer",
        "schema_version": 1,
        "published_on": ["LEGACY-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.1"],
        "name_flags": 1,
        "enroll_principals": [DU],
    },
    {
        "name": "PolicyLinked",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "issuance_policies": ["1.3.6.1.4.1.311.21.8.111.222.333"],
        "enroll_principals": [DU],
    },
    {
        "name": "ApprovalRequired",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "name_flags": 1,
        "enrollment_flags": 2,
        "enroll_principals": [DU],
    },
    {
        "name": "WeakKey",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.5.5.7.3.1"],
        "key_size": 1024,
        "enroll_principals": [DA],
    },
    {
        "name": "Unpublished",
        "published_on": [],
        "ekus": ["1.3.6.1.5.5.7.3.2"],
        "name_flags": 1,
        "enroll_principals": [DU],
    },
    {
        "name": "LongAuth",
        "published_on": ["CORP-CA"],
        "ekus": ["1.3.6.1.4.1.311.20.2.2"],
        "validity_days": 1825,
        "enroll_principals": [DA],
    },
]


def vulnerable() -> dict:
    admins_extra = [
        user(
            f"adm{i:02d}",
            1600 + i,
            admin_count=True,
            member_of=[DA, f"{D}-525"],
            in_protected_users=True,
            sensitive_no_delegation=True,
        )
        for i in range(1, 10)
    ]
    fillers = [user(f"user{i:03d}", 2000 + i) for i in range(1, 56)]
    users = [
        user(
            "Administrator",
            500,
            admin_count=True,
            member_of=[DA, "S-1-5-32-544"],
            pwd_last_set="2020-01-01T00:00:00Z",
            mail="admin@corp.local",
            password_never_expires=True,
        ),
        user("Guest", 501, primary_group_id=514, member_of=[f"{D}-514"]),
        user("krbtgt", 502, enabled=False, spns=["kadmin/changepw"]),
        user("krbtgt_12345", 1501, enabled=False),
        user("krbtgt_99999", 1502, enabled=False),
        user("svc_sql_admin", 1101, admin_count=True, spns=["MSSQLSvc/sql01.corp.local:1433"], member_of=[DA]),
        user(
            "adm_old",
            1111,
            admin_count=True,
            member_of=[DA],
            last_logon=OLD,
            dont_require_preauth=True,
            pwd_last_set="2026-06-01T00:00:00Z",
            unicode_pwd_last_change="2023-01-01T00:00:00Z",
        ),
        user("svc_web", 1102, spns=["HTTP/intranet.corp.local"], supported_enc_types=4),
        user(
            "j.doe",
            1103,
            dont_require_preauth=True,
            upn="svc_web@corp.local",
            pwd_last_set="2026-10-01T00:00:00Z",
            unicode_pwd_last_change="2026-01-01T00:00:00Z",
        ),
        user("old.user", 1104, last_logon=OLD, password_never_expires=True, pwd_not_required=True),
        user("backup_op", 1106),
        user(
            "m.martin",
            1107,
            alt_security_identities=["X509:<RFC822>m.martin@corp.local"],
            reversible_encryption=True,
            use_des_only=True,
        ),
        user("a.strong", 1108, alt_security_identities=["X509:<I>DC=local,DC=corp,CN=CORP-CA<SR>1a2b3c4d"]),
        user("hidden.admin", 1112, primary_group_id=512, sid_history=[f"{D}-1105"]),
        user("migrated.user", 1113, sid_history=["S-1-5-21-9999-9999-9999-1500", f"{TRUSTED}-512"]),
        user("ex.admin", 1114, admin_count=True),
        user("$DUPLICATE-1f2a", 1115),
        user("CORP$$$", 1116),
        user("unix.user", 1117, has_unix_password=True),
        user("sc.user", 1118, smartcard_required=True, pwd_last_set="2024-01-01T00:00:00Z"),
        user("spn.trick", 1119, spns=["HTTP/intranet​.corp.local"]),
        user("deleg.user", 1120, allowed_to_delegate_to=["krbtgt/CORP.LOCAL", "cifs/ghost.corp.local"]),
        user("script.user", 1121, script_path="\\\\partner.local\\netlogon\\logon.bat"),
        user("helpdesk.lead", 1400),
        user("dev1", 1401),
        *admins_extra,
        *fillers,
    ]
    computers = [
        comp(
            "DC01",
            1000,
            is_dc=True,
            os="Windows Server 2012 R2 Datacenter",
            os_build=9600,
            ip="10.0.0.10",
            owner_sid=f"{D}-1103",
            pwd_last_set="2026-08-01T00:00:00Z",
            last_update="2026-05-01T00:00:00Z",
            registration_issues=["Objet NTDS Settings absent"],
            allowed_to_delegate_to=["cifs/fs01.corp.local"],
            primary_group_id=516,
            laps=False,
        ),
        comp(
            "DC02",
            1001,
            is_dc=True,
            os="Windows Server 2025 Datacenter",
            os_build=26100,
            ip="10.0.1.11",
            rbcd_principals=[f"{D}-1105"],
            allowed_to_delegate_to=["ldap/dc01.corp.local"],
            protocol_transition=True,
            last_logon="2026-08-01T00:00:00Z",
            primary_group_id=516,
            laps=False,
        ),
        comp(
            "RODC01",
            1002,
            is_dc=True,
            is_rodc=True,
            os="Windows Server 2022 Standard",
            os_build=20348,
            ip="10.0.1.12",
            reveal_on_demand_sids=[DA],
            revealed_sids=[f"{D}-1101"],
            rodc_sysvol_write=True,
            primary_group_id=521,
            laps=False,
        ),
        comp("WS01", 1105, os="Windows 11 Pro", os_build=26100, creator_sid=f"{D}-1103", primary_group_id=515),
        comp(
            "SRV-OLD",
            1109,
            os="Windows Server 2012 R2 Standard",
            os_build=9600,
            trusted_for_delegation=True,
            laps=False,
            last_logon="2026-03-01T08:00:00Z",
            pwd_last_set="2026-03-01T08:00:00Z",
        ),
        comp("PC-45", 1130, pwd_last_set="2026-09-01T00:00:00Z"),
        comp("PC-90", 1131, pwd_last_set="2026-06-01T00:00:00Z", reversible_encryption=True, primary_group_id=512),
        comp(
            "CLUSTER01",
            1132,
            os="Windows Server 2022 Standard",
            os_build=20348,
            spns=["MSClusterVirtualServer/cluster01"],
            pwd_last_set="2026-01-01T00:00:00Z",
        ),
        comp("SRV2016", 1133, os="Windows Server 2016 Standard", os_build=14393),
        comp("PC-MISMATCH", 1134, dns_hostname="dc01.corp.local"),
        comp("AZUREADSSOACC", 1135, os=None, os_build=None, pwd_last_set="2025-01-01T00:00:00Z", laps=False),
    ]
    groups = [
        {"sid": f"{D}-518", "name": "Schema Admins", "members": [f"{D}-500"]},
        {"sid": "S-1-5-32-548", "name": "Account Operators", "members": [f"{D}-1103"]},
        {"sid": f"{D}-1150", "name": "DnsAdmins", "members": [f"{D}-1102"]},
        {"sid": f"{D}-571", "name": "Allowed RODC Password Replication Group", "members": [f"{D}-1104"]},
        {"sid": f"{D}-572", "name": "Denied RODC Password Replication Group", "members": [DA, DC_GRP]},
        {"sid": f"{D}-525", "name": "Protected Users", "members": [f"{D}-{1600 + i}" for i in range(1, 10)]},
        {"sid": f"{D}-1200", "name": "PKI-Admins", "members": []},
        {"sid": f"{D}-1300", "name": "Exchange Windows Permissions", "members": []},
        {"sid": f"{D}-1500", "name": "Helpdesk", "members": [f"{D}-1400"]},
    ]
    gpos = [
        {
            "guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "name": "Default Domain Policy",
            "linked_to": ["DC=corp,DC=local"],
            "applies_to_domain": True,
            "writers": [AU],
            "security": {
                "System Access": {
                    "MinimumPasswordLength": "7",
                    "ClearTextPassword": "1",
                    "LSAAnonymousNameLookup": "1",
                },
                "Privilege Rights": {"SeDebugPrivilege": f"*{AU}", "SeTrustedCredManAccessPrivilege": f"*{D}-1102"},
            },
            "registry": {
                LSA + r"\nolmhash": 0,
                LSA + r"\limitblankpassworduse": 0,
                LSA + r"\restrictanonymous": 0,
                WU + r"\wuserver": "http://wsus.corp.local:8530",
                WU + r"\setproxybehaviorforupdatedetection": 1,
                WU + r"\donotenforceenterprisetlscertpinningforupdatedetection": 1,
                r"machine\software\microsoft\windows nt\currentversion\setup\recoveryconsole\securitylevel": 1,
                r"machine\software\policies\microsoft\windows\networkprovider\hardenedpaths\\\\*\sysvol": "RequireMutualAuthentication=0, RequireIntegrity=0",
            },
            "local_group_members": {"S-1-5-32-544": [DU]},
            "scripts": [{"path": "\\\\corp.local\\netlogon\\map.bat", "writers": [AU]}],
            "files": [{"path": "\\\\partner.local\\share\\agent.msi", "writers": [EVERYONE]}],
            "cpassword_files": ["{31B2F340}\\Machine\\Preferences\\Groups\\Groups.xml"],
        },
        {
            "guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
            "name": "Default Domain Controllers Policy",
            "linked_to": ["OU=Domain Controllers,DC=corp,DC=local"],
            "applies_to_dcs": True,
            "security": {"Privilege Rights": {"SeInteractiveLogonRight": f"*{AU},*S-1-5-32-544"}},
            "registry": {
                LSA + r"\lmcompatibilitylevel": 3,
                r"machine\system\currentcontrolset\services\ntds\parameters\ldapserverintegrity": 0,
                r"machine\system\currentcontrolset\services\netlogon\parameters\refusepasswordchange": 1,
            },
            "audit": {"Audit Logon": 1},
        },
        {
            "guid": "{11111111-2222-3333-4444-555555555555}",
            "name": "Workstations",
            "linked_to": ["OU=Workstations,DC=corp,DC=local"],
            "security": {"System Access": {"MinimumPasswordLength": "4"}},
        },
    ]
    return {
        "schema_version": "2",
        "collected_at": NOW,
        "collector": "fixture-vulnerable",
        "domain": {
            "name": "corp.local",
            "netbios": "CORP",
            "sid": D,
            "functional_level": 7,
            "forest_functional_level": 6,
            "machine_account_quota": 10,
            "krbtgt_pwd_last_set": "2022-03-01T00:00:00Z",
            "recycle_bin": False,
            "ds_heuristics": ds_heuristics(p3="1", p7="2", p8="1", p16="1", p21="1", p28="2"),
            "min_pwd_length": 7,
            "psos": [],
            "last_backup": "2026-09-01T00:00:00Z",
            "sysvol_replication": "ntfrs",
            "subnets": ["10.0.1.0/24"],
            "default_users_container": "OU=NewUsers,DC=corp,DC=local",
            "java_schema": True,
            "vulnerable_schema_classes": ["customComputer"],
            "unprotected_ous": ["OU=Paris,DC=corp,DC=local"],
            "display_specifier_actions": ["\\\\tools.other.local\\admin\\menu.exe"],
            "smartcard_pwd_rotation": False,
            "protected_users_exists": True,
            "exchange_present": True,
            "pre2k_compat_members": [ANON, AU, f"{D}-1104"],
        },
        "users": users,
        "computers": computers,
        "groups": groups,
        "trusts": [
            {
                "target": "partner.local",
                "sid": TRUSTED,
                "sid_filtering": False,
                "tgt_delegation": True,
                "aes_enabled": False,
                "last_change": "2026-01-01T00:00:00Z",
            },
            {"target": "LEGACYNT4", "trust_type": 1, "direction": "outbound", "last_change": RECENT},
        ],
        "acl_edges": [
            edge(f"{D}-1106", "corp.local", "DS-Replication-Get-Changes-All", "domain"),
            edge(DC_GRP, "corp.local", "DS-Replication-Get-Changes-All", "domain"),
            edge(AU, "OU=Paris,DC=corp,DC=local", "GenericAll", "ou"),
            edge(f"{D}-1500", "OU=Paris,DC=corp,DC=local", "AllExtendedRights", "ou"),
            edge(f"{D}-1500", "OU=Paris,DC=corp,DC=local", "CreateChild-dMSA", "ou"),
            edge(f"{D}-1102", "CN=MicrosoftDNS,DC=DomainDnsZones", "GenericWrite", "dns"),
            edge(f"{D}-1300", "corp.local", "WriteDacl", "domain"),
            edge(f"{D}-1300", "CN=AdminSDHolder", "WriteDacl", "adminsdholder"),
            edge(f"{D}-1103", "CN=AdminSDHolder", "GenericAll", "adminsdholder"),
            edge(f"{D}-526", "corp.local", "WriteProperty", "domain"),
            edge(AU, "helpdesk.lead", "GenericWrite", "user", f"{D}-1400"),
            edge(DU, "helpdesk.lead", "GenericAll", "user", f"{D}-1400"),
            edge(f"{D}-1400", "Domain Admins", "AddMember", "group", DA),
        ],
        "gpos": gpos,
        "dns_zones": [
            {
                "name": "corp.local",
                "critical": True,
                "dynamic_update": "nonsecure_and_secure",
                "authenticated_users_create_child": True,
            },
            {"name": "_msdcs.corp.local", "critical": True, "zone_transfer": True},
            {"name": "test.corp.local", "dynamic_update": "nonsecure_and_secure"},
        ],
        "dc_probes": [
            {
                "name": "DC01",
                "smb1": True,
                "smb_signing_enabled": False,
                "smb_signing_required": False,
                "ldap_signing_required": False,
                "ldaps_channel_binding_required": False,
                "ldaps_protocols": ["SSLv3", "TLSv1", "TLSv1.2"],
                "spooler": True,
                "webclient": True,
                "coerce_interfaces": ["MS-EFSR", "MS-DFSNM"],
                "null_session": True,
                "anonymous_bind": True,
                "net_session_enum_open": True,
                "ms17_010": True,
                "ms14_068": True,
            },
        ],
        "tls_probes": [{"host": "wsus.corp.local", "port": 8531, "service": "wsus", "protocols": ["TLSv1", "TLSv1.2"]}],
        "pki": {
            "cas": [
                {
                    "name": "CORP-CA",
                    "dns_host": "ca01.corp.local",
                    "edit_flags": 262144,
                    "interface_flags": 1601,
                    "web_enrollment_https": True,
                    "web_enrollment_epa": True,
                    "manage_ca_principals": [DA],
                    "cert_key_size": 4096,
                    "cert_signature_algorithm": "sha256",
                    "cert_not_after": "2035-01-01T00:00:00Z",
                    "patched_cve_2024_49019": True,
                },
                {
                    "name": "LEGACY-CA",
                    "dns_host": "ca02.corp.local",
                    "edit_flags": 0,
                    "interface_flags": 0,
                    "web_enrollment_http": True,
                    "disabled_extensions": ["1.3.6.1.4.1.311.25.2"],
                    "manage_ca_principals": [AU],
                    "cert_key_size": 1024,
                    "cert_signature_algorithm": "sha1",
                    "cert_not_after": "2027-01-15T00:00:00Z",
                    "patched_cve_2024_49019": False,
                },
            ],
            "templates": TEMPLATES_VULN,
            "certificates": [
                {
                    "subject": "CN=Old Root",
                    "store": "root",
                    "sig_hash": "md5",
                    "key_type": "rsa",
                    "key_size": 512,
                    "rsa_exponent": 3,
                },
                {
                    "subject": "CN=Legacy Issuing",
                    "store": "intermediate",
                    "sig_hash": "sha1",
                    "key_type": "rsa",
                    "key_size": 1536,
                    "rsa_exponent": 65537,
                },
                {"subject": "CN=DSA CA", "store": "ntauth", "sig_hash": "sha256", "key_type": "dsa", "key_size": 2048},
                {
                    "subject": "CN=Token CA",
                    "store": "ntauth",
                    "sig_hash": "sha256",
                    "key_type": "rsa",
                    "key_size": 2048,
                    "rsa_exponent": 65537,
                    "roca": True,
                },
            ],
            "oid_group_links": {"1.3.6.1.4.1.311.21.8.111.222.333": f"{D}-1200"},
            "object_acl": [
                edge(AU, "CN=NTAuthCertificates", "0x40000"),
                edge(f"{D}-519", "CN=NTAuthCertificates", "0xf01ff"),
            ],
        },
        "dc_registry": {"strong_cert_binding_enforcement": 1, "certificate_mapping_methods": 24},
        "entra": entra_vulnerable(),
    }


def entra_user(i, upn, **kw):
    return {
        "id": f"u{i}",
        "upn": upn,
        "mfa_registered": kw.pop("mfa", True),
        "last_sign_in": kw.pop("last", RECENT),
        "created": "2024-01-01T00:00:00Z",
        **kw,
    }


def entra_vulnerable() -> dict:
    users = [entra_user(1, "ga1@corp.com", mfa=False, on_prem_synced=True)]
    users += [entra_user(i, f"ga{i}@contoso.onmicrosoft.com") for i in range(2, 8)]
    users += [
        entra_user(20, "partner@ext.com", user_type="Guest"),
        entra_user(21, "dormant@corp.com", last="2026-01-01T00:00:00Z"),
        entra_user(22, "oldguest@ext.com", user_type="Guest", last=None),
        entra_user(23, "victim@corp.com", risk_level="high", risk_state="atRisk"),
        entra_user(24, "dev1@corp.com"),
    ]
    users += [entra_user(30 + i, f"staff{i}@corp.com", mfa=i > 2) for i in range(10)]
    assignments = [
        {"role": "Global Administrator", "role_template_id": GA, "principal_id": f"u{i}"} for i in range(1, 8)
    ]
    assignments += [
        {"role": "Security Administrator", "role_template_id": SEC_ADMIN, "principal_id": "u20"},
        {
            "role": "Global Administrator",
            "role_template_id": GA,
            "principal_id": "sp1",
            "principal_type": "servicePrincipal",
        },
    ]
    return {
        "tenant_id": "00000000-0000-0000-0000-00000000c0de",
        "name": "contoso",
        "security_defaults": False,
        "users_can_register_apps": True,
        "users_can_consent": True,
        "users_can_create_tenants": True,
        "guest_role": "same_as_member",
        "guest_invite_from": "everyone",
        "federated_domains": ["corp.com"],
        "connect_version": "1.6.4.0",
        "pim_available": True,
        "users": users,
        "role_assignments": assignments,
        "apps": [
            {
                "id": "app1",
                "app_id": "a1",
                "name": "OldAutomation",
                "graph_app_permissions": ["RoleManagement.ReadWrite.Directory"],
                "owners": ["u24"],
                "credentials": [{"kind": "password", "start": "2024-01-01T00:00:00Z", "end": "2029-01-01T00:00:00Z"}],
            },
            {
                "id": "sp2",
                "app_id": "a2",
                "name": "Mailer",
                "kind": "servicePrincipal",
                "graph_app_permissions": ["Mail.Send"],
                "credentials": [
                    {"kind": "certificate", "start": "2024-01-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"}
                ],
            },
            {
                "id": "sp3",
                "app_id": "a3",
                "name": "SP-Persist",
                "kind": "servicePrincipal",
                "credentials": [{"kind": "password", "start": "2026-10-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"}],
            },
            {"id": "sp1", "app_id": "a4", "name": "BackupApp", "kind": "servicePrincipal"},
        ],
        "ca_policies": [
            {
                "name": "MFA pilote",
                "state": "enabledForReportingButNotEnforced",
                "include_users": ["All"],
                "grant_controls": ["mfa"],
            }
        ],
    }


# ============================================================================ domaine durci
def hardened() -> dict:
    admins = [
        user(
            f"t0adm{i}",
            1600 + i,
            admin_count=True,
            member_of=[DA, f"{D}-525"],
            in_protected_users=True,
            sensitive_no_delegation=True,
        )
        for i in range(1, 4)
    ]
    users = [
        user(
            "Administrator",
            500,
            admin_count=True,
            member_of=[DA, "S-1-5-32-544"],
            sensitive_no_delegation=True,
            last_logon="2026-06-01T00:00:00Z",
        ),
        user("Guest", 501, enabled=False, primary_group_id=514, member_of=[f"{D}-514"]),
        user("krbtgt", 502, enabled=False),
        user("alice", 1101),
        user("bob", 1102, upn="bob@corp.local"),
        user("svc_app", 1103, supported_enc_types=24, member_of=[DU]),  # SPN porté par une gMSA
        *admins,
    ]
    computers = [
        comp(
            "DC01",
            1000,
            is_dc=True,
            os="Windows Server 2025 Datacenter",
            os_build=26100,
            ip="10.0.1.10",
            owner_sid=DA,
            primary_group_id=516,
            last_update="2026-10-15T00:00:00Z",
            laps=False,
        ),
        comp(
            "DC02",
            1001,
            is_dc=True,
            os="Windows Server 2025 Datacenter",
            os_build=26100,
            ip="10.0.1.11",
            owner_sid=DA,
            primary_group_id=516,
            last_update="2026-10-15T00:00:00Z",
            laps=False,
        ),
        comp("WS01", 1105, primary_group_id=515),
    ]
    reg_ok = {
        r"machine\software\microsoft\windows\currentversion\policies\system\kerberos\parameters\enablecbacandarmor": 1,
        r"machine\software\policies\microsoft\windows nt\dnsclient\enablemulticast": 0,
        r"machine\software\policies\microsoft\windows nt\terminal services\userauthentication": 1,
        r"machine\software\policies\microsoft\windows\powershell\scriptblocklogging\enablescriptblocklogging": 1,
        **{ASR_KEY + "\\" + r: 1 for r in ASR},
    }
    gpos = [
        {
            "guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "name": "Default Domain Policy",
            "linked_to": ["DC=corp,DC=local"],
            "applies_to_domain": True,
            "writers": [DA],
            "security": {"System Access": {"MinimumPasswordLength": "14", "ClearTextPassword": "0"}},
            "registry": reg_ok,
            "folder_options": {e: "notepad.exe" for e in ["js", "jse", "vbs", "vbe", "wsf", "wsh", "hta"]},
            "firewall_rules": [
                {"action": "Block", "dir": "Out", "app": f"%SystemRoot%\\system32\\{x}"}
                for x in ["wscript.exe", "cscript.exe", "mshta.exe"]
            ],
            "scripts": [{"path": "\\\\corp.local\\netlogon\\map.bat", "writers": [DA]}],
        },
        {
            "guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
            "name": "Default Domain Controllers Policy",
            "linked_to": ["OU=Domain Controllers,DC=corp,DC=local"],
            "applies_to_dcs": True,
            "security": {"Privilege Rights": {"SeInteractiveLogonRight": "*S-1-5-32-544"}},
            "registry": {
                LSA + r"\lmcompatibilitylevel": 5,
                r"machine\system\currentcontrolset\services\ntds\parameters\ldapserverintegrity": 2,
                r"machine\software\microsoft\windows\currentversion\policies\system\kdc\parameters\enablecbacandarmor": 1,
            },
            "audit": {s: 3 for s in AUDIT},
        },
        {
            "guid": "{22222222-3333-4444-5555-666666666666}",
            "name": "Tiering - postes",
            "linked_to": ["OU=Workstations,DC=corp,DC=local"],
            "security": {
                "Privilege Rights": {
                    "SeDenyInteractiveLogonRight": f"*{DA}",
                    "SeDenyRemoteInteractiveLogonRight": f"*{DA}",
                }
            },
        },
    ]
    return {
        "schema_version": "2",
        "collected_at": NOW,
        "collector": "fixture-hardened",
        "domain": {
            "name": "corp.local",
            "netbios": "CORP",
            "sid": D,
            "functional_level": 10,
            "forest_functional_level": 10,
            "machine_account_quota": 0,
            "krbtgt_pwd_last_set": "2026-08-01T00:00:00Z",
            "recycle_bin": True,
            "ds_heuristics": None,
            "min_pwd_length": 14,
            "psos": [{"name": "Services", "min_length": 24}],
            "last_backup": "2026-10-31T00:00:00Z",
            "sysvol_replication": "dfsr",
            "subnets": ["10.0.1.0/24"],
            "default_users_container": "CN=Users,DC=corp,DC=local",
            "smartcard_pwd_rotation": True,
            "pre2k_compat_members": [],
        },
        "users": users,
        "computers": computers,
        "groups": [
            {"sid": f"{D}-518", "name": "Schema Admins", "members": []},
            {
                "sid": f"{D}-572",
                "name": "Denied RODC Password Replication Group",
                "members": [f"{D}-{r}" for r in (512, 516, 517, 518, 519, 520, 521, 502)],
            },
            {"sid": f"{D}-525", "name": "Protected Users", "members": [a["sid"] for a in admins]},
        ],
        "trusts": [{"target": "partner.local", "sid": TRUSTED, "aes_enabled": True, "last_change": RECENT}],
        "acl_edges": [edge(DC_GRP, "corp.local", "DS-Replication-Get-Changes-All", "domain")],
        "gpos": gpos,
        "dns_zones": [{"name": "corp.local", "critical": True}, {"name": "_msdcs.corp.local", "critical": True}],
        "dc_probes": [
            {
                "name": n,
                "smb1": False,
                "smb_signing_enabled": True,
                "smb_signing_required": True,
                "ldap_signing_required": True,
                "ldaps_channel_binding_required": True,
                "ldaps_protocols": ["TLSv1.2", "TLSv1.3"],
                "spooler": False,
                "webclient": False,
                "coerce_interfaces": [],
                "null_session": False,
                "anonymous_bind": False,
                "net_session_enum_open": False,
                "ms17_010": False,
                "ms14_068": False,
            }
            for n in ("DC01", "DC02")
        ],
        "tls_probes": [{"host": "wsus.corp.local", "port": 8531, "service": "wsus", "protocols": ["TLSv1.2"]}],
        "pki": {
            "cas": [
                {
                    "name": "CORP-CA",
                    "dns_host": "ca01.corp.local",
                    "edit_flags": 0,
                    "interface_flags": 1601,
                    "web_enrollment_https": True,
                    "web_enrollment_epa": True,
                    "manage_ca_principals": [DA],
                    "cert_key_size": 4096,
                    "cert_signature_algorithm": "sha256",
                    "cert_not_after": "2035-01-01T00:00:00Z",
                    "patched_cve_2024_49019": True,
                }
            ],
            "templates": [
                {
                    "name": "CorpUser",
                    "published_on": ["CORP-CA"],
                    "ekus": ["1.3.6.1.5.5.7.3.2"],
                    "enroll_principals": [DU],
                    "write_principals": [DA],
                    "owner_sid": f"{D}-519",
                }
            ],
            "certificates": [
                {
                    "subject": "CN=CORP-CA",
                    "store": "root",
                    "sig_hash": "sha256",
                    "key_type": "rsa",
                    "key_size": 4096,
                    "rsa_exponent": 65537,
                    "roca": False,
                }
            ],
        },
        "dc_registry": {"strong_cert_binding_enforcement": 2, "certificate_mapping_methods": 24},
        "entra": {
            "tenant_id": "00000000-0000-0000-0000-00000000beef",
            "name": "contoso",
            "security_defaults": False,
            "users_can_register_apps": False,
            "users_can_consent": False,
            "users_can_create_tenants": False,
            "guest_role": "restricted",
            "guest_invite_from": "adminsAndGuestInviters",
            "federated_domains": [],
            "connect_version": "2.5.3.0",
            "pim_available": True,
            "users": [entra_user(i, f"ga{i}@contoso.onmicrosoft.com") for i in range(1, 4)]
            + [entra_user(10 + i, f"staff{i}@corp.com", on_prem_synced=True) for i in range(5)],
            "role_assignments": [
                {"role": "Global Administrator", "role_template_id": GA, "principal_id": "u1"},
                {"role": "Global Administrator", "role_template_id": GA, "principal_id": "u2"},
                {
                    "role": "Global Administrator",
                    "role_template_id": GA,
                    "principal_id": "u3",
                    "assignment": "eligible",
                    "permanent": False,
                },
            ],
            "apps": [
                {
                    "id": "app1",
                    "app_id": "a1",
                    "name": "HR-Sync",
                    "graph_app_permissions": ["User.Read.All"],
                    "credentials": [
                        {"kind": "certificate", "start": "2026-05-01T00:00:00Z", "end": "2027-05-01T00:00:00Z"}
                    ],
                }
            ],
            "ca_policies": [
                {"name": "MFA admins", "state": "enabled", "include_roles": [GA], "grant_controls": ["mfa"]},
                {"name": "MFA tous", "state": "enabled", "include_users": ["All"], "grant_controls": ["mfa"]},
                {
                    "name": "Bloquer legacy",
                    "state": "enabled",
                    "include_users": ["All"],
                    "client_app_types": ["exchangeActiveSync", "other"],
                    "grant_controls": ["block"],
                },
            ],
        },
    }


if __name__ == "__main__":
    here = Path(__file__).parent
    for name, data in (("vulnerable_snapshot.json", vulnerable()), ("hardened_snapshot.json", hardened())):
        (here / name).write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
        print("écrit", here / name)
