"""Constantes Active Directory / ADCS (SIDs bien connus, OIDs EKU, flags).

Toutes les valeurs viennent de la documentation Microsoft (MS-ADTS, MS-CRTD, MS-CSRA).
"""

# --- SIDs bien connus -------------------------------------------------------
SID_EVERYONE = "S-1-1-0"
SID_ANONYMOUS = "S-1-5-7"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_ENTERPRISE_DCS = "S-1-5-9"
SID_SYSTEM = "S-1-5-18"
SID_BUILTIN_ADMINS = "S-1-5-32-544"
SID_BUILTIN_USERS = "S-1-5-32-545"
SID_BUILTIN_GUESTS = "S-1-5-32-546"
SID_ACCOUNT_OPERATORS = "S-1-5-32-548"
SID_SERVER_OPERATORS = "S-1-5-32-549"
SID_PRINT_OPERATORS = "S-1-5-32-550"
SID_BACKUP_OPERATORS = "S-1-5-32-551"
SID_PRE2K = "S-1-5-32-554"
OPERATOR_GROUPS = (SID_ACCOUNT_OPERATORS, SID_SERVER_OPERATORS, SID_PRINT_OPERATORS, SID_BACKUP_OPERATORS)

# RIDs relatifs au domaine
RID_ADMINISTRATOR = 500
RID_GUEST = 501
RID_GPO_CREATOR_OWNERS = 520
RID_RODCS = 521
RID_PROTECTED_USERS = 525
RID_KEY_ADMINS = 526
RID_ENTERPRISE_KEY_ADMINS = 527
RID_RODC_ALLOWED = 571
RID_RODC_DENIED = 572
RID_DOMAIN_ADMINS = 512
RID_DOMAIN_USERS = 513
RID_DOMAIN_GUESTS = 514
RID_DOMAIN_COMPUTERS = 515
RID_DOMAIN_CONTROLLERS = 516
RID_CERT_PUBLISHERS = 517
RID_SCHEMA_ADMINS = 518
RID_ENTERPRISE_ADMINS = 519
RID_ENTERPRISE_RODCS = 498
RID_KRBTGT = 502

LOW_PRIV_WELL_KNOWN = {
    SID_EVERYONE,
    SID_ANONYMOUS,
    SID_AUTHENTICATED_USERS,
    SID_BUILTIN_USERS,
    SID_BUILTIN_GUESTS,
}
LOW_PRIV_RIDS = {RID_DOMAIN_USERS, RID_DOMAIN_GUESTS, RID_DOMAIN_COMPUTERS}

TIER0_WELL_KNOWN = {SID_SYSTEM, SID_BUILTIN_ADMINS, SID_ENTERPRISE_DCS, *OPERATOR_GROUPS}
TIER0_RIDS = {
    RID_DOMAIN_ADMINS,
    RID_DOMAIN_CONTROLLERS,
    RID_SCHEMA_ADMINS,
    RID_ENTERPRISE_ADMINS,
    RID_ENTERPRISE_RODCS,
}

# --- EKU (Extended Key Usage) ----------------------------------------------
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

AUTH_EKUS = {EKU_CLIENT_AUTH, EKU_PKINIT_CLIENT_AUTH, EKU_SMART_CARD_LOGON, EKU_ANY_PURPOSE}

EKU_NAMES = {
    EKU_CLIENT_AUTH: "Client Authentication",
    EKU_PKINIT_CLIENT_AUTH: "PKINIT Client Authentication",
    EKU_SMART_CARD_LOGON: "Smart Card Logon",
    EKU_ANY_PURPOSE: "Any Purpose",
    EKU_CERT_REQUEST_AGENT: "Certificate Request Agent",
    EKU_SERVER_AUTH: "Server Authentication",
}

# --- Flags des modèles de certificats (MS-CRTD) ------------------------------
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001  # msPKI-Certificate-Name-Flag
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002  # msPKI-Enrollment-Flag (approbation manager)
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000  # msPKI-Enrollment-Flag (ESC9)

# --- Flags de l'autorité de certification (MS-CSRA) --------------------------
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # EditFlags (ESC6)
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200  # InterfaceFlags (ESC11)
SZOID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"  # extension SID (ESC16)

# --- Droits étendus / GUIDs -------------------------------------------------
GUID_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
GUID_DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

# --- Masques d'accès --------------------------------------------------------
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
FULL_CONTROL = 0x000F01FF

# --- userAccountControl -----------------------------------------------------
UAC_ACCOUNTDISABLE = 0x00000002
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x00000080
UAC_DONT_EXPIRE_PASSWORD = 0x00010000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_NOT_DELEGATED = 0x00100000
UAC_USE_DES_KEY_ONLY = 0x00200000
UAC_DONT_REQ_PREAUTH = 0x00400000
UAC_SERVER_TRUST_ACCOUNT = 0x00002000  # contrôleur de domaine

# Mappings explicites altSecurityIdentities considérés faibles (KB5014754 / ESC14)
WEAK_EXPLICIT_MAPPING_PREFIXES = ("X509:<I>", "X509:<S>", "X509:<RFC822>")
STRONG_EXPLICIT_MAPPING_MARKERS = ("<SR>", "<SKI>", "<SHA1-PUKEY>")

# --- Kerberos : msDS-SupportedEncryptionTypes ---------------------------------
ENC_DES_CBC_CRC = 0x1
ENC_DES_CBC_MD5 = 0x2
ENC_RC4 = 0x4
ENC_AES128 = 0x8
ENC_AES256 = 0x10

# --- dsHeuristics (position 1-based, cf. MS-ADTS 6.1.1.2.4.1.2) ---------------
DSH_DO_LIST_OBJECT = 3
DSH_BLOCK_ANON_OPS = 7  # '2' = opérations anonymes autorisées
DSH_ALLOW_ANON_NSPI = 8
DSH_ADMINSD_EXMASK = 16
DSH_DONT_VERIFY_UNIQUENESS = 21
DSH_LDAP_ADD_AUTHZ = 28  # CVE-2021-42291 : '2' = protection désactivée
DSH_LDAP_OWNER_MODIFY = 29

# --- Privilèges dangereux (GptTmpl.inf [Privilege Rights]) --------------------
DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeTcbPrivilege",
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeImpersonatePrivilege",
    "SeSecurityPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeRelabelPrivilege",
    "SeManageVolumePrivilege",
}
DC_LOGON_RIGHTS = {
    "SeInteractiveLogonRight",
    "SeRemoteInteractiveLogonRight",
    "SeNetworkLogonRight",
    "SeBatchLogonRight",
    "SeServiceLogonRight",
}

# --- Entra ID ------------------------------------------------------------------
ENTRA_ROLE_GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
ENTRA_PRIVILEGED_ROLES = {
    ENTRA_ROLE_GLOBAL_ADMIN: "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
}
ENTRA_GUEST_ROLES = {
    "a0b1b346-4d3e-4e8b-98f8-753987be4970": "same_as_member",
    "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited",
    "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted",
}
# Permissions Graph (application) permettant une élévation vers Global Admin ou un accès massif
GRAPH_DANGEROUS_APP_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory": "critical",
    "AppRoleAssignment.ReadWrite.All": "critical",
    "Application.ReadWrite.All": "critical",
    "Directory.ReadWrite.All": "critical",
    "Domain.ReadWrite.All": "critical",
    "Policy.ReadWrite.ConditionalAccess": "high",
    "User.ReadWrite.All": "high",
    "Group.ReadWrite.All": "high",
    "UserAuthenticationMethod.ReadWrite.All": "high",
    "Mail.ReadWrite": "high",
    "Mail.Send": "high",
    "Files.ReadWrite.All": "high",
    "Sites.FullControl.All": "high",
}
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
