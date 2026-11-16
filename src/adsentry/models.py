"""Modèles de données.

* ``Snapshot`` : photographie normalisée et en LECTURE SEULE d'un domaine AD et/ou d'un tenant
  Entra ID, produite par les collecteurs (LDAP, SYSVOL, sondes réseau, Microsoft Graph) ou par
  un import. Le moteur de règles ne travaille QUE sur ce modèle.
* ``Rule`` / ``Finding`` / ``ScanResult`` : catalogue et résultats.

Convention : ``None`` = donnée non collectée (inconnue). Une règle ne se déclenche jamais sur
une donnée inconnue.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from . import constants as c

# =============================================================================
# Active Directory
# =============================================================================


class User(BaseModel):
    sam: str
    sid: str
    dn: str | None = None
    upn: str | None = None
    mail: str | None = None
    enabled: bool = True
    admin_count: bool = False
    spns: list[str] = []
    dont_require_preauth: bool = False
    password_never_expires: bool = False
    pwd_not_required: bool = False
    reversible_encryption: bool = False
    use_des_only: bool = False
    smartcard_required: bool = False
    trusted_for_delegation: bool = False
    protocol_transition: bool = False
    allowed_to_delegate_to: list[str] = []
    sensitive_no_delegation: bool = False
    in_protected_users: bool = False
    supported_enc_types: int | None = None
    has_unix_password: bool = False
    primary_group_id: int = 513
    sid_history: list[str] = []
    script_path: str | None = None
    created: datetime | None = None
    last_logon: datetime | None = None
    pwd_last_set: datetime | None = None
    unicode_pwd_last_change: datetime | None = Field(
        None, description="Date de réplication de unicodePwd (métadonnées) : détecte les faux changements"
    )
    member_of: list[str] = Field(default_factory=list, description="SIDs des groupes (transitif)")
    alt_security_identities: list[str] = []


class Computer(BaseModel):
    name: str
    sid: str
    dn: str | None = None
    dns_hostname: str | None = None
    ip: str | None = None
    enabled: bool = True
    os: str | None = None
    os_build: int | None = None
    is_dc: bool = False
    is_rodc: bool = False
    owner_sid: str | None = None
    creator_sid: str | None = Field(None, description="ms-DS-CreatorSID : utilisateur ayant joint la machine")
    primary_group_id: int | None = None
    last_logon: datetime | None = None
    pwd_last_set: datetime | None = None
    reversible_encryption: bool = False
    trusted_for_delegation: bool = False
    protocol_transition: bool = False
    allowed_to_delegate_to: list[str] = []
    rbcd_principals: list[str] = Field(default_factory=list, description="msDS-AllowedToActOnBehalfOf")
    spns: list[str] = []
    sid_history: list[str] = []
    supported_enc_types: int | None = None
    laps: bool = False
    # Spécifique contrôleurs de domaine
    registration_issues: list[str] = []
    last_update: datetime | None = None
    # Spécifique RODC
    revealed_sids: list[str] = []
    reveal_on_demand_sids: list[str] = []
    never_reveal_sids: list[str] = []
    rodc_sysvol_write: bool | None = None


class Group(BaseModel):
    sid: str
    name: str
    members: list[str] = Field(default_factory=list, description="SIDs des membres directs")


class Trust(BaseModel):
    target: str
    sid: str | None = None
    direction: str = "bidirectional"  # inbound | outbound | bidirectional
    trust_type: int = 2  # 1 = downlevel (NT4), 2 = uplevel (AD), 3 = MIT
    sid_filtering: bool = True
    tgt_delegation: bool = False
    aes_enabled: bool | None = None
    last_change: datetime | None = None
    # forest | external | realm (Kerberos MIT) | downlevel (NT4) | within_forest ; None = non collecté
    kind: str | None = None


class AclEdge(BaseModel):
    """Un droit d'un principal sur un objet."""

    principal_sid: str
    target: str
    right: str
    target_type: str = "object"  # domain|ou|container|adminsdholder|gpo|dns|dnszone|template|dc|...
    target_sid: str | None = None  # renseigné quand la cible est un principal (pour les chemins de contrôle)


class Pso(BaseModel):
    name: str
    min_length: int
    applies_to: list[str] = []


class ScriptRef(BaseModel):
    path: str
    writers: list[str] | None = None  # None = ACL non lue


class Gpo(BaseModel):
    """GPO normalisée (GptTmpl.inf, Registry.pol, audit.csv, scripts, préférences)."""

    guid: str
    name: str
    enabled: bool = True
    linked_to: list[str] = []
    applies_to_dcs: bool = False
    applies_to_domain: bool = False
    writers: list[str] = Field(default_factory=list, description="SIDs pouvant modifier la GPO (LDAP)")
    security: dict[str, dict[str, str]] = Field(default_factory=dict, description="Sections de GptTmpl.inf")
    registry: dict[str, Any] = Field(default_factory=dict, description="HKLM\\chemin\\valeur -> donnée")
    audit: dict[str, int] = Field(default_factory=dict, description="Sous-catégorie d'audit -> 0..3")
    scripts: list[ScriptRef] = []
    files: list[ScriptRef] = []
    cpassword_files: list[str] = []
    local_group_members: dict[str, list[str]] = {}
    folder_options: dict[str, str] = {}
    firewall_rules: list[dict[str, str]] = []

    @property
    def is_effective(self) -> bool:
        return self.enabled and bool(self.linked_to)


class DnsZone(BaseModel):
    name: str
    critical: bool = False  # zone du domaine ou _msdcs
    dynamic_update: str = "secure"  # none | secure | nonsecure_and_secure
    zone_transfer: bool = False
    authenticated_users_create_child: bool = False


class DcProbe(BaseModel):
    """Résultats des sondes réseau en lecture seule sur un DC (None = non testé)."""

    name: str
    smb1: bool | None = None
    smb_signing_enabled: bool | None = None
    smb_signing_required: bool | None = None
    ldap_signing_required: bool | None = None
    ldaps_channel_binding_required: bool | None = None
    ldaps_protocols: list[str] | None = None
    spooler: bool | None = None
    webclient: bool | None = None
    coerce_interfaces: list[str] | None = None
    null_session: bool | None = None
    anonymous_bind: bool | None = None
    net_session_enum_open: bool | None = None
    ms17_010: bool | None = None
    ms14_068: bool | None = None


class TlsProbe(BaseModel):
    host: str
    port: int
    service: str  # wsus | ldaps | ...
    protocols: list[str]


class DomainInfo(BaseModel):
    name: str
    sid: str
    netbios: str | None = None
    forest: str | None = None  # nom DNS de la racine de forêt (None = non collecté)
    functional_level: int = 7  # 7 = 2016, 10 = 2025
    forest_functional_level: int | None = None
    machine_account_quota: int = 10
    krbtgt_pwd_last_set: datetime | None = None
    recycle_bin: bool = True
    ds_heuristics: str | None = None
    min_pwd_length: int | None = None
    lockout_threshold: int | None = None  # 0 = verrouillage désactivé ; None = non collecté
    psos: list[Pso] = []
    last_backup: datetime | None = None
    sysvol_replication: str | None = None  # dfsr | ntfrs
    subnets: list[str] = []
    default_users_container: str | None = None
    default_computers_container: str | None = None
    java_schema: bool = False
    vulnerable_schema_classes: list[str] = []
    unprotected_ous: list[str] = []
    display_specifier_actions: list[str] = []
    smartcard_pwd_rotation: bool | None = None
    protected_users_exists: bool = True
    exchange_present: bool = False
    pre2k_compat_members: list[str] = []


class CertTemplate(BaseModel):
    name: str
    display_name: str | None = None
    schema_version: int = 2
    published_on: list[str] = Field(default_factory=list, description="Noms des CA qui publient le modèle")
    ekus: list[str] = []
    name_flags: int = 0
    enrollment_flags: int = 0
    ra_signatures: int = 0
    enroll_principals: list[str] = Field(default_factory=list, description="SIDs avec droit Enroll/AutoEnroll")
    write_principals: list[str] = Field(default_factory=list, description="SIDs avec droit d'écriture")
    owner_sid: str | None = None
    issuance_policies: list[str] = []
    key_size: int = 2048
    validity_days: int = 365

    @property
    def enabled(self) -> bool:
        return bool(self.published_on)

    @property
    def enrollee_supplies_subject(self) -> bool:
        return bool(self.name_flags & c.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

    @property
    def requires_manager_approval(self) -> bool:
        return bool(self.enrollment_flags & c.CT_FLAG_PEND_ALL_REQUESTS)

    @property
    def no_security_extension(self) -> bool:
        return bool(self.enrollment_flags & c.CT_FLAG_NO_SECURITY_EXTENSION)

    @property
    def allows_authentication(self) -> bool:
        return not self.ekus or bool(set(self.ekus) & c.AUTH_EKUS)

    @property
    def any_purpose_or_no_eku(self) -> bool:
        return not self.ekus or c.EKU_ANY_PURPOSE in self.ekus


class CertificateAuthority(BaseModel):
    name: str
    dns_host: str
    edit_flags: int | None = None
    interface_flags: int | None = None
    web_enrollment_http: bool = False
    web_enrollment_https: bool = False
    web_enrollment_epa: bool | None = None
    disabled_extensions: list[str] = []
    manage_ca_principals: list[str] = []
    manage_certs_principals: list[str] = []
    cert_key_size: int | None = None
    cert_signature_algorithm: str | None = None
    cert_not_after: datetime | None = None
    patched_cve_2024_49019: bool | None = None


class CertInfo(BaseModel):
    """Certificat publié dans l'AD (racines, intermédiaires, NTAuth)."""

    subject: str
    store: str  # root | intermediate | ntauth
    sig_hash: str | None = None  # md2 | md4 | md5 | sha0 | sha1 | sha256 ...
    key_type: str | None = None  # rsa | dsa | ec
    key_size: int | None = None
    rsa_exponent: int | None = None
    not_after: datetime | None = None
    roca: bool | None = None


class PKI(BaseModel):
    cas: list[CertificateAuthority] = []
    templates: list[CertTemplate] = []
    certificates: list[CertInfo] = []
    oid_group_links: dict[str, str] = Field(
        default_factory=dict, description="OID de politique d'émission -> SID du groupe lié (ESC13)"
    )
    object_acl: list[AclEdge] = Field(
        default_factory=list, description="ACL dangereuses sur les objets PKI du Configuration NC (ESC5)"
    )


class DcRegistry(BaseModel):
    strong_cert_binding_enforcement: int | None = None  # 0 désactivé, 1 compat, 2 complet
    certificate_mapping_methods: int | None = None  # Schannel, 0x4 = mapping UPN


# =============================================================================
# Entra ID
# =============================================================================


class EntraUser(BaseModel):
    id: str
    upn: str
    enabled: bool = True
    user_type: str = "Member"  # Member | Guest
    on_prem_synced: bool = False
    on_prem_sid: str | None = None
    last_sign_in: datetime | None = None
    created: datetime | None = None
    mfa_registered: bool | None = None
    risk_level: str | None = None  # none | low | medium | high
    risk_state: str | None = None  # atRisk | remediated | dismissed ...


class EntraRoleAssignment(BaseModel):
    role: str  # nom du rôle (ex: Global Administrator)
    role_template_id: str
    principal_id: str
    principal_type: str = "user"  # user | group | servicePrincipal
    assignment: str = "active"  # active | eligible
    permanent: bool = True


class EntraCredential(BaseModel):
    kind: str  # password | certificate
    start: datetime | None = None
    end: datetime | None = None


class EntraApp(BaseModel):
    """Application (enregistrement) ou principal de service."""

    id: str
    app_id: str
    name: str
    kind: str = "application"  # application | servicePrincipal
    first_party: bool = False  # SP d'un éditeur Microsoft / tiers non géré par le tenant
    credentials: list[EntraCredential] = []
    graph_app_permissions: list[str] = Field(default_factory=list, description="Permissions Graph (application)")
    owners: list[str] = Field(default_factory=list, description="IDs des propriétaires")


class ConditionalAccessPolicy(BaseModel):
    name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    include_users: list[str] = []  # "All", IDs
    include_roles: list[str] = []  # template IDs
    exclude_users: list[str] = []
    client_app_types: list[str] = []  # all | browser | mobileAppsAndDesktopClients | exchangeActiveSync | other
    grant_controls: list[str] = []  # mfa | block | compliantDevice ...
    authentication_strength: str | None = None
    auth_flows: list[str] = []  # deviceCodeFlow | authenticationTransfer
    user_risk_levels: list[str] = []
    sign_in_risk_levels: list[str] = []


class EntraTenant(BaseModel):
    tenant_id: str
    name: str
    security_defaults: bool | None = None
    users_can_register_apps: bool | None = None
    users_can_consent: bool | None = None
    users_can_create_tenants: bool | None = None
    guest_role: str | None = None  # same_as_member | limited | restricted
    guest_invite_from: str | None = None  # none | adminsAndGuestInviters | adminsGuestInvitersAndAllMembers | everyone
    federated_domains: list[str] = []
    connect_version: str | None = None
    connect_last_sync: datetime | None = None
    pim_available: bool | None = None
    weak_auth_methods: list[str] | None = None  # méthodes SMS / appel vocal activées ; None = non lisible
    device_join_all_users: bool | None = None  # tous les utilisateurs peuvent joindre des appareils
    device_join_mfa_required: bool | None = None  # MFA exigée pour joindre ou inscrire un appareil
    users: list[EntraUser] = []
    role_assignments: list[EntraRoleAssignment] = []
    apps: list[EntraApp] = []
    ca_policies: list[ConditionalAccessPolicy] | None = None  # None = non lisible (licence/permission)


# =============================================================================
# Snapshot
# =============================================================================


class Snapshot(BaseModel):
    schema_version: str = "2"
    collected_at: datetime
    collector: str = "unknown"
    domain: DomainInfo | None = None
    users: list[User] = []
    computers: list[Computer] = []
    groups: list[Group] = []
    trusts: list[Trust] = []
    # Approbations internes à la forêt (parent-enfant, racine d'arbre) : topologie uniquement, aucune règle
    intra_forest_trusts: list[Trust] = []
    acl_edges: list[AclEdge] = []
    gpos: list[Gpo] | None = None  # None = SYSVOL non lu
    dns_zones: list[DnsZone] | None = None
    dc_probes: list[DcProbe] = []
    tls_probes: list[TlsProbe] = []
    pki: PKI = PKI()
    dc_registry: DcRegistry = DcRegistry()
    entra: EntraTenant | None = None

    # --- helpers de privilège -------------------------------------------------
    def rid(self, sid: str) -> int | None:
        if self.domain is None or not sid.startswith(self.domain.sid + "-"):
            return None
        try:
            return int(sid.rsplit("-", 1)[1])
        except ValueError:
            return None

    def is_low_privileged(self, sid: str) -> bool:
        return sid in c.LOW_PRIV_WELL_KNOWN or self.rid(sid) in c.LOW_PRIV_RIDS

    def is_tier0(self, sid: str) -> bool:
        if sid in c.TIER0_WELL_KNOWN or self.rid(sid) in c.TIER0_RIDS:
            return True
        return any(comp.sid == sid and comp.is_dc for comp in self.computers)

    def user_is_privileged(self, user: User) -> bool:
        return user.admin_count or any(self.is_tier0(g) for g in user.member_of)

    def principal_name(self, sid: str) -> str:
        for u in self.users:
            if u.sid == sid:
                return u.sam
        for comp in self.computers:
            if comp.sid == sid:
                return comp.name
        for g in self.groups:
            if g.sid == sid:
                return g.name
        return WELL_KNOWN_NAMES.get(sid) or _rid_name(self.rid(sid)) or sid

    def group(self, sid: str) -> Group | None:
        return next((g for g in self.groups if g.sid == sid), None)

    def dcs(self) -> list[Computer]:
        return [cp for cp in self.computers if cp.is_dc and cp.enabled]


WELL_KNOWN_NAMES = {
    c.SID_EVERYONE: "Everyone",
    c.SID_ANONYMOUS: "Anonymous Logon",
    c.SID_AUTHENTICATED_USERS: "Authenticated Users",
    c.SID_ENTERPRISE_DCS: "Enterprise Domain Controllers",
    c.SID_SYSTEM: "SYSTEM",
    c.SID_BUILTIN_ADMINS: "BUILTIN\\Administrators",
    c.SID_BUILTIN_USERS: "BUILTIN\\Users",
    c.SID_BUILTIN_GUESTS: "BUILTIN\\Guests",
    c.SID_ACCOUNT_OPERATORS: "Account Operators",
    c.SID_SERVER_OPERATORS: "Server Operators",
    c.SID_PRINT_OPERATORS: "Print Operators",
    c.SID_BACKUP_OPERATORS: "Backup Operators",
    c.SID_PRE2K: "Pre-Windows 2000 Compatible Access",
}


def _rid_name(rid: int | None) -> str | None:
    return (
        {
            c.RID_ADMINISTRATOR: "Administrator",
            c.RID_GUEST: "Guest",
            c.RID_KRBTGT: "krbtgt",
            c.RID_DOMAIN_ADMINS: "Domain Admins",
            c.RID_DOMAIN_USERS: "Domain Users",
            c.RID_DOMAIN_GUESTS: "Domain Guests",
            c.RID_DOMAIN_COMPUTERS: "Domain Computers",
            c.RID_DOMAIN_CONTROLLERS: "Domain Controllers",
            c.RID_CERT_PUBLISHERS: "Cert Publishers",
            c.RID_SCHEMA_ADMINS: "Schema Admins",
            c.RID_ENTERPRISE_ADMINS: "Enterprise Admins",
            c.RID_GPO_CREATOR_OWNERS: "Group Policy Creator Owners",
            c.RID_RODCS: "Read-only Domain Controllers",
            c.RID_KEY_ADMINS: "Key Admins",
            c.RID_ENTERPRISE_KEY_ADMINS: "Enterprise Key Admins",
            c.RID_PROTECTED_USERS: "Protected Users",
            c.RID_RODC_ALLOWED: "Allowed RODC Password Replication Group",
            c.RID_RODC_DENIED: "Denied RODC Password Replication Group",
        }.get(rid)
        if rid is not None
        else None
    )


# =============================================================================
# Règles et résultats
# =============================================================================


class Category(str, Enum):
    STALE = "stale_objects"
    PRIVILEGED = "privileged_accounts"
    TRUSTS = "trusts"
    ANOMALIES = "anomalies"
    PKI = "pki"
    ENTRA = "entra_id"


CATEGORY_LABELS = {
    Category.STALE: "Objets obsolètes",
    Category.PRIVILEGED: "Comptes à privilèges",
    Category.TRUSTS: "Relations d'approbation",
    Category.ANOMALIES: "Anomalies",
    Category.PKI: "PKI / Certificats (ADCS)",
    Category.ENTRA: "Entra ID",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class MitreRef(BaseModel):
    technique: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    relation: str = "primary"  # primary | related


class Rule(BaseModel):
    id: str
    category: Category
    title: str
    description: str
    severity: Severity
    points: int = Field(ge=0, le=100)
    mitre: list[MitreRef] = []
    remediation: str
    detection: str = ""
    references: list[str] = []
    check: str
    params: dict[str, Any] = {}
    manual: bool = False
    source: str = Field("ldap", description="Données nécessaires : ldap|gpo|probe|dns|graph|registry")

    @property
    def scope(self) -> str:
        return "entra" if self.category == Category.ENTRA else "ad"


class Finding(BaseModel):
    rule_id: str
    category: Category
    severity: Severity
    title: str
    description: str
    points: int
    affected: list[str]
    details: dict[str, Any] = {}
    mitre: list[MitreRef] = []
    remediation: str
    detection: str = ""


class TemplateClassification(BaseModel):
    template: str
    classe: str
    exposition: str
    risque: Severity
    esc: list[str] = []
    raisons: list[str] = []


class ScanResult(BaseModel):
    domain: str
    collected_at: datetime
    analyzed_at: datetime
    findings: list[Finding]
    scores: dict[Category, int]
    global_score: int
    pki_classification: list[TemplateClassification] = []
    manual_checks: list[str] = []
    not_evaluated: list[str] = Field(default_factory=list, description="Règles sans données (périmètre absent)")
