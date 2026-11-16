"""Collecteur LDAP en LECTURE SEULE (ldap3 + impacket pour les descripteurs de sécurité).

Un compte utilisateur standard du domaine suffit. Produit la partie annuaire du ``Snapshot`` :
domaine, comptes, groupes, approbations, ACL des objets sensibles (domaine, OU, AdminSDHolder,
objets Tier 0, DNS, GPO), PKI (CA, modèles, certificats de confiance), zones DNS, RODC.

Les GPO (SYSVOL) sont lues par ``sysvol_collector`` et les sondes réseau par ``probes``.

⚠ Non validé contre un vrai domaine : à tester sur le lab (phase 1 : failles connues du lab + Certipy).
"""

from __future__ import annotations

import logging
import struct
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import constants as c
from ..models import (
    PKI,
    AclEdge,
    CertificateAuthority,
    CertInfo,
    CertTemplate,
    Computer,
    DcRegistry,
    DnsZone,
    DomainInfo,
    Group,
    Pso,
    Snapshot,
    Trust,
    User,
)

log = logging.getLogger(__name__)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
ATTR_UNICODE_PWD = 0x9005A
ATTR_DSA_SIGNATURE = 0x2004A
GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_FORCE_CHANGE_PWD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_DMSA_CLASS = "0feb936f-47b3-49f2-9386-1dedc2c23765"  # msDS-DelegatedManagedServiceAccount (à vérifier)
ADS_RIGHT_DS_CREATE_CHILD = 0x1
DELETE, DELETE_TREE = 0x10000, 0x40


# =============================================================================== utilitaires


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    value = value if value.tzinfo else value.replace(tzinfo=UTC)
    return None if value <= EPOCH_1601 + timedelta(days=1) else value


def _first(attrs: dict, name: str, default: Any = None) -> Any:
    v = attrs.get(name, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v if v not in (None, "") else default


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def sid_from_bytes(raw: bytes | None) -> str | None:
    if not raw or len(raw) < 8:
        return None
    rev, count = raw[0], raw[1]
    auth = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack("<" + "I" * count, raw[8 : 8 + 4 * count])
    return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)


def parse_repl_metadata(raw: bytes | None) -> dict[int, datetime]:
    """replPropertyMetaData (MS-DRSR REPL_PROPERTY_META_DATA_VECTOR v1) -> {attrtyp: date de modification}."""
    out: dict[int, datetime] = {}
    if not raw or len(raw) < 16:
        return out
    (count,) = struct.unpack_from("<I", raw, 8)
    for i in range(count):
        off = 16 + i * 48
        if off + 16 > len(raw):
            break
        attrtyp, _version, seconds = struct.unpack_from("<IIq", raw, off)
        out[attrtyp] = EPOCH_1601 + timedelta(seconds=seconds)
    return out


def parse_sd(raw: bytes) -> tuple[str | None, list[tuple[str, int, str | None]], list[tuple[str, int]]]:
    """Retourne (owner, ACE allow [(sid, mask, guid)], ACE deny [(sid, mask)])."""
    from impacket.ldap.ldaptypes import (
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
        SR_SECURITY_DESCRIPTOR,
    )
    from impacket.uuid import bin_to_string

    sd = SR_SECURITY_DESCRIPTOR(data=raw)
    owner = sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else None
    allow, deny = [], []
    if not sd["Dacl"]:
        return owner, allow, deny
    for ace in sd["Dacl"].aces:
        body = ace["Ace"]
        if ace["AceType"] == ACCESS_DENIED_ACE.ACE_TYPE:
            deny.append((body["Sid"].formatCanonical(), body["Mask"]["Mask"]))
            continue
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue
        guid = None
        if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and (
            body["Flags"] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        ):
            guid = bin_to_string(body["ObjectType"]).lower()
        allow.append((body["Sid"].formatCanonical(), body["Mask"]["Mask"], guid))
    return owner, allow, deny


def ace_rights(mask: int, guid: str | None) -> list[str]:
    """Traduit une ACE en noms de droits utilisés par les règles."""
    rights = []
    if mask & c.ADS_RIGHT_GENERIC_ALL or (mask & c.FULL_CONTROL) == c.FULL_CONTROL:
        return ["GenericAll"]
    if mask & c.ADS_RIGHT_GENERIC_WRITE:
        rights.append("GenericWrite")
    if mask & c.ADS_RIGHT_WRITE_DAC:
        rights.append("WriteDacl")
    if mask & c.ADS_RIGHT_WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & c.ADS_RIGHT_DS_WRITE_PROP:
        rights.append("AddMember" if guid == GUID_MEMBER else "WriteProperty" if guid is None else "")
    if mask & c.ADS_RIGHT_DS_CONTROL_ACCESS:
        rights.append(
            {
                None: "AllExtendedRights",
                GUID_FORCE_CHANGE_PWD: "User-Force-Change-Password",
                c.GUID_DS_REPLICATION_GET_CHANGES_ALL: "DS-Replication-Get-Changes-All",
            }.get(guid, "")
        )
    if mask & ADS_RIGHT_DS_CREATE_CHILD:
        rights.append("CreateChild-dMSA" if guid == GUID_DMSA_CLASS else "CreateChild" if guid is None else "")
    return [r for r in rights if r]


def _is_write(mask: int, guid: str | None) -> bool:
    return bool(
        set(ace_rights(mask, guid)) & {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"}
    )


def _is_enroll(mask: int, guid: str | None) -> bool:
    if mask & c.ADS_RIGHT_GENERIC_ALL or (mask & c.FULL_CONTROL) == c.FULL_CONTROL:
        return True
    if mask & c.ADS_RIGHT_DS_CONTROL_ACCESS:
        return guid in (None, c.GUID_CERTIFICATE_ENROLLMENT, c.GUID_CERTIFICATE_AUTOENROLLMENT)
    return False


def cert_info(der: bytes, subject_store: str) -> CertInfo | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

        cert = x509.load_der_x509_certificate(der)
        key = cert.public_key()
        key_type = (
            "rsa"
            if isinstance(key, rsa.RSAPublicKey)
            else "dsa"
            if isinstance(key, dsa.DSAPublicKey)
            else "ec"
            if isinstance(key, ec.EllipticCurvePublicKey)
            else None
        )
        oid = cert.signature_algorithm_oid._name.lower()
        sig = next((h for h in ("md2", "md4", "md5", "sha1", "sha256", "sha384", "sha512") if h in oid), oid)
        return CertInfo(
            subject=cert.subject.rfc4514_string(),
            store=subject_store,
            sig_hash=sig,
            key_type=key_type,
            key_size=getattr(key, "key_size", None),
            rsa_exponent=key.public_numbers().e if key_type == "rsa" else None,
            not_after=cert.not_valid_after_utc,
        )
    except Exception as exc:
        log.warning("Certificat illisible (%s) : %s", subject_store, exc)
        return None


# =============================================================================== collecteur


class LdapCollector:
    def __init__(self, dc: str, domain: str, username: str, password: str, use_ldaps: bool = False):
        self.dc, self.domain, self.username, self.password = dc, domain, username, password
        self.use_ldaps = use_ldaps
        self.conn = None
        self.dn_to_sid: dict[str, str] = {}
        self.missing_attributes: set[str] = set()  # absents du schéma : non collectés (inconnu ≠ vulnérable)

    # -- connexion -------------------------------------------------------------
    def connect(self) -> None:
        from ldap3 import ALL, NTLM, Connection, Server

        server = Server(self.dc, use_ssl=self.use_ldaps, get_info=ALL)
        self.conn = Connection(
            server,
            user=f"{self.domain}\\{self.username}",
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
            read_only=True,
        )
        info = server.info.other
        self.base_dn = info["defaultNamingContext"][0]
        self.config_dn = info["configurationNamingContext"][0]
        self.schema_dn = info["schemaNamingContext"][0]
        root = info.get("rootDomainNamingContext", [None])[0]
        self.forest = ".".join(p.split("=", 1)[1] for p in root.split(",")) if root else None
        self.pks_dn = f"CN=Public Key Services,CN=Services,{self.config_dn}"

    def _known_attributes(self, attrs: list[str]) -> list[str]:
        """Retire les attributs absents du schéma du domaine (extension non installée, ex. LAPS historique).

        ldap3 refuse toute la requête si un seul attribut est inconnu ; l'attribut retiré reste non collecté
        et les règles qui en dépendent le traitent comme absent.
        """
        schema = getattr(getattr(self.conn, "server", None), "schema", None)
        types = getattr(schema, "attribute_types", None)
        if not types:
            return attrs
        keep = []
        for a in attrs:
            if a in ("*", "+") or a in types:
                keep.append(a)
            elif a not in self.missing_attributes:
                self.missing_attributes.add(a)
                log.info("Attribut absent du schéma, non collecté : %s", a)
        return keep

    def _search(
        self, base: str, flt: str, attrs: list[str], with_sd: bool = False, scope: str = "SUBTREE"
    ) -> list[dict]:
        from ldap3 import BASE, SUBTREE
        from ldap3.core.exceptions import LDAPNoSuchObjectResult
        from ldap3.protocol.microsoft import security_descriptor_control

        controls = security_descriptor_control(sdflags=0x07) if with_sd else None
        if with_sd:
            attrs = [*attrs, "nTSecurityDescriptor"]
        attrs = self._known_attributes(attrs)
        out = []
        try:
            gen = self.conn.extend.standard.paged_search(
                base,
                flt,
                search_scope=BASE if scope == "BASE" else SUBTREE,
                attributes=attrs,
                controls=controls,
                paged_size=500,
                generator=True,
            )
            for e in gen:
                if e.get("type") == "searchResEntry":
                    out.append({"dn": e["dn"], "a": e["attributes"], "raw": e["raw_attributes"]})
        except LDAPNoSuchObjectResult:
            return []
        return out

    def _sd(self, entry: dict):
        raw = _first(entry["raw"], "nTSecurityDescriptor")
        return parse_sd(raw) if raw else (None, [], [])

    def _edges(self, entry: dict, target: str, ttype: str, target_sid: str | None = None) -> list[AclEdge]:
        owner, allow, _ = self._sd(entry)
        edges = [
            AclEdge(principal_sid=s, target=target, right=r, target_type=ttype, target_sid=target_sid)
            for s, m, g in allow
            for r in ace_rights(m, g)
        ]
        if owner:
            edges.append(
                AclEdge(principal_sid=owner, target=target, right="Owner", target_type=ttype, target_sid=target_sid)
            )
        return edges

    # -- collecte --------------------------------------------------------------
    def collect(self) -> Snapshot:
        if self.conn is None:
            self.connect()
        dom = self._search(
            self.base_dn,
            "(objectClass=domain)",
            [
                "objectSid",
                "ms-DS-MachineAccountQuota",
                "msDS-Behavior-Version",
                "minPwdLength",
                "lockoutThreshold",
                "nETBIOSName",
                "wellKnownObjects",
                "msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
                "replPropertyMetaData",
            ],
            with_sd=True,
            scope="BASE",
        )[0]
        self.domain_sid = str(_first(dom["a"], "objectSid"))

        groups, members_raw = self._groups()
        users = self._users(groups)
        computers = self._computers(groups)
        group_models = [
            Group(sid=sid, name=name, members=[self._resolve(m) for m in members_raw[sid]])
            for sid, name in groups["names"].items()
        ]
        acl = self._edges(dom, self.domain, "domain") + self._sensitive_acls(users)
        domain = self._domain_info(dom, users, groups)
        self._fill_rodc(computers)

        return Snapshot(
            collected_at=datetime.now(UTC),
            collector="ldap",
            domain=domain,
            users=users,
            computers=computers,
            groups=group_models,
            trusts=self._trusts(),
            intra_forest_trusts=self._trusts(within_forest=True),
            acl_edges=acl,
            dns_zones=self._dns_zones(),
            pki=self._pki(groups),
            dc_registry=DcRegistry(),
            gpos=None,
        )

    def gpo_writers(self) -> dict[str, list[str]]:
        """{dn GPO: [SIDs pouvant la modifier]} — utilisé par le collecteur SYSVOL."""
        out = {}
        for e in self._search(
            f"CN=Policies,CN=System,{self.base_dn}", "(objectClass=groupPolicyContainer)", ["cn"], with_sd=True
        ):
            owner, allow, _ = self._sd(e)
            out[e["dn"].lower()] = sorted({s for s, m, g in allow if _is_write(m, g)} | ({owner} if owner else set()))
        return out

    def _resolve(self, dn_or_sid: str) -> str:
        if dn_or_sid.upper().startswith("CN=S-1-"):
            return dn_or_sid.split(",")[0][3:]
        return self.dn_to_sid.get(dn_or_sid.lower(), dn_or_sid)

    # -- groupes et comptes ----------------------------------------------------
    def _groups(self) -> tuple[dict, dict[str, list[str]]]:
        entries = self._search(self.base_dn, "(objectClass=group)", ["objectSid", "member", "sAMAccountName"])
        names, members = {}, {}
        parents: dict[str, set[str]] = defaultdict(set)
        for e in entries:
            sid = str(_first(e["a"], "objectSid"))
            self.dn_to_sid[e["dn"].lower()] = sid
            names[sid] = str(_first(e["a"], "sAMAccountName", sid))
            members[sid] = _as_list(e["a"].get("member"))
            for m in members[sid]:
                parents[m.lower()].add(sid)
        sid_to_dn = {v: k for k, v in self.dn_to_sid.items()}
        return {"names": names, "parents": parents, "sid_to_dn": sid_to_dn}, members

    @staticmethod
    def _transitive(dn: str, primary_sid: str | None, groups: dict) -> list[str]:
        seen: set[str] = set()
        stack = list(groups["parents"].get(dn.lower(), set())) + ([primary_sid] if primary_sid else [])
        while stack:
            sid = stack.pop()
            if sid in seen:
                continue
            seen.add(sid)
            gdn = groups["sid_to_dn"].get(sid)
            if gdn:
                stack.extend(groups["parents"].get(gdn, set()))
        return sorted(seen)

    def _users(self, groups: dict) -> list[User]:
        attrs = [
            "sAMAccountName",
            "objectSid",
            "userAccountControl",
            "adminCount",
            "servicePrincipalName",
            "lastLogonTimestamp",
            "pwdLastSet",
            "primaryGroupID",
            "altSecurityIdentities",
            "userPrincipalName",
            "mail",
            "msDS-AllowedToDelegateTo",
            "msDS-SupportedEncryptionTypes",
            "sIDHistory",
            "scriptPath",
            "whenCreated",
            "unixUserPassword",
            "userPassword",
            "replPropertyMetaData",
        ]
        protected = f"{self.domain_sid}-{c.RID_PROTECTED_USERS}"
        out = []
        for e in self._search(self.base_dn, "(&(objectCategory=person)(objectClass=user))", attrs):
            a, raw = e["a"], e["raw"]
            sid = str(_first(a, "objectSid"))
            self.dn_to_sid[e["dn"].lower()] = sid
            uac = int(_first(a, "userAccountControl", 0))
            pg = int(_first(a, "primaryGroupID", 513))
            member_of = self._transitive(e["dn"], f"{self.domain_sid}-{pg}", groups)
            meta = parse_repl_metadata(_first(raw, "replPropertyMetaData"))
            out.append(
                User(
                    sam=str(_first(a, "sAMAccountName")),
                    sid=sid,
                    dn=e["dn"],
                    upn=_first(a, "userPrincipalName"),
                    mail=_first(a, "mail"),
                    enabled=not uac & c.UAC_ACCOUNTDISABLE,
                    admin_count=int(_first(a, "adminCount", 0) or 0) == 1,
                    spns=_as_list(a.get("servicePrincipalName")),
                    dont_require_preauth=bool(uac & c.UAC_DONT_REQ_PREAUTH),
                    password_never_expires=bool(uac & c.UAC_DONT_EXPIRE_PASSWORD),
                    pwd_not_required=bool(uac & 0x20),
                    reversible_encryption=bool(uac & c.UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
                    use_des_only=bool(uac & c.UAC_USE_DES_KEY_ONLY),
                    smartcard_required=bool(uac & 0x40000),
                    trusted_for_delegation=bool(uac & c.UAC_TRUSTED_FOR_DELEGATION),
                    protocol_transition=bool(uac & 0x1000000),
                    allowed_to_delegate_to=_as_list(a.get("msDS-AllowedToDelegateTo")),
                    sensitive_no_delegation=bool(uac & c.UAC_NOT_DELEGATED),
                    in_protected_users=protected in member_of,
                    supported_enc_types=_first(a, "msDS-SupportedEncryptionTypes"),
                    has_unix_password=bool(_first(raw, "unixUserPassword") or _first(raw, "userPassword")),
                    primary_group_id=pg,
                    sid_history=[s for s in map(sid_from_bytes, _as_list(raw.get("sIDHistory"))) if s],
                    script_path=_first(a, "scriptPath"),
                    created=_dt(_first(a, "whenCreated")),
                    last_logon=_dt(_first(a, "lastLogonTimestamp")),
                    pwd_last_set=_dt(_first(a, "pwdLastSet")),
                    unicode_pwd_last_change=meta.get(ATTR_UNICODE_PWD),
                    member_of=member_of,
                    alt_security_identities=_as_list(a.get("altSecurityIdentities")),
                )
            )
        return out

    def _computers(self, groups: dict) -> list[Computer]:
        attrs = [
            "sAMAccountName",
            "objectSid",
            "userAccountControl",
            "operatingSystem",
            "operatingSystemVersion",
            "lastLogonTimestamp",
            "pwdLastSet",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-PasswordExpirationTime",
            "dNSHostName",
            "primaryGroupID",
            "msDS-AllowedToDelegateTo",
            "servicePrincipalName",
            "sIDHistory",
            "msDS-SupportedEncryptionTypes",
            "ms-DS-CreatorSID",
            "serverReferenceBL",
        ]
        out = []
        dc_ou = f"OU=Domain Controllers,{self.base_dn}".lower()
        for e in self._search(self.base_dn, "(objectCategory=computer)", attrs):
            a, raw = e["a"], e["raw"]
            sid = str(_first(a, "objectSid"))
            self.dn_to_sid[e["dn"].lower()] = sid
            uac = int(_first(a, "userAccountControl", 0))
            rbcd_raw = _first(raw, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            version = str(_first(a, "operatingSystemVersion", "") or "")
            build = (
                int(version.split("(")[1].rstrip(")"))
                if "(" in version and version.split("(")[1][:-1].isdigit()
                else None
            )
            is_dc = bool(uac & c.UAC_SERVER_TRUST_ACCOUNT) or bool(uac & 0x4000000)
            issues = []
            if is_dc and not _first(a, "serverReferenceBL"):
                issues.append("serverReferenceBL absent (objet serveur/NTDS Settings manquant)")
            if is_dc and not e["dn"].lower().endswith(dc_ou):
                issues.append("hors de l'OU Domain Controllers")
            comp = Computer(
                name=str(_first(a, "sAMAccountName", "")).rstrip("$"),
                sid=sid,
                dn=e["dn"],
                dns_hostname=_first(a, "dNSHostName"),
                enabled=not uac & c.UAC_ACCOUNTDISABLE,
                os=_first(a, "operatingSystem"),
                os_build=build,
                is_dc=is_dc,
                is_rodc=bool(uac & 0x4000000),
                creator_sid=sid_from_bytes(_first(raw, "ms-DS-CreatorSID")),
                primary_group_id=_first(a, "primaryGroupID"),
                last_logon=_dt(_first(a, "lastLogonTimestamp")),
                pwd_last_set=_dt(_first(a, "pwdLastSet")),
                reversible_encryption=bool(uac & c.UAC_ENCRYPTED_TEXT_PWD_ALLOWED),
                trusted_for_delegation=bool(uac & c.UAC_TRUSTED_FOR_DELEGATION) and not is_dc,
                protocol_transition=bool(uac & 0x1000000),
                allowed_to_delegate_to=_as_list(a.get("msDS-AllowedToDelegateTo")),
                rbcd_principals=[s for s, _, _ in parse_sd(rbcd_raw)[1]] if rbcd_raw else [],
                spns=_as_list(a.get("servicePrincipalName")),
                sid_history=[s for s in map(sid_from_bytes, _as_list(raw.get("sIDHistory"))) if s],
                supported_enc_types=_first(a, "msDS-SupportedEncryptionTypes"),
                laps=bool(_first(raw, "ms-Mcs-AdmPwdExpirationTime") or _first(raw, "msLAPS-PasswordExpirationTime")),
                registration_issues=issues,
            )
            out.append(comp)
        for comp in out:  # propriétaire des objets DC (recherche ciblée)
            if comp.is_dc and comp.dn:
                res = self._search(comp.dn, "(objectClass=*)", ["cn"], with_sd=True, scope="BASE")
                comp.owner_sid = self._sd(res[0])[0] if res else None
        return out

    def _fill_rodc(self, computers: list[Computer]) -> None:
        for comp in [x for x in computers if x.is_rodc and x.dn]:
            res = self._search(
                comp.dn,
                "(objectClass=*)",
                ["msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedList"],
                scope="BASE",
            )
            if not res:
                continue
            a = res[0]["a"]
            comp.reveal_on_demand_sids = [self._resolve(d) for d in _as_list(a.get("msDS-RevealOnDemandGroup"))]
            comp.never_reveal_sids = [self._resolve(d) for d in _as_list(a.get("msDS-NeverRevealGroup"))]
            comp.revealed_sids = [
                self._resolve(str(v).rsplit(":", 1)[-1]) for v in _as_list(a.get("msDS-RevealedList"))
            ]

    # -- ACL sensibles -----------------------------------------------------------
    def _sensitive_acls(self, users: list[User]) -> list[AclEdge]:
        edges: list[AclEdge] = []
        for e in self._search(self.base_dn, "(objectClass=organizationalUnit)", ["ou"], with_sd=True):
            edges += self._edges(e, e["dn"], "ou")
        for e in self._search(
            f"CN=AdminSDHolder,CN=System,{self.base_dn}", "(objectClass=*)", ["cn"], with_sd=True, scope="BASE"
        ):
            edges += self._edges(e, "CN=AdminSDHolder", "adminsdholder")
        for e in self._search(f"DC=DomainDnsZones,{self.base_dn}", "(objectClass=container)", ["cn"], with_sd=True):
            if e["dn"].upper().startswith("CN=MICROSOFTDNS"):
                edges += self._edges(e, e["dn"], "dns")
        # objets Tier 0 (groupes et comptes privilégiés) pour les chemins de contrôle
        tier0_dns = [
            dn
            for dn, sid in self.dn_to_sid.items()
            if sid in {f"{self.domain_sid}-{r}" for r in (512, 518, 519)} | {c.SID_BUILTIN_ADMINS}
        ]
        tier0_dns += [u.dn for u in users if u.admin_count and u.dn]
        for dn in tier0_dns:
            for e in self._search(dn, "(objectClass=*)", ["objectSid"], with_sd=True, scope="BASE"):
                edges += self._edges(e, dn, "tier0", str(_first(e["a"], "objectSid")))
        return [x for x in edges if x.principal_sid not in (c.SID_SYSTEM,)]

    # -- domaine ----------------------------------------------------------------
    def _domain_info(self, dom: dict, users: list[User], groups: dict) -> DomainInfo:
        a = dom["a"]
        wko = {
            str(v).split(":")[2].upper(): str(v).split(":", 3)[3]
            for v in _as_list(a.get("wellKnownObjects"))
            if str(v).count(":") >= 3
        }
        krbtgt = next((u for u in users if u.sam.lower() == "krbtgt"), None)
        ds = self._search(
            f"CN=Directory Service,CN=Windows NT,CN=Services,{self.config_dn}",
            "(objectClass=*)",
            ["dSHeuristics"],
            scope="BASE",
        )
        part = self._search(
            f"CN=Partitions,{self.config_dn}", "(objectClass=*)", ["msDS-Behavior-Version"], scope="BASE"
        )
        rb = self._search(
            f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{self.config_dn}",
            "(cn=Recycle Bin Feature)",
            ["msDS-EnabledFeatureBL"],
        )
        dfsr = self._search(
            f"CN=DFSR-GlobalSettings,CN=System,{self.base_dn}", "(objectClass=*)", ["msDFSR-Flags"], scope="BASE"
        )
        psos = [
            Pso(
                name=str(_first(p["a"], "cn")),
                min_length=int(_first(p["a"], "msDS-MinimumPasswordLength", 0)),
                applies_to=[self._resolve(d) for d in _as_list(p["a"].get("msDS-PSOAppliesTo"))],
            )
            for p in self._search(
                f"CN=Password Settings Container,CN=System,{self.base_dn}",
                "(objectClass=msDS-PasswordSettings)",
                ["cn", "msDS-MinimumPasswordLength", "msDS-PSOAppliesTo"],
            )
        ]
        subnets = [
            str(_first(s["a"], "cn"))
            for s in self._search(f"CN=Subnets,CN=Sites,{self.config_dn}", "(objectClass=subnet)", ["cn"])
        ]
        ous = self._search(self.base_dn, "(objectClass=organizationalUnit)", ["ou"], with_sd=True)
        unprotected = [
            o["dn"]
            for o in ous
            if not any(s == c.SID_EVERYONE and m & (DELETE | DELETE_TREE) for s, m in self._sd(o)[2])
        ]
        actions = []
        for ds_entry in self._search(
            f"CN=DisplaySpecifiers,{self.config_dn}", "(adminContextMenu=*)", ["adminContextMenu"]
        ):
            actions += [str(v).split(",", 2)[-1] for v in _as_list(ds_entry["a"].get("adminContextMenu"))]
        meta = parse_repl_metadata(_first(dom["raw"], "replPropertyMetaData"))
        flags = int(_first(dfsr[0]["a"], "msDFSR-Flags", 0) or 0) if dfsr else 0
        return DomainInfo(
            name=self.domain,
            sid=self.domain_sid,
            netbios=_first(a, "nETBIOSName"),
            forest=getattr(self, "forest", None),
            functional_level=int(_first(a, "msDS-Behavior-Version", 0)),
            forest_functional_level=int(_first(part[0]["a"], "msDS-Behavior-Version", 0)) if part else None,
            machine_account_quota=int(_first(a, "ms-DS-MachineAccountQuota", 10)),
            krbtgt_pwd_last_set=krbtgt.pwd_last_set if krbtgt else None,
            recycle_bin=bool(rb and _as_list(rb[0]["a"].get("msDS-EnabledFeatureBL"))),
            ds_heuristics=_first(ds[0]["a"], "dSHeuristics") if ds else None,
            min_pwd_length=int(_first(a, "minPwdLength", 0)) if _first(a, "minPwdLength") is not None else None,
            lockout_threshold=(
                int(_first(a, "lockoutThreshold")) if _first(a, "lockoutThreshold") is not None else None
            ),
            psos=psos,
            last_backup=meta.get(ATTR_DSA_SIGNATURE),
            sysvol_replication="dfsr" if flags >= 48 else "ntfrs" if dfsr or flags else None,
            subnets=subnets,
            default_users_container=wko.get("A9D1CA15768811D1ADED00C04FD8D5CD"),
            default_computers_container=wko.get("AA312825768811D1ADED00C04FD8D5CD"),
            java_schema=bool(self._search(self.schema_dn, "(cn=javaClassName)", ["cn"])),
            unprotected_ous=unprotected,
            display_specifier_actions=actions,
            smartcard_pwd_rotation=_first(a, "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"),
            protected_users_exists=f"{self.domain_sid}-{c.RID_PROTECTED_USERS}" in groups["names"],
            exchange_present=bool(self._search(f"CN=Services,{self.config_dn}", "(cn=Microsoft Exchange)", ["cn"])),
            pre2k_compat_members=[self._resolve(m) for m in self._group_members_raw(c.SID_PRE2K, groups)],
        )

    def _group_members_raw(self, sid: str, groups: dict) -> list[str]:
        dn = groups["sid_to_dn"].get(sid)
        if not dn:
            return []
        res = self._search(dn, "(objectClass=*)", ["member"], scope="BASE")
        return _as_list(res[0]["a"].get("member")) if res else []

    def _trusts(self, within_forest: bool = False) -> list[Trust]:
        """Approbations sortant de la forêt (par défaut) ou internes à la forêt (within_forest=True)."""
        out = []
        for e in self._search(
            self.base_dn,
            "(objectClass=trustedDomain)",
            [
                "trustPartner",
                "trustDirection",
                "trustAttributes",
                "trustType",
                "securityIdentifier",
                "whenChanged",
                "msDS-SupportedEncryptionTypes",
            ],
        ):
            a, raw = e["a"], e["raw"]
            attrs = int(_first(a, "trustAttributes", 0))
            if bool(attrs & 0x20) != within_forest:  # WITHIN_FOREST : pas de filtrage SID par conception
                continue
            ttype = int(_first(a, "trustType", 2))
            kind = (
                "within_forest"
                if attrs & 0x20
                else "forest"
                if attrs & 0x8
                else "realm"
                if ttype == 3
                else "downlevel"
                if ttype == 1
                else "external"
            )
            sid_filtering = (not attrs & 0x40) if attrs & 0x8 else bool(attrs & 0x4)
            enc = _first(a, "msDS-SupportedEncryptionTypes")
            out.append(
                Trust(
                    target=str(_first(a, "trustPartner")),
                    sid=sid_from_bytes(_first(raw, "securityIdentifier")),
                    direction={1: "inbound", 2: "outbound", 3: "bidirectional"}.get(
                        int(_first(a, "trustDirection", 3))
                    ),
                    trust_type=ttype,
                    kind=kind,
                    sid_filtering=sid_filtering,
                    tgt_delegation=bool(attrs & 0x800),
                    last_change=_dt(_first(a, "whenChanged")),
                    aes_enabled=None if enc is None else bool(int(enc) & (c.ENC_AES128 | c.ENC_AES256)),
                )
            )
        return out

    # -- DNS ---------------------------------------------------------------------
    def _dns_zones(self) -> list[DnsZone] | None:
        zones = self._search(
            f"DC=DomainDnsZones,{self.base_dn}", "(objectClass=dnsZone)", ["name", "dnsProperty"], with_sd=True
        )
        zones += self._search(
            f"DC=ForestDnsZones,{self.base_dn}", "(objectClass=dnsZone)", ["name", "dnsProperty"], with_sd=True
        )
        if not zones:
            return None
        out = []
        for z in zones:
            name = str(_first(z["a"], "name"))
            if name in ("RootDNSServers", "..TrustAnchors") or name.endswith("in-addr.arpa"):
                continue
            update = "secure"
            for prop in _as_list(z["raw"].get("dnsProperty")):
                if len(prop) >= 21 and struct.unpack_from("<I", prop, 16)[0] == 0x02:  # DSPROPERTY_ZONE_ALLOW_UPDATE
                    update = {0: "none", 1: "nonsecure_and_secure", 2: "secure"}.get(prop[20], "secure")
            _, allow, _ = self._sd(z)
            au_child = any(s == c.SID_AUTHENTICATED_USERS and m & ADS_RIGHT_DS_CREATE_CHILD for s, m, _ in allow)
            out.append(
                DnsZone(
                    name=name,
                    critical=name.lower() in (self.domain.lower(), f"_msdcs.{self.domain.lower()}"),
                    dynamic_update=update,
                    authenticated_users_create_child=au_child,
                )
            )
        return out

    # -- PKI ---------------------------------------------------------------------
    def _pki(self, groups: dict) -> PKI:
        published: dict[str, list[str]] = defaultdict(list)
        cas = []
        for e in self._search(
            f"CN=Enrollment Services,{self.pks_dn}",
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "certificateTemplates", "cACertificate"],
        ):
            name = str(_first(e["a"], "cn"))
            for t in _as_list(e["a"].get("certificateTemplates")):
                published[t].append(name)
            ca = CertificateAuthority(name=name, dns_host=str(_first(e["a"], "dNSHostName", "")))
            if der := _first(e["raw"], "cACertificate"):
                info = cert_info(der, "ca")
                if info:
                    ca.cert_key_size, ca.cert_signature_algorithm, ca.cert_not_after = (
                        info.key_size,
                        info.sig_hash,
                        info.not_after,
                    )
            cas.append(ca)

        templates = [
            self._template(e, published)
            for e in self._search(
                f"CN=Certificate Templates,{self.pks_dn}",
                "(objectClass=pKICertificateTemplate)",
                [
                    "cn",
                    "displayName",
                    "msPKI-Template-Schema-Version",
                    "pKIExtendedKeyUsage",
                    "msPKI-Certificate-Application-Policy",
                    "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag",
                    "msPKI-RA-Signature",
                    "msPKI-Minimal-Key-Size",
                    "pKIExpirationPeriod",
                    "msPKI-Certificate-Policy",
                ],
                with_sd=True,
            )
        ]

        certificates: list[CertInfo] = []
        for base, store in (
            (f"CN=Certification Authorities,{self.pks_dn}", "root"),
            (f"CN=AIA,{self.pks_dn}", "intermediate"),
            (f"CN=NTAuthCertificates,{self.pks_dn}", "ntauth"),
        ):
            for e in self._search(base, "(cACertificate=*)", ["cACertificate"]):
                certificates += [ci for der in _as_list(e["raw"].get("cACertificate")) if (ci := cert_info(der, store))]

        links = {}
        for e in self._search(
            f"CN=OID,{self.pks_dn}", "(msDS-OIDToGroupLink=*)", ["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"]
        ):
            gdn = str(_first(e["a"], "msDS-OIDToGroupLink", "")).lower()
            if gdn in self.dn_to_sid:
                links[str(_first(e["a"], "msPKI-Cert-Template-OID"))] = self.dn_to_sid[gdn]

        object_acl = []
        for dn in (
            self.pks_dn,
            f"CN=NTAuthCertificates,{self.pks_dn}",
            f"CN=Enrollment Services,{self.pks_dn}",
            f"CN=Certificate Templates,{self.pks_dn}",
        ):
            for e in self._search(dn, "(objectClass=*)", ["cn"], with_sd=True, scope="BASE"):
                owner, allow, _ = self._sd(e)
                short = dn.split(",")[0]
                object_acl += [
                    AclEdge(principal_sid=s, target=short, right=hex(m)) for s, m, g in allow if _is_write(m, g)
                ]
                if owner:
                    object_acl.append(AclEdge(principal_sid=owner, target=short, right="Owner"))
        return PKI(
            cas=cas, templates=templates, certificates=certificates, oid_group_links=links, object_acl=object_acl
        )

    def _template(self, e: dict, published: dict[str, list[str]]) -> CertTemplate:
        a, raw = e["a"], e["raw"]
        name = str(_first(a, "cn"))
        app_policies = _as_list(a.get("msPKI-Certificate-Application-Policy"))
        owner, aces, _ = self._sd(e)
        period = _first(raw, "pKIExpirationPeriod")
        validity = int(-int.from_bytes(period, "little", signed=True) / (10**7 * 86400)) if period else 365
        return CertTemplate(
            name=name,
            display_name=_first(a, "displayName"),
            schema_version=int(_first(a, "msPKI-Template-Schema-Version", 1)),
            published_on=published.get(name, []),
            ekus=[str(x) for x in (app_policies or _as_list(a.get("pKIExtendedKeyUsage")))],
            name_flags=int(_first(a, "msPKI-Certificate-Name-Flag", 0)) & 0xFFFFFFFF,
            enrollment_flags=int(_first(a, "msPKI-Enrollment-Flag", 0)) & 0xFFFFFFFF,
            ra_signatures=int(_first(a, "msPKI-RA-Signature", 0) or 0),
            enroll_principals=sorted({s for s, m, g in aces if _is_enroll(m, g)}),
            write_principals=sorted({s for s, m, g in aces if _is_write(m, g)}),
            owner_sid=owner,
            issuance_policies=[str(x) for x in _as_list(a.get("msPKI-Certificate-Policy"))],
            key_size=int(_first(a, "msPKI-Minimal-Key-Size", 2048) or 2048),
            validity_days=validity,
        )
