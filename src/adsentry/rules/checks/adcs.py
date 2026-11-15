"""Contrôles PKI / ADCS : ESC1 → ESC16 + hygiène cryptographique.

Références : SpecterOps « Certified Pre-Owned » (2021), wiki Certipy (ESC9–ESC16),
TrustedSec « EKUwu » (ESC15 / CVE-2024-49019), Microsoft KB5014754 (mapping fort).
Ces fonctions DÉTECTENT des mauvaises configurations ; elles n'exploitent rien.
"""

from __future__ import annotations

from datetime import timedelta

from ... import constants as c
from ...models import CertTemplate, Snapshot
from ..registry import CheckResult, check


def _low_priv(snap: Snapshot, sids: list[str]) -> list[str]:
    return [snap.principal_name(s) for s in sids if snap.is_low_privileged(s)]


def _enrollable_by_low_priv(snap: Snapshot, t: CertTemplate) -> list[str]:
    return _low_priv(snap, t.enroll_principals)


def _no_issuance_control(t: CertTemplate) -> bool:
    return not t.requires_manager_approval and t.ra_signatures == 0


def _template_result(snap: Snapshot, predicate) -> CheckResult:
    res = CheckResult()
    for t in snap.pki.templates:
        if not t.enabled or not _no_issuance_control(t):
            continue
        who = _enrollable_by_low_priv(snap, t)
        if who and predicate(t):
            res.affected.append(t.name)
            res.details[t.name] = {"inscription": who, "ca": t.published_on}
    return res


@check("adcs_esc1")
def esc1(snap: Snapshot, params: dict) -> CheckResult:
    return _template_result(snap, lambda t: t.enrollee_supplies_subject and t.allows_authentication)


@check("adcs_esc2")
def esc2(snap: Snapshot, params: dict) -> CheckResult:
    return _template_result(snap, lambda t: t.any_purpose_or_no_eku)


@check("adcs_esc3")
def esc3(snap: Snapshot, params: dict) -> CheckResult:
    return _template_result(snap, lambda t: c.EKU_CERT_REQUEST_AGENT in t.ekus)


@check("adcs_esc4")
def esc4(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for t in snap.pki.templates:
        writers = _low_priv(snap, t.write_principals)
        if t.owner_sid and snap.is_low_privileged(t.owner_sid):
            writers.append(f"{snap.principal_name(t.owner_sid)} (propriétaire)")
        if writers:
            res.affected.append(t.name)
            res.details[t.name] = {"ecriture": writers, "publie": t.enabled}
    return res


@check("adcs_esc5")
def esc5(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for edge in snap.pki.object_acl:
        if snap.is_low_privileged(edge.principal_sid):
            res.affected.append(edge.target)
            res.details.setdefault(edge.target, []).append(
                {"principal": snap.principal_name(edge.principal_sid), "droit": edge.right}
            )
    return res


@check("adcs_esc6")
def esc6(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        if ca.edit_flags is not None and ca.edit_flags & c.EDITF_ATTRIBUTESUBJECTALTNAME2:
            res.affected.append(ca.name)
    return res


@check("adcs_esc7")
def esc7(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        manage_ca = _low_priv(snap, ca.manage_ca_principals)
        manage_certs = _low_priv(snap, ca.manage_certs_principals)
        if manage_ca or manage_certs:
            res.affected.append(ca.name)
            res.details[ca.name] = {"ManageCA": manage_ca, "ManageCertificates": manage_certs}
    return res


@check("adcs_esc8")
def esc8(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        reasons = []
        if ca.web_enrollment_http:
            reasons.append("inscription web accessible en HTTP")
        if ca.web_enrollment_https and ca.web_enrollment_epa is False:
            reasons.append("HTTPS sans Extended Protection for Authentication (EPA)")
        if reasons:
            res.affected.append(ca.name)
            res.details[ca.name] = reasons
    return res


def _weak_binding(snap: Snapshot) -> bool | None:
    v = snap.dc_registry.strong_cert_binding_enforcement
    return None if v is None else v < 2


@check("adcs_esc9")
def esc9(snap: Snapshot, params: dict) -> CheckResult:
    res = _template_result(snap, lambda t: t.no_security_extension and t.allows_authentication)
    weak = _weak_binding(snap)
    if weak is False:  # mapping fort imposé : ESC9 non exploitable
        return CheckResult()
    res.details["_mapping_fort"] = "inconnu" if weak is None else "non imposé"
    return res


@check("adcs_esc10")
def esc10(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    reg = snap.dc_registry
    if reg.strong_cert_binding_enforcement in (0, 1):
        res.affected.append("Contrôleurs de domaine (Kerberos)")
        res.details["StrongCertificateBindingEnforcement"] = reg.strong_cert_binding_enforcement
    if reg.certificate_mapping_methods is not None and reg.certificate_mapping_methods & 0x4:
        res.affected.append("Contrôleurs de domaine (Schannel)")
        res.details["CertificateMappingMethods"] = hex(reg.certificate_mapping_methods)
    return res


@check("adcs_esc11")
def esc11(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        if ca.interface_flags is not None and not ca.interface_flags & c.IF_ENFORCEENCRYPTICERTREQUEST:
            res.affected.append(ca.name)
    return res


@check("adcs_esc13")
def esc13(snap: Snapshot, params: dict) -> CheckResult:
    links = snap.pki.oid_group_links

    def linked(t: CertTemplate) -> bool:
        return t.allows_authentication and any(p in links for p in t.issuance_policies)

    res = _template_result(snap, linked)
    for name in res.affected:
        t = next(t for t in snap.pki.templates if t.name == name)
        res.details[name]["groupes_lies"] = [snap.principal_name(links[p]) for p in t.issuance_policies if p in links]
    return res


@check("adcs_esc14")
def esc14(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for u in snap.users:
        weak = [
            m
            for m in u.alt_security_identities
            if m.startswith(c.WEAK_EXPLICIT_MAPPING_PREFIXES)
            and not any(s in m for s in c.STRONG_EXPLICIT_MAPPING_MARKERS)
        ]
        if weak:
            res.affected.append(u.sam)
            res.details[u.sam] = weak
    return res


@check("adcs_esc15")
def esc15(snap: Snapshot, params: dict) -> CheckResult:
    unpatched = {ca.name for ca in snap.pki.cas if ca.patched_cve_2024_49019 is not True}
    return _template_result(
        snap,
        lambda t: t.schema_version == 1 and t.enrollee_supplies_subject and bool(set(t.published_on) & unpatched),
    )


@check("adcs_esc16")
def esc16(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        if c.SZOID_NTDS_CA_SECURITY_EXT in ca.disabled_extensions:
            res.affected.append(ca.name)
    return res


# --- Hygiène ------------------------------------------------------------------


@check("adcs_template_weak_key")
def template_weak_key(snap: Snapshot, params: dict) -> CheckResult:
    minimum = params.get("min_key_size", 2048)
    res = CheckResult()
    for t in snap.pki.templates:
        if t.enabled and t.key_size < minimum:
            res.affected.append(t.name)
            res.details[t.name] = {"taille_cle": t.key_size}
    return res


@check("adcs_ca_weak_crypto")
def ca_weak_crypto(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for ca in snap.pki.cas:
        reasons = []
        if ca.cert_key_size is not None and ca.cert_key_size < params.get("min_key_size", 2048):
            reasons.append(f"clé RSA {ca.cert_key_size} bits")
        if ca.cert_signature_algorithm and "sha1" in ca.cert_signature_algorithm.lower():
            reasons.append(f"signature {ca.cert_signature_algorithm}")
        if reasons:
            res.affected.append(ca.name)
            res.details[ca.name] = reasons
    return res


@check("adcs_ca_cert_expiring")
def ca_cert_expiring(snap: Snapshot, params: dict) -> CheckResult:
    horizon = snap.collected_at + timedelta(days=params.get("days", 180))
    res = CheckResult()
    for ca in snap.pki.cas:
        if ca.cert_not_after and ca.cert_not_after <= horizon:
            res.affected.append(ca.name)
            res.details[ca.name] = {"expire_le": ca.cert_not_after.date().isoformat()}
    return res


@check("adcs_long_validity_auth")
def long_validity_auth(snap: Snapshot, params: dict) -> CheckResult:
    max_days = params.get("max_days", 730)
    res = CheckResult()
    for t in snap.pki.templates:
        if t.enabled and t.allows_authentication and t.validity_days > max_days:
            res.affected.append(t.name)
            res.details[t.name] = {"validite_jours": t.validity_days}
    return res


# --- Certificats publiés dans l'AD (racines, intermédiaires, NTAuth) ------------


@check("adcs_cert_weak")
def cert_weak(snap: Snapshot, params: dict) -> CheckResult:
    """params.what : obsolete_hash | sha1 | rsa_lt_1024 | rsa_lt_2048 | dsa | rsa_exponent | roca"""
    what = params["what"]
    res = CheckResult()
    for cert in snap.pki.certificates:
        h = (cert.sig_hash or "").lower()
        hit = {
            "obsolete_hash": h in ("md2", "md4", "md5", "sha0"),
            "sha1": h == "sha1",
            "rsa_lt_1024": cert.key_type == "rsa" and cert.key_size is not None and cert.key_size < 1024,
            "rsa_lt_2048": cert.key_type == "rsa" and cert.key_size is not None and 1024 <= cert.key_size < 2048,
            "dsa": cert.key_type == "dsa",
            "rsa_exponent": cert.key_type == "rsa" and cert.rsa_exponent is not None and cert.rsa_exponent < 65537,
            "roca": bool(cert.roca),
        }[what]
        if hit:
            res.affected.append(f"{cert.subject} [{cert.store}]")
    return res
