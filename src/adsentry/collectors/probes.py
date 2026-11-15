"""Sondes réseau en LECTURE SEULE sur les contrôleurs de domaine.

Aucune sonde n'exploite quoi que ce soit : on négocie un protocole, on liste des canaux nommés,
on tente une authentification légitime avec le compte d'audit (ou anonyme) et on observe la réponse.
Les vulnérabilités MS17-010 / MS14-068 ne sont PAS testées (laisser à un scanner dédié, import prévu).

⚠ Non validé contre un vrai domaine : à tester sur le lab (phase 1).
"""

from __future__ import annotations

import logging
import socket
import ssl

from ..models import DcProbe, TlsProbe

log = logging.getLogger(__name__)

COERCE_PIPES = {"efsrpc": "MS-EFSR", "netdfs": "MS-DFSNM", "fssagentrpc": "MS-FSRVP"}
TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def tls_versions(host: str, port: int, timeout: float = 5) -> list[str]:
    """Versions TLS acceptées (SSLv2/v3 non testables avec OpenSSL moderne)."""
    accepted = []
    for name, version in TLS_VERSIONS.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            ctx.minimum_version = ctx.maximum_version = version
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock):
                accepted.append(name)
        except (OSError, ssl.SSLError, ValueError):
            continue
    return accepted


def probe_dc(name: str, host: str, domain: str, username: str, password: str, base_dn: str) -> DcProbe:
    p = DcProbe(name=name)
    _smb(p, host, domain, username, password)
    _ldap(p, host, domain, username, password, base_dn)
    try:
        p.ldaps_protocols = tls_versions(host, 636)
    except Exception as exc:
        log.warning("%s : sonde TLS LDAPS impossible (%s)", name, exc)
    return p


def _smb(p: DcProbe, host: str, domain: str, username: str, password: str) -> None:
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection

    try:  # SMBv1 accepté ?
        SMBConnection(host, host, preferredDialect=SMB_DIALECT, timeout=10).close()
        p.smb1 = True
    except Exception:
        p.smb1 = False
    try:
        conn = SMBConnection(host, host, timeout=10)
        p.smb_signing_required = bool(conn.isSigningRequired())
        p.smb_signing_enabled = True  # toujours possible en SMB2/3
        conn.login(username, password, domain)
        pipes = {f.get_longname().lower() for f in conn.listPath("IPC$", "*")}
        p.spooler = "spoolss" in pipes
        p.webclient = "dav rpc service" in pipes
        p.coerce_interfaces = sorted(v for k, v in COERCE_PIPES.items() if k in pipes)
        p.net_session_enum_open = _net_session_enum(conn)
        conn.close()
    except Exception as exc:
        log.warning("%s : sonde SMB authentifiée incomplète (%s)", p.name, exc)
    try:
        anon = SMBConnection(host, host, timeout=10)
        anon.login("", "")
        p.null_session = _samr_enum(anon)
        anon.close()
    except Exception:
        p.null_session = False


def _net_session_enum(conn) -> bool | None:
    from impacket.dcerpc.v5 import srvs, transport
    from impacket.dcerpc.v5.dtypes import NULL

    try:
        rpc = transport.SMBTransport(conn.getRemoteHost(), filename=r"\srvsvc", smb_connection=conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        return True
    except Exception as exc:
        return False if "ACCESS_DENIED" in str(exc).upper() else None


def _samr_enum(conn) -> bool:
    from impacket.dcerpc.v5 import samr, transport

    try:
        rpc = transport.SMBTransport(conn.getRemoteHost(), filename=r"\samr", smb_connection=conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        handle = samr.hSamrConnect(dce)["ServerHandle"]
        samr.hSamrEnumerateDomainsInSamServer(dce, handle)
        return True
    except Exception:
        return False


def _ldap(p: DcProbe, host: str, domain: str, username: str, password: str, base_dn: str) -> None:
    from ldap3 import NTLM, Connection, Server

    user = f"{domain}\\{username}"
    try:  # bind NTLM sans signature sur 389
        conn = Connection(Server(host, port=389), user=user, password=password, authentication=NTLM)
        ok = conn.bind()
        p.ldap_signing_required = not ok and conn.result.get("result") == 8  # strongerAuthRequired
        if ok:
            p.ldap_signing_required = False
        conn.unbind()
    except Exception as exc:
        log.warning("%s : sonde signature LDAP impossible (%s)", p.name, exc)
    try:  # bind NTLM sur LDAPS sans jeton de liaison de canal
        conn = Connection(Server(host, port=636, use_ssl=True), user=user, password=password, authentication=NTLM)
        ok = conn.bind()
        p.ldaps_channel_binding_required = not ok and "80090346" in str(conn.result.get("message", ""))
        if ok:
            p.ldaps_channel_binding_required = False
        conn.unbind()
    except Exception as exc:
        log.warning("%s : sonde channel binding impossible (%s)", p.name, exc)
    try:  # bind anonyme puis recherche hors RootDSE
        conn = Connection(Server(host, port=389))
        conn.bind()
        conn.search(base_dn, "(objectClass=user)", size_limit=1)
        p.anonymous_bind = bool(conn.entries)
        conn.unbind()
    except Exception:
        p.anonymous_bind = False


def probe_tls_service(host: str, port: int, service: str) -> TlsProbe:
    return TlsProbe(host=host, port=port, service=service, protocols=tls_versions(host, port))
