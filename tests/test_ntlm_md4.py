"""NTLM sur OpenSSL 3 : MD4 désactivé par défaut, ldap3 doit disposer d'un repli (pycryptodome)."""

from __future__ import annotations

import hashlib
import hmac

import pytest

ldap3_ntlm = pytest.importorskip("ldap3.utils.ntlm")


def test_ntowf_v2_without_openssl_md4(monkeypatch):
    real_new = hashlib.new

    def no_md4(name, *args, **kwargs):  # simule OpenSSL 3 sans fournisseur « legacy »
        if name.lower() == "md4":
            raise ValueError("unsupported hash type MD4")
        return real_new(name, *args, **kwargs)

    monkeypatch.setattr(hashlib, "new", no_md4)
    client = ldap3_ntlm.NtlmClient("CLOUD", "Administrator", "Passw0rd!")
    digest = client.ntowf_v2()

    # Valeur attendue calculée indépendamment (MD4 de pycryptodomex, présent avec impacket)
    md4 = pytest.importorskip("Cryptodome.Hash.MD4")
    nt_hash = md4.new("Passw0rd!".encode("utf-16-le")).digest()
    expected = hmac.new(nt_hash, ("ADMINISTRATOR" + "CLOUD").encode("utf-16-le"), digestmod=hashlib.md5).digest()
    assert digest == expected
