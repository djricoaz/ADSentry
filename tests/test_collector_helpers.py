"""Fonctions pures des collecteurs (décodage binaire AD, ACE, gPLink)."""

from __future__ import annotations

import struct

from adsentry.collectors import ldap_collector as lc
from adsentry.collectors.sysvol_collector import parse_gplink


def test_sid_from_bytes():
    raw = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + struct.pack("<5I", 21, 1000, 2000, 3000, 500)
    assert lc.sid_from_bytes(raw) == "S-1-5-21-1000-2000-3000-500"


def test_repl_metadata():
    raw = struct.pack("<IIII", 1, 0, 1, 0) + struct.pack("<IIq", lc.ATTR_UNICODE_PWD, 1, 13400000000) + b"\0" * 32
    meta = lc.parse_repl_metadata(raw)
    assert meta[lc.ATTR_UNICODE_PWD].year == 2025


def test_ace_rights():
    assert lc.ace_rights(0x20, lc.GUID_MEMBER) == ["AddMember"]
    assert lc.ace_rights(0x100, None) == ["AllExtendedRights"]
    assert lc.ace_rights(0x000F01FF, None) == ["GenericAll"]
    assert lc.ace_rights(0x1, lc.GUID_DMSA_CLASS) == ["CreateChild-dMSA"]
    assert lc.ace_rights(0x100, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") == ["DS-Replication-Get-Changes-All"]


def test_gplink():
    links = parse_gplink("[LDAP://cn={A},cn=policies,cn=system,DC=x;0][LDAP://cn={B},cn=policies,cn=system,DC=x;1]")
    assert links == [("cn={a},cn=policies,cn=system,dc=x", True), ("cn={b},cn=policies,cn=system,dc=x", False)]
