"""Collecte LDAP : un attribut absent du schéma (extension non installée, ex. LAPS historique) ne doit pas
interrompre le scan ; il est simplement non collecté (règle d'or 3)."""

from __future__ import annotations

import pytest

ldap3 = pytest.importorskip("ldap3")

from adsentry.collectors.ldap_collector import LdapCollector  # noqa: E402


@pytest.fixture()
def collector():
    from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

    server = Server("dc01.cloud.lab", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user="cn=audit,dc=cloud,dc=lab", password="x", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry("cn=audit,dc=cloud,dc=lab", {"userPassword": "x", "sAMAccountName": "audit"})
    conn.strategy.add_entry(
        "cn=PC01,dc=cloud,dc=lab",
        {"objectClass": ["top", "computer"], "sAMAccountName": "PC01$", "dNSHostName": "pc01.cloud.lab"},
    )
    conn.bind()
    c = LdapCollector("dc01.cloud.lab", "cloud.lab", "audit", "x")
    c.conn = conn
    return c


def test_unknown_attribute_is_skipped_not_fatal(collector):
    # Sans correctif : LDAPAttributeError « invalid attribute type ms-Mcs-AdmPwdExpirationTime »
    rows = collector._search(
        "dc=cloud,dc=lab",
        "(objectClass=computer)",
        ["sAMAccountName", "dNSHostName", "ms-Mcs-AdmPwdExpirationTime"],
    )
    assert [r["a"]["sAMAccountName"] for r in rows] == ["PC01$"]
    assert "ms-Mcs-AdmPwdExpirationTime" not in rows[0]["raw"]
    assert "ms-Mcs-AdmPwdExpirationTime" in collector.missing_attributes


def test_known_attributes_untouched(collector):
    assert collector._known_attributes(["sAMAccountName", "dNSHostName"]) == ["sAMAccountName", "dNSHostName"]
    assert collector.missing_attributes == set()
