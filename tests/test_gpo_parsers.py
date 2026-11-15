"""Analyseurs SYSVOL (GptTmpl.inf, Registry.pol, audit.csv, scripts.ini, préférences XML)."""

from __future__ import annotations

from adsentry.collectors import gpo_parsers as gp

GPTTMPL = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 7
ClearTextPassword = 0
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-11
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionPipes=7,
""".encode("utf-16")


def test_gpttmpl():
    sections, registry = gp.parse_gpttmpl(GPTTMPL)
    assert sections["System Access"]["MinimumPasswordLength"] == "7"
    assert gp.sids_from_privilege(sections["Privilege Rights"]["SeDebugPrivilege"]) == ["S-1-5-32-544", "S-1-5-11"]
    assert registry[r"machine\system\currentcontrolset\control\lsa\lmcompatibilitylevel"] == 5


def test_registry_pol_roundtrip():
    data = gp.build_registry_pol(
        [
            (r"Software\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", gp.REG_DWORD, 0),
            (r"Software\Policies\Microsoft\Windows\WindowsUpdate", "WUServer", gp.REG_SZ, "http://wsus:8530"),
            (
                r"Software\Policies\Microsoft\WindowsFirewall\FirewallRules",
                "{abc}",
                gp.REG_SZ,
                "v2.30|Action=Block|Active=TRUE|Dir=Out|App=%SystemRoot%\\system32\\wscript.exe|Name=x|",
            ),
        ]
    )
    reg = gp.parse_registry_pol(data)
    assert reg[r"machine\software\policies\microsoft\windows nt\dnsclient\enablemulticast"] == 0
    assert reg[r"machine\software\policies\microsoft\windows\windowsupdate\wuserver"] == "http://wsus:8530"
    fw = gp.firewall_rules(reg)
    assert fw[0]["action"] == "Block" and fw[0]["dir"] == "Out" and fw[0]["app"].endswith("wscript.exe")


def test_audit_csv_and_scripts():
    audit = gp.parse_audit_csv(
        b"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"
        b",System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\n"
    )
    assert audit == {"Audit Logon": 3}
    scripts = gp.parse_scripts_ini("[Logon]\n0CmdLine=\\\\srv\\share\\a.bat\n0Parameters=\n".encode("utf-16"))
    assert scripts == ["\\\\srv\\share\\a.bat"]


def test_gpp_xml():
    xml = b"""<?xml version="1.0" encoding="utf-8"?>
<Groups><Group name="Administrators (built-in)"><Properties action="U" groupSid="S-1-5-32-544">
<Members><Member name="CORP\\Domain Users" action="ADD" sid="S-1-5-21-1-2-3-513"/></Members></Properties></Group>
<User name="local"><Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" userName="adm"/></User></Groups>"""
    out = gp.parse_gpp_xml(xml)
    assert out["cpassword"] is True
    assert out["groups"]["S-1-5-32-544"] == ["S-1-5-21-1-2-3-513"]
