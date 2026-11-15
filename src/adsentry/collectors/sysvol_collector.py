"""Collecte des GPO : métadonnées par LDAP + fichiers par SMB (SYSVOL), en lecture seule.

Pour chaque GPO : nom, état, liaisons (gPLink sur domaine/OU), ACL (qui peut la modifier), puis
lecture dans SYSVOL de GptTmpl.inf, Registry.pol (machine et utilisateur), audit.csv, scripts.ini et
des préférences XML (cpassword, groupes locaux, fichiers déployés, options des dossiers).

⚠ Non validé contre un vrai domaine : à tester sur le lab (phase 1). Les ACL NTFS des scripts et
fichiers déployés ne sont pas encore lues (writers=None => règles P-DELEGATION-LOGIN-SCRIPT/FILE muettes).
"""

from __future__ import annotations

import io
import logging
import re

from ..models import Gpo, ScriptRef
from . import gpo_parsers as gp

log = logging.getLogger(__name__)

PREFERENCE_FILES = [
    "Machine/Preferences/Groups/Groups.xml",
    "User/Preferences/Groups/Groups.xml",
    "Machine/Preferences/Services/Services.xml",
    "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml",
    "User/Preferences/ScheduledTasks/ScheduledTasks.xml",
    "Machine/Preferences/DataSources/DataSources.xml",
    "User/Preferences/Drives/Drives.xml",
    "Machine/Preferences/Files/Files.xml",
    "User/Preferences/Files/Files.xml",
    "User/Preferences/FolderOptions/FolderOptions.xml",
]
GPLINK_RE = re.compile(r"\[LDAP://([^;\]]+);(\d)\]", re.I)


def parse_gplink(value: str) -> list[tuple[str, bool]]:
    """'[LDAP://cn={GUID},cn=policies,...;0]' -> [(dn_gpo, actif)] (option 1 = lien désactivé)."""
    return [(m.group(1).lower(), not int(m.group(2)) & 1) for m in GPLINK_RE.finditer(value or "")]


class SysvolCollector:
    def __init__(self, ldap_collector, smb_host: str, domain: str, username: str, password: str):
        self.ldap, self.host, self.domain = ldap_collector, smb_host, domain
        self.username, self.password = username, password
        self.smb = None

    def _read(self, share_path: str) -> bytes | None:
        buf = io.BytesIO()
        try:
            self.smb.getFile("SYSVOL", share_path.replace("/", "\\"), buf.write)
            return buf.getvalue()
        except Exception:  # fichier absent : cas normal
            return None

    def collect(self, writers_by_gpo_dn: dict[str, list[str]] | None = None) -> list[Gpo]:
        from impacket.smbconnection import SMBConnection

        self.smb = SMBConnection(self.host, self.host, timeout=30)
        self.smb.login(self.username, self.password, self.domain)

        base, dc_ou = self.ldap.base_dn.lower(), f"ou=domain controllers,{self.ldap.base_dn}".lower()
        links: dict[str, list[str]] = {}
        for e in self.ldap._search(self.ldap.base_dn, "(gPLink=*)", ["gPLink"]):
            gplink = e["a"].get("gPLink")
            gplink = gplink[0] if isinstance(gplink, list) else gplink
            for gdn, active in parse_gplink(gplink):
                if active:
                    links.setdefault(gdn, []).append(e["dn"])

        gpos = []
        for e in self.ldap._search(
            f"CN=Policies,CN=System,{self.ldap.base_dn}",
            "(objectClass=groupPolicyContainer)",
            ["cn", "displayName", "flags", "gPCFileSysPath"],
        ):
            guid = e["a"].get("cn")
            guid = guid[0] if isinstance(guid, list) else guid
            linked = links.get(e["dn"].lower(), [])
            flags = int(e["a"].get("flags") or 0)
            g = Gpo(
                guid=guid,
                name=str(e["a"].get("displayName") or guid),
                enabled=flags != 3,
                linked_to=linked,
                applies_to_domain=any(dn.lower() == base for dn in linked),
                applies_to_dcs=any(dn.lower() == dc_ou for dn in linked),
                writers=(writers_by_gpo_dn or {}).get(e["dn"].lower(), []),
            )
            self._fill_files(g, f"{self.domain}/Policies/{guid}")
            gpos.append(g)
        return gpos

    def _fill_files(self, g: Gpo, root: str) -> None:
        if data := self._read(f"{root}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"):
            g.security, reg = gp.parse_gpttmpl(data)
            g.registry.update(reg)
        for hive in ("Machine", "User"):
            if data := self._read(f"{root}/{hive}/Registry.pol"):
                try:
                    g.registry.update(gp.parse_registry_pol(data, hive.lower()))
                except ValueError as exc:
                    log.warning("GPO %s : %s", g.name, exc)
        g.firewall_rules = gp.firewall_rules(g.registry)
        if data := self._read(f"{root}/Machine/Microsoft/Windows NT/Audit/audit.csv"):
            g.audit = gp.parse_audit_csv(data)
        for sub in ("Machine/Scripts/scripts.ini", "User/Scripts/scripts.ini"):
            if data := self._read(f"{root}/{sub}"):
                g.scripts += [ScriptRef(path=p) for p in gp.parse_scripts_ini(data)]
        for pref in PREFERENCE_FILES:
            if data := self._read(f"{root}/{pref}"):
                parsed = gp.parse_gpp_xml(data)
                if parsed["cpassword"]:
                    g.cpassword_files.append(f"{root}/{pref}")
                for grp, members in parsed["groups"].items():
                    g.local_group_members.setdefault(grp, []).extend(members)
                g.files += [ScriptRef(path=p) for p in parsed["files"]]
                g.folder_options.update(parsed["folder_options"])
