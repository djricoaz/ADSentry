"""Analyseurs des fichiers de GPO lus dans SYSVOL (fonctions pures, testables hors réseau).

* GptTmpl.inf  : paramètres de sécurité (stratégie de mots de passe, droits, valeurs de registre, groupes)
* Registry.pol : modèles d'administration (format binaire « PReg »)
* audit.csv    : stratégie d'audit avancée
* scripts.ini  : scripts d'ouverture/fermeture de session, démarrage/arrêt
* Préférences XML (Groups.xml, Files.xml, ...) : cpassword, membres de groupes locaux, fichiers déployés

Toutes les clés de registre sont normalisées en minuscules : ``machine\\software\\...\\valeur``.
"""

from __future__ import annotations

import csv
import io
import re
import struct
import xml.etree.ElementTree as ET
from typing import Any

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


def norm_key(path: str) -> str:
    return path.replace("/", "\\").strip("\\").lower()


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if len(data) > 1 and data[1:2] == b"\x00":
        return data.decode("utf-16-le")
    return data.decode("utf-8-sig", errors="replace")


# ----------------------------------------------------------------------------- GptTmpl.inf


def parse_ini(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
            continue
        if current is not None and "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip()
    return sections


def parse_gpttmpl(data: bytes) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    """Retourne (sections, registre normalisé issu de [Registry Values])."""
    sections = parse_ini(decode_text(data))
    registry: dict[str, Any] = {}
    for key, raw in sections.get("Registry Values", {}).items():
        typ, _, value = raw.partition(",")
        value = value.strip().strip('"')
        registry[norm_key(key)] = int(value) if typ.strip() == "4" and value.lstrip("-").isdigit() else value
    return sections, registry


def sids_from_privilege(value: str) -> list[str]:
    """'*S-1-5-32-544,*S-1-1-0,Domain Admins' -> ['S-1-5-32-544', 'S-1-1-0', 'Domain Admins']"""
    return [p.strip().lstrip("*") for p in value.split(",") if p.strip()]


# ----------------------------------------------------------------------------- Registry.pol


def parse_registry_pol(data: bytes, hive: str = "machine") -> dict[str, Any]:
    if data[:4] != b"PReg":
        raise ValueError("Fichier Registry.pol invalide (signature PReg absente)")
    pos, out = 8, {}

    def read_wstr() -> str:
        nonlocal pos
        end = pos
        while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
            end += 2
        s = data[pos:end].decode("utf-16-le")
        pos = end + 2
        return s

    def expect(ch: str) -> None:
        nonlocal pos
        if data[pos : pos + 2] != ch.encode("utf-16-le"):
            raise ValueError(f"Registry.pol corrompu à l'octet {pos} (attendu {ch!r})")
        pos += 2

    while pos < len(data):
        expect("[")
        key = read_wstr()
        expect(";")
        name = read_wstr()
        expect(";")
        (typ,) = struct.unpack_from("<I", data, pos)
        pos += 4
        expect(";")
        (size,) = struct.unpack_from("<I", data, pos)
        pos += 4
        expect(";")
        raw = data[pos : pos + size]
        pos += size
        expect("]")
        out[norm_key(f"{hive}\\{key}\\{name}")] = _reg_value(typ, raw)
    return out


def _reg_value(typ: int, raw: bytes) -> Any:
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le").rstrip("\x00")
    if typ == REG_DWORD and len(raw) >= 4:
        return struct.unpack("<I", raw[:4])[0]
    if typ == REG_QWORD and len(raw) >= 8:
        return struct.unpack("<Q", raw[:8])[0]
    if typ == REG_MULTI_SZ:
        return [s for s in raw.decode("utf-16-le").split("\x00") if s]
    return raw.hex()


def build_registry_pol(entries: list[tuple[str, str, int, Any]]) -> bytes:
    """Fabrique un Registry.pol (utilisé par les tests et le lab)."""
    out = bytearray(b"PReg" + struct.pack("<I", 1))

    def w(s: str) -> bytes:
        return (s + "\x00").encode("utf-16-le")

    for key, name, typ, value in entries:
        if typ == REG_DWORD:
            raw = struct.pack("<I", value)
        elif typ in (REG_SZ, REG_EXPAND_SZ):
            raw = w(value)
        else:
            raw = bytes(value)
        out += "[".encode("utf-16-le") + w(key) + ";".encode("utf-16-le") + w(name)
        out += ";".encode("utf-16-le") + struct.pack("<I", typ) + ";".encode("utf-16-le")
        out += struct.pack("<I", len(raw)) + ";".encode("utf-16-le") + raw + "]".encode("utf-16-le")
    return bytes(out)


def firewall_rules(registry: dict[str, Any]) -> list[dict[str, str]]:
    """Extrait les règles de pare-feu (format 'v2.x|Action=Block|Dir=Out|App=...')."""
    rules = []
    for key, value in registry.items():
        if "\\windowsfirewall\\firewallrules\\" in key and isinstance(value, str):
            fields = dict(p.split("=", 1) for p in value.split("|")[1:] if "=" in p)
            rules.append({k.lower(): v for k, v in fields.items()})
    return rules


# ----------------------------------------------------------------------------- audit.csv / scripts.ini


def parse_audit_csv(data: bytes) -> dict[str, int]:
    out = {}
    for row in csv.DictReader(io.StringIO(decode_text(data))):
        sub, val = row.get("Subcategory"), row.get("Setting Value")
        if sub and val and val.strip().isdigit():
            out[sub.strip()] = int(val)
    return out


def parse_scripts_ini(data: bytes) -> list[str]:
    paths = []
    for section in parse_ini(decode_text(data)).values():
        for k, v in section.items():
            if re.fullmatch(r"\d+CmdLine", k, flags=re.I) and v:
                paths.append(v)
    return paths


# ----------------------------------------------------------------------------- Préférences XML


def parse_gpp_xml(data: bytes) -> dict[str, Any]:
    """cpassword présent ? membres de groupes locaux ajoutés, fichiers déployés, associations."""
    result: dict[str, Any] = {"cpassword": False, "groups": {}, "files": [], "folder_options": {}}
    try:
        root = ET.fromstring(decode_text(data).encode("utf-8"))
    except ET.ParseError:
        return result
    for el in root.iter():
        if el.get("cpassword"):
            result["cpassword"] = True
        if el.tag == "Properties" and (el.get("groupSid") or el.get("groupName")):
            group = el.get("groupSid") or el.get("groupName") or "?"
            members = [
                m.get("sid") or m.get("name") for m in el.iter("Member") if (m.get("action") or "ADD").upper() == "ADD"
            ]
            result["groups"].setdefault(group, []).extend(x for x in members if x)
        if el.tag == "Properties" and el.get("fromPath"):
            result["files"].append(el.get("fromPath"))
        if el.get("fileExtn") or el.get("fileExtension"):
            ext = (el.get("fileExtn") or el.get("fileExtension") or "").lower().lstrip(".")
            result["folder_options"][ext] = el.get("application") or el.get("appProgID") or ""
    return result
