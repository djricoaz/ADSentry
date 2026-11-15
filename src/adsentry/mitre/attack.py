"""Chargement de MITRE ATT&CK (Enterprise) depuis le bundle STIX officiel.

On ne code JAMAIS en dur les tactiques : depuis ATT&CK v19 (avril 2026), « Defense Evasion »
a été scindée en « Stealth » et « Impair Defenses », et chaque version peut déplacer ou
révoquer des techniques. Les tactiques sont donc lues dans le bundle téléchargé.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
CACHE_DIR = Path.home() / ".cache" / "adsentry"


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]
    url: str
    revoked: bool = False
    deprecated: bool = False
    revoked_by: str | None = None


@dataclass
class AttackKB:
    version: str
    tactic_order: list[str] = field(default_factory=list)
    techniques: dict[str, Technique] = field(default_factory=dict)
    tactics: dict[str, str] = field(default_factory=dict)  # shortname -> nom affiché

    def validate(self, ids: list[str]) -> dict[str, list[str]]:
        """Retourne les IDs inconnus / révoqués / dépréciés (à corriger dans le catalogue)."""
        report: dict[str, list[str]] = {"inconnus": [], "revoques": [], "deprecies": []}
        for tid in ids:
            t = self.techniques.get(tid)
            if t is None:
                report["inconnus"].append(tid)
            elif t.revoked:
                report["revoques"].append(f"{tid} -> {t.revoked_by or '?'}")
            elif t.deprecated:
                report["deprecies"].append(tid)
        return report


def download(dest: Path | None = None, url: str = STIX_URL) -> Path:
    dest = dest or CACHE_DIR / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
        r.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in r.iter_bytes():
                fh.write(chunk)
    return dest


def load(path: Path | None = None) -> AttackKB:
    path = path or CACHE_DIR / "enterprise-attack.json"
    if not path.exists():
        path = download(path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])

    version = next((o.get("x_mitre_version", "?") for o in objects if o.get("type") == "x-mitre-collection"), "?")
    kb = AttackKB(version=version)
    stix_to_ext: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "x-mitre-tactic":
            kb.tactics[o["x_mitre_shortname"]] = o["name"]
            stix_to_ext[o["id"]] = o["x_mitre_shortname"]
        elif o.get("type") == "attack-pattern":
            ref = next(
                (r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
                None,
            )
            if not ref:
                continue
            stix_to_ext[o["id"]] = ref["external_id"]
            kb.techniques[ref["external_id"]] = Technique(
                id=ref["external_id"],
                name=o.get("name", ""),
                tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])],
                url=ref.get("url", ""),
                revoked=o.get("revoked", False),
                deprecated=o.get("x_mitre_deprecated", False),
            )
    # Ordre officiel des tactiques (matrice Enterprise)
    matrix = next((o for o in objects if o.get("type") == "x-mitre-matrix"), None)
    if matrix:
        kb.tactic_order = [stix_to_ext[t] for t in matrix.get("tactic_refs", []) if t in stix_to_ext]
    # Révocations : indiquer la technique de remplacement (ex. T1562.002 -> T1685.001 en v19+)
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = stix_to_ext.get(o["source_ref"]), stix_to_ext.get(o["target_ref"])
            if src in kb.techniques and dst:
                kb.techniques[src].revoked_by = dst
    return kb


EXPORT_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_subset.json"


def export_subset(kb: AttackKB, ids: list[str], path: Path = EXPORT_PATH) -> Path:
    """Écrit les techniques utilisées par le catalogue + l'ordre des tactiques (pour l'interface hors ligne)."""
    data = {
        "version": kb.version,
        "tactics": [{"id": t, "name": kb.tactics[t]} for t in kb.tactic_order if t in kb.tactics],
        "techniques": {
            tid: {"name": kb.techniques[tid].name, "tactics": kb.techniques[tid].tactics}
            for tid in sorted(ids)
            if tid in kb.techniques
        },
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return path
