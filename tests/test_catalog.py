"""Cohérence et étendue du catalogue de règles."""

from __future__ import annotations

import re

import pytest

from adsentry.rules.registry import load_all_checks


def test_catalog_is_consistent(rules):
    checks = load_all_checks()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.manual or r.check in checks, f"{r.id}: contrôle {r.check} absent"
        assert r.remediation.strip() and r.description.strip(), r.id
        assert re.fullmatch(r"(S|P|T|A|PKI|E)-[A-Z0-9-]+", r.id), r.id
    assert {f"PKI-ESC{i}" for i in range(1, 17)} <= set(ids)


def test_catalog_breadth(rules):
    """Chaque domaine d'analyse est couvert en profondeur."""
    from collections import Counter

    counts = Counter(r.category.value for r in rules)
    assert len(rules) >= 200
    assert all(counts[c] >= 10 for c in ("stale_objects", "privileged_accounts", "anomalies", "pki", "entra_id"))


def test_no_third_party_identifiers():
    """Aucune référence à un outil d'audit tiers dans le produit (propriété intellectuelle)."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    banned = ("ping" + "castle", "purple " + "knight")
    for path in [*root.glob("src/**/*"), *root.glob("appliance/**/*"), *root.glob("docs/**/*"), root / "README.md"]:
        if path.is_file() and path.suffix in {".py", ".yaml", ".md", ".js", ".html", ".json", ".css"}:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            assert not any(b in text for b in banned), path


@pytest.mark.network
def test_mitre_ids_exist_in_current_attack(rules):
    from adsentry.mitre.attack import load

    kb = load()
    ids = sorted({m.technique for r in rules for m in r.mitre})
    assert kb.validate(ids) == {"inconnus": [], "revoques": [], "deprecies": []}
