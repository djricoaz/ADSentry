from __future__ import annotations

import json
from pathlib import Path

import pytest

from adsentry.models import Snapshot
from adsentry.rules.engine import analyze, load_rules

FIXTURES = Path(__file__).parent / "fixtures"


def load_raw(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def rules():
    return load_rules()


@pytest.fixture(scope="session")
def vuln(rules):
    return analyze(Snapshot.model_validate(load_raw("vulnerable")), rules)


@pytest.fixture(scope="session")
def hardened(rules):
    return analyze(Snapshot.model_validate(load_raw("hardened")), rules)


def by_id(result):
    return {f.rule_id: f for f in result.findings}
