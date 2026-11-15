"""Configuration de l'appliance : cron, secrets chiffrés, cibles."""

from __future__ import annotations

from datetime import datetime

import pytest

from adsentry.appliance.config import SecretStore, cron_matches, load_targets


@pytest.mark.parametrize(
    "expr, when, expected",
    [
        ("17 2 * * *", datetime(2026, 11, 6, 2, 17), True),
        ("17 2 * * *", datetime(2026, 11, 6, 2, 18), False),
        ("*/15 * * * *", datetime(2026, 11, 6, 9, 45), True),
        ("0 3 * * 1-5", datetime(2026, 11, 7, 3, 0), False),  # samedi
        ("0 3 * * 1-5", datetime(2026, 11, 6, 3, 0), True),  # vendredi
        ("30 4 1,15 * *", datetime(2026, 11, 15, 4, 30), True),
    ],
)
def test_cron(expr, when, expected):
    assert cron_matches(expr, when) is expected


def test_secret_store_roundtrip(tmp_path):
    store = SecretStore(tmp_path / "master.key", tmp_path / "secrets.json")
    store.set("corp-ad", "S3cr3t!")
    assert store.get("corp-ad") == "S3cr3t!"
    assert "S3cr3t!" not in (tmp_path / "secrets.json").read_text()
    assert oct((tmp_path / "master.key").stat().st_mode)[-3:] == "400"


def test_load_targets(tmp_path):
    (tmp_path / "targets.yaml").write_text(
        "targets:\n  - name: corp\n    ad: {domain: corp.local, dc: 10.0.0.10, username: a, password_secret: s}\n"
        "  - name: cloud\n    entra: {tenant_id: t, client_id: c, certificate: /x.pem, thumbprint: AB}\n"
    )
    targets = load_targets(tmp_path / "targets.yaml")
    assert [t.name for t in targets] == ["corp", "cloud"]
    assert targets[0].ad.sysvol is True and targets[1].entra.tenant_id == "t"
