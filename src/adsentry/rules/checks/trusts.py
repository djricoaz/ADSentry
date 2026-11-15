"""Relations d'approbation, SID History, ressources hors domaine, SSO Entra (AZUREADSSOACC)."""

from __future__ import annotations

from ...models import Snapshot
from ..registry import CheckResult, check
from ._helpers import in_domain, older_than, unc_host


def _domain_part(sid: str) -> str:
    return sid.rsplit("-", 1)[0]


@check("trust_sid_filtering_disabled")
def sid_filtering_disabled(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[t.target for t in snap.trusts if not t.sid_filtering and t.direction != "outbound"])


@check("trust_tgt_delegation")
def tgt_delegation(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[t.target for t in snap.trusts if t.tgt_delegation])


@check("trust_inactive")
def inactive(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[t.target for t in snap.trusts if older_than(snap, t.last_change, params.get("days", 45))]
    )


@check("trust_downlevel")
def downlevel(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[t.target for t in snap.trusts if t.trust_type == 1])


@check("trust_aes_disabled")
def aes_disabled(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[t.target for t in snap.trusts if t.aes_enabled is False])


def _sid_history_items(snap: Snapshot):
    for u in snap.users:
        for s in u.sid_history:
            yield u.sam, s
    for cp in snap.computers:
        for s in cp.sid_history:
            yield cp.name, s


@check("trust_sid_history_same_domain")
def sid_history_same_domain(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(affected=[n for n, s in _sid_history_items(snap) if _domain_part(s) == snap.domain.sid])


@check("trust_sid_history_unknown_domain")
def sid_history_unknown_domain(snap: Snapshot, params: dict) -> CheckResult:
    known = {snap.domain.sid} | {t.sid for t in snap.trusts if t.sid}
    return CheckResult(
        affected=[n for n, s in _sid_history_items(snap) if s.startswith("S-1-5-21-") and _domain_part(s) not in known]
    )


@check("trust_sid_history_dangerous")
def sid_history_dangerous(snap: Snapshot, params: dict) -> CheckResult:
    res = CheckResult()
    for n, s in _sid_history_items(snap):
        rid = int(s.rsplit("-", 1)[1]) if s.rsplit("-", 1)[1].isdigit() else 9999
        if s.startswith("S-1-5-32-") or (s.startswith("S-1-5-21-") and rid < 1000):
            res.affected.append(n)
            res.details[n] = s
    return res


@check("trust_out_of_domain_path")
def out_of_domain_path(snap: Snapshot, params: dict) -> CheckResult:
    """Scripts de connexion ou fichiers déployés hébergés hors du domaine (params.what = scripts|files)."""
    what = params.get("what", "scripts")
    paths: list[str] = []
    for g in snap.gpos or []:
        paths += [r.path for r in (g.scripts if what == "scripts" else g.files)]
    if what == "scripts":
        paths += [u.script_path for u in snap.users if u.script_path]
    res = CheckResult()
    for p in paths:
        host = unc_host(p)
        if host and not in_domain(snap, host):
            res.affected.append(p)
    return res


@check("trust_azuread_sso")
def azuread_sso(snap: Snapshot, params: dict) -> CheckResult:
    return CheckResult(
        affected=[
            cp.name
            for cp in snap.computers
            if cp.name.upper().startswith("AZUREADSSOACC") and older_than(snap, cp.pwd_last_set, params.get("days", 40))
        ]
    )
