"""Classification des modèles de certificats.

Chaque modèle reçoit :
* une **classe** (ce que permet un certificat émis) :
    - « T0 – Chemin vers Domain Admin » : le modèle est impliqué dans une ESC critique ;
    - « Authentification »               : le certificat permet d'ouvrir une session (PKINIT/Schannel) ;
    - « Agent d'inscription »            : le certificat permet de demander pour autrui ;
    - « Usage restreint »                : chiffrement, signature, serveur web… ;
    - « Inactif »                        : modèle non publié sur une CA.
* une **exposition** : « Large » si des groupes non privilégiés peuvent s'inscrire, sinon « Restreinte » ;
* un **niveau de risque** et la liste des ESC qui le concernent.

Les autorités de certification elles-mêmes sont toujours des actifs Tier 0.
"""

from __future__ import annotations

from .. import constants as c
from ..models import SEVERITY_ORDER, Finding, Severity, Snapshot, TemplateClassification

CLASS_T0 = "T0 – Chemin vers Domain Admin"
CLASS_AUTH = "Authentification"
CLASS_AGENT = "Agent d'inscription"
CLASS_RESTRICTED = "Usage restreint"
CLASS_INACTIVE = "Inactif (non publié)"


def classify_templates(snap: Snapshot, findings: list[Finding]) -> list[TemplateClassification]:
    pki_findings = [f for f in findings if f.rule_id.startswith("PKI-")]
    out: list[TemplateClassification] = []

    for t in snap.pki.templates:
        related = [f for f in pki_findings if t.name in f.affected]
        esc = sorted({f.rule_id.removeprefix("PKI-") for f in related})
        worst = min((f.severity for f in related), key=lambda s: SEVERITY_ORDER[s], default=None)
        broad = any(snap.is_low_privileged(s) for s in t.enroll_principals)

        raisons: list[str] = []
        if not t.enabled:
            classe = CLASS_INACTIVE
        elif worst == Severity.CRITICAL:
            classe = CLASS_T0
        elif c.EKU_CERT_REQUEST_AGENT in t.ekus:
            classe = CLASS_AGENT
        elif t.allows_authentication:
            classe = CLASS_AUTH
        else:
            classe = CLASS_RESTRICTED

        if t.allows_authentication:
            ekus = [c.EKU_NAMES.get(e, e) for e in t.ekus] or ["aucun EKU (tous usages)"]
            raisons.append("EKU d'authentification : " + ", ".join(ekus))
        if t.enrollee_supplies_subject:
            raisons.append("le demandeur fournit le sujet/SAN")
        if t.requires_manager_approval:
            raisons.append("approbation manager requise (atténuation)")
        if t.key_size < 2048:
            raisons.append(f"clé faible ({t.key_size} bits)")
        if t.schema_version == 1:
            raisons.append("schéma v1 (non modifiable, concerné par EKUwu)")

        risque = worst or _baseline_risk(classe, broad)
        out.append(
            TemplateClassification(
                template=t.name,
                classe=classe,
                exposition="Large" if broad else "Restreinte",
                risque=risque,
                esc=esc,
                raisons=raisons,
            )
        )
    return sorted(out, key=lambda x: (SEVERITY_ORDER[x.risque], x.template))


def _baseline_risk(classe: str, broad: bool) -> Severity:
    if classe == CLASS_INACTIVE:
        return Severity.INFO
    if classe in (CLASS_AUTH, CLASS_AGENT):
        return Severity.MEDIUM if broad else Severity.LOW
    return Severity.LOW if broad else Severity.INFO
