"""Brouillon de script de correction rédigé par l'IA locale, pour les règles sans modèle vérifié.

Le brouillon n'est accepté qu'après validate_ai_body (commandes interdites, simulation obligatoire, accolades) ;
il est enregistré à part (<scan>.scripts.json) et toujours présenté comme « à relire ».
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from ..models import ScanResult
from ..rules.engine import load_rules
from .generator import build_ai_script, templates

SYSTEM = """Tu écris le CORPS d'un script PowerShell de correction de sécurité pour Active Directory ou Entra ID.
L'en-tête est déjà fourni : il définit $Targets (objets concernés, chaînes), $Domain, $DomainSid, et les fonctions
Invoke-Change "description" { action }, Save-State -Name n -InputObject o, Get-AdsPrincipal -Name n -Properties p.
Règles impératives :
1. Toute commande qui modifie quelque chose (Set-, Add-, Remove-, Disable-, Enable-, New-, Clear-...) est placée
   DANS un bloc Invoke-Change. Rien n'est modifié en dehors.
2. Appelle Save-State sur chaque objet avant de le modifier.
3. N'utilise que les modules ActiveDirectory, GroupPolicy ou Microsoft.Graph et des commandes qui existent.
4. Interdit : supprimer des objets de l'annuaire, réinitialiser des mots de passe, télécharger quoi que ce soit,
   Invoke-Expression, code encodé, Start-Process, modifier $Apply.
5. Si la correction ne peut pas être automatisée sans risque, écris un script qui affiche les objets et les étapes
   manuelles (Write-Host), sans rien modifier.
6. Commentaires et messages en français. Réponds uniquement avec le code, dans un bloc ```powershell."""


def _example() -> str:
    return templates()["A-ASREP-ROASTABLE"]["body"]


def _extract(text: str) -> str:
    m = re.search(r"```(?:powershell|ps1|pwsh)?\s*\n(.*?)```", text, re.S | re.I)
    if not m or not m.group(1).strip():
        raise ValueError("réponse sans bloc de code PowerShell")
    return m.group(1).strip()


def draft_script(scan_id: str, result: ScanResult, rule_id: str, data_dir: Path, client=None) -> dict:
    from ..ai.admin import load_settings
    from ..ai.ollama_client import OllamaClient

    rule = next(r for r in load_rules() if r.id == rule_id)
    finding = next(f for f in result.findings if f.rule_id == rule_id)
    settings = load_settings()
    client = client or OllamaClient(model=settings.analyst_model)
    user = (
        f"Constat {rule.id} : {rule.title}\nRisque : {finding.description}\nCorrection recommandée : "
        f"{finding.remediation}\nDétection : {finding.detection or '—'}\n"
        f"Objets concernés (extrait) : {', '.join(finding.affected[:10])}\n"
        f"Cible : {'Entra ID (Microsoft Graph)' if rule.category.value == 'entra_id' else 'Active Directory'}\n\n"
        f"Exemple de corps de script conforme :\n```powershell\n{_example()}```"
    )
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    last_error = None
    for _ in range(2):  # un second essai avec la liste des erreurs
        reply = client.chat(messages, temperature=0.1)
        try:
            body = _extract(reply)
            script = build_ai_script(rule, finding, result, body)
        except ValueError as exc:
            last_error = str(exc)
            messages += [
                {"role": "assistant", "content": reply},
                {"role": "user", "content": f"{last_error}. Corrige le script en respectant les règles."},
            ]
            continue
        path = data_dir / f"{scan_id}.scripts.json"
        drafts = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        drafts[rule_id] = {
            "body": body,
            "generated_at": datetime.now(UTC).isoformat(),
            "model": settings.analyst_model,
            "warnings": script.warnings,
        }
        path.write_text(json.dumps(drafts, ensure_ascii=False, indent=1), encoding="utf-8")
        return {"rule_id": rule_id, "warnings": script.warnings}
    raise RuntimeError(last_error or "Brouillon refusé")
