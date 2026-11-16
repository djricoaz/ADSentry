"""Scripts PowerShell de correction, générés pour chaque constat à partir de modèles vérifiés.

Principes (non négociables) :
* ADSentry n'exécute jamais ces scripts : il les produit, un administrateur les relit puis les lance ;
* simulation par défaut : rien n'est modifié sans le paramètre -Apply ;
* sauvegarde de l'état avant chaque modification et journal de la session (Start-Transcript) ;
* le script refuse de s'exécuter sur un autre domaine (ou tenant) que celui du rapport ;
* les valeurs issues de l'annuaire sont insérées comme chaînes PowerShell littérales (guillemets simples,
  caractères de contrôle retirés) : un nom d'objet ne peut pas injecter de code.

Trois sortes de scripts : modèle écrit à la main (templates.yaml), modèle générique pour les règles de GPO,
guide sans modification pour les autres règles. L'IA peut en outre proposer un brouillon (ai_body), soumis à
validate_ai_body et toujours marqué « à relire ».
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml

from ..models import Finding, Rule, ScanResult

TEMPLATES_PATH = Path(__file__).with_name("templates.yaml")
KIND_LABELS = {
    "fix": "Correction",
    "partial": "Atténuation (action complémentaire nécessaire)",
    "guide": "Guide (aucune modification)",
    "ai": "Brouillon de l'IA — à relire",
}
GPO_CHECKS = {"anom_gpo_registry_bad", "anom_gpo_registry_missing", "anom_gpo_registry_present"}
# Valeur sûre à imposer plutôt que de supprimer la valeur (la valeur par défaut de Windows n'est pas sûre)
GPO_SECURE_VALUE = {"A-LM-HASH": 1, "A-LIMIT-BLANK-PASSWORD": 1, "A-LDAP-SIGNING-GPO": 2, "A-WDIGEST": 0}


@dataclass
class Script:
    rule_id: str
    kind: str
    summary: str
    text: str
    filename: str
    warnings: list[str] = field(default_factory=list)

    @property
    def kind_label(self) -> str:
        return KIND_LABELS[self.kind]

    def public(self, with_text: bool = True) -> dict:
        out = {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "kind_label": self.kind_label,
            "summary": self.summary,
            "filename": self.filename,
            "warnings": self.warnings,
        }
        if with_text:
            out["script"] = self.text
        return out


# ----------------------------------------------------------------------------- échappement


_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]")
_SINGLE_QUOTES = "'‘’‚‛"  # PowerShell traite aussi les guillemets typographiques comme ' (sic)


def ps_quote(value: str) -> str:
    """Chaîne littérale PowerShell sûre : aucun développement ($, `, sous-expressions) entre guillemets simples."""
    s = _CONTROL.sub(" ", str(value))
    for q in _SINGLE_QUOTES:
        s = s.replace(q, q + q)
    return f"'{s}'"


def ps_comment(text: str) -> str:
    """Texte libre en commentaires ligne par ligne (aucun moyen de refermer un bloc de commentaire)."""
    lines = _CONTROL.sub(" ", str(text).replace("\r\n", "\n").replace("\n", " ")).split(" ")
    return "\n".join(f"#   {line.strip()}" for line in lines)


def _slug(rule_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9-]", "_", rule_id)


# ----------------------------------------------------------------------------- modèles


@lru_cache(maxsize=1)
def templates() -> dict:
    return yaml.safe_load(TEMPLATES_PATH.read_text(encoding="utf-8")) or {}


def _targets_block(affected: list[str], mode: str) -> str:
    if mode == "arrow_pair":
        rows = []
        for a in affected:
            left, _, right = a.partition(" → ")
            rows.append(f"    ,@({ps_quote(left.strip())}, {ps_quote(right.strip())})")
        body = "\n".join(rows)
    else:
        values = [a.partition(" → ")[0].strip() if mode == "before_arrow" else a for a in affected]
        body = "\n".join(f"    {ps_quote(v)}" for v in values)
    return f"$Targets = @(\n{body}\n)" if body else "$Targets = @()"


def _header(
    rule: Rule, finding: Finding, result: ScanResult, kind: str, summary: str, module: str, scopes: list[str]
) -> str:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "#Requires -Version 5.1",
        "<#",
        ".SYNOPSIS",
        f"    ADSentry {rule.id} : {_CONTROL.sub(' ', rule.title).replace('#>', '# >')}",
        "",
        ".DESCRIPTION",
        f"    {KIND_LABELS[kind]}. {_CONTROL.sub(' ', summary).replace('#>', '# >')}",
        "    SIMULATION PAR DÉFAUT : rien n'est modifié sans le paramètre -Apply.",
        "    L'état de chaque objet est sauvegardé avant modification, et la session est journalisée.",
        "",
        ".PARAMETER Apply",
        "    Applique réellement les modifications. À n'utiliser qu'après relecture et test.",
        "",
        ".PARAMETER BackupPath",
        "    Dossier de sauvegarde et de journal (par défaut : dossier daté dans le répertoire courant).",
        "",
        ".NOTES",
        f"    Généré par ADSentry le {generated} pour {_CONTROL.sub(' ', result.domain).replace('#>', '# >')},",
        f"    rapport du {result.collected_at:%Y-%m-%d %H:%M}. À relire avant toute exécution.",
        "#>",
        "",
        "# Risque :",
        ps_comment(finding.description),
        "# Correction recommandée :",
        ps_comment(finding.remediation),
    ]
    if finding.detection:
        lines += ["# Détection :", ps_comment(finding.detection)]
    lines += [
        "",
        "[CmdletBinding()]",
        "param(",
        "    [switch]$Apply,",
        "    [string]$BackupPath = (Join-Path -Path (Get-Location) -ChildPath ('ADSentry-"
        + _slug(rule.id)
        + "-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))",
        ")",
        "",
        "Set-StrictMode -Version 2.0",
        "$ErrorActionPreference = 'Stop'",
    ]
    if module == "Microsoft.Graph":
        tenant = result.tenant_id
        lines += [
            "Import-Module Microsoft.Graph.Identity.SignIns",
            f"$TenantId = {ps_quote(tenant) if tenant else '$null'}",
            f"Connect-MgGraph -Scopes {', '.join(ps_quote(s) for s in scopes)} -NoWelcome"
            + (" -TenantId $TenantId" if tenant else ""),
            "if ($TenantId -and (Get-MgContext).TenantId -ne $TenantId) {",
            '    throw "Ce script a été généré pour le tenant $TenantId : connexion à un autre tenant refusée."',
            "}",
        ]
    else:
        domain = result.ad_domain
        lines += [
            "Import-Module ActiveDirectory",
            *(["Import-Module GroupPolicy"] if module == "GroupPolicy" else []),
            f"$Domain = {ps_quote(domain) if domain else '$null'}",
            "$AdDomain = Get-ADDomain",
            "if ($Domain -and $AdDomain.DNSRoot -ne $Domain) {",
            '    throw "Ce script a été généré pour le domaine $Domain, pas pour $($AdDomain.DNSRoot)."',
            "}",
            'if (-not $Domain) { $Domain = $AdDomain.DNSRoot; Write-Warning "Domaine du rapport inconnu : vérifiez que $Domain est le bon." }',
            "$DomainSid = $AdDomain.DomainSID.Value",
        ]
    lines += [
        "",
        "New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null",
        "Start-Transcript -Path (Join-Path -Path $BackupPath -ChildPath 'journal.txt') -Append | Out-Null",
        "if ($Apply) { Write-Warning 'Mode APPLICATION : les modifications vont être effectuées.' }",
        "else { Write-Host 'Mode SIMULATION : aucune modification ne sera effectuée (ajoutez -Apply pour appliquer).' -ForegroundColor Cyan }",
        "",
        "function Invoke-Change {",
        "    param([Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][scriptblock]$Action)",
        "    if ($Apply) {",
        '        Write-Host "[APPLIQUÉ] $Description" -ForegroundColor Yellow',
        "        & $Action",
        "    } else {",
        '        Write-Host "[SIMULATION] $Description" -ForegroundColor Cyan',
        "    }",
        "}",
        "",
        "function Save-State {",
        "    param([Parameter(Mandatory)][string]$Name, $InputObject)",
        "    $file = Join-Path -Path $BackupPath -ChildPath (($Name -replace '[^\\w.-]', '_') + '.xml')",
        "    $InputObject | Export-Clixml -Path $file",
        "}",
    ]
    if module != "Microsoft.Graph":
        lines += [
            "",
            "function Get-AdsPrincipal {",
            "    param([Parameter(Mandatory)][string]$Name, [string[]]$Properties = @())",
            '    $n = $Name -replace "\'", "\'\'"',
            "    $filter = \"sAMAccountName -eq '$n' -or sAMAccountName -eq '$n`$' -or name -eq '$n'\"",
            "    $found = Get-ADObject -Filter $filter -Properties ($Properties + @('sAMAccountName', 'objectSid')) | Select-Object -First 1",
            '    if (-not $found) { Write-Warning "Objet introuvable : $Name" }',
            "    return $found",
            "}",
        ]
    return "\n".join(lines)


def _wrap(header: str, targets: str, body: str) -> str:
    body = "\n".join(("    " + line) if line.strip() else "" for line in body.rstrip().splitlines())
    return (
        f"{header}\n\n# Objets concernés (tirés du rapport)\n{targets}\n\ntry {{\n{body}\n}}\nfinally {{\n"
        "    Stop-Transcript | Out-Null\n}\n"
        "if (-not $Apply) { Write-Host 'Simulation terminée. Relisez la sortie, puis relancez avec -Apply.' -ForegroundColor Cyan }\n"
    )


# ----------------------------------------------------------------------------- règles de GPO (modèle générique)


def _gpo_key(key: str) -> tuple[str, str]:
    hive, _, rest = key.partition("\\")
    path, _, value = rest.rpartition("\\")
    return ("HKLM\\" if hive == "machine" else "HKCU\\") + path, value


def _gpo_body(rule: Rule) -> tuple[str, str, str]:
    """Corps, sorte et résumé pour les règles de registre par GPO."""
    key, value_name = _gpo_key(rule.params["key"])
    security_option = "\\currentcontrolset\\" in rule.params["key"]
    gpmc_hint = (
        "Si la valeur est une option de sécurité (Configuration ordinateur > Stratégies > Paramètres Windows > "
        "Paramètres de sécurité > Options de sécurité), modifiez-la dans la console de gestion des stratégies de groupe."
    )
    q_key, q_value = ps_quote(key), ps_quote(value_name)
    if rule.check == "anom_gpo_registry_missing":
        good = rule.params["good"][0]
        vtype, vlit = ("DWord", str(int(good))) if isinstance(good, int) else ("String", ps_quote(str(good)))
        default_gpo = (
            "Default Domain Controllers Policy" if rule.params.get("scope") == "dcs" else "Default Domain Policy"
        )
        body = f"""$TargetGpo = {ps_quote(default_gpo)}  # adaptez : une GPO dédiée liée au bon périmètre est préférable
Write-Host "Paramètre attendu : {key}\\{value_name} = {good}"
Backup-GPO -Name $TargetGpo -Path $BackupPath | Out-Null
Invoke-Change "Définir {value_name} = {good} dans la GPO $TargetGpo" {{
    Set-GPRegistryValue -Name $TargetGpo -Key {q_key} -ValueName {q_value} -Type {vtype} -Value {vlit} | Out-Null
}}
Write-Warning "Testez sur un périmètre restreint avant de lier la GPO largement."
"""
        return body, "fix", f"Définit {value_name} = {good} par GPO."
    secure = GPO_SECURE_VALUE.get(rule.id)
    if secure is not None:
        action = (
            f"Set-GPRegistryValue -Name $gpo -Key {q_key} -ValueName {q_value} -Type DWord -Value {secure} | Out-Null"
        )
        what, summary = f"Imposer {value_name} = {secure}", f"Impose {value_name} = {secure} dans les GPO concernées."
    else:
        action = f"Remove-GPRegistryValue -Name $gpo -Key {q_key} -ValueName {q_value} | Out-Null"
        what, summary = f"Supprimer {value_name}", f"Retire {value_name} des GPO concernées."
    extra = ""
    if rule.check == "anom_gpo_registry_present":
        extra = (
            "Write-Warning \"Changez immédiatement le mot de passe du compte d'ouverture automatique : "
            'il a été lisible par tous les utilisateurs du domaine."\n'
        )
    body = f"""foreach ($gpo in $Targets) {{
    $current = $null
    try {{ $current = Get-GPRegistryValue -Name $gpo -Key {q_key} -ValueName {q_value} -ErrorAction Stop }} catch {{ }}
    if (-not $current) {{
        Write-Warning "{value_name} n'est pas dans les paramètres de registre de la GPO $gpo. {gpmc_hint}"
        continue
    }}
    Backup-GPO -Name $gpo -Path $BackupPath | Out-Null
    Invoke-Change "{what} dans la GPO $gpo" {{
        {action}
    }}
}}
{extra}"""
    return body, ("partial" if security_option else "fix"), summary


# ----------------------------------------------------------------------------- guide (aucune modification)


def _guide_body(finding: Finding) -> str:
    return f"""Write-Host 'Aucune correction automatique pour cette règle : le script liste les objets et la marche à suivre.'
Write-Host ''
Write-Host 'Objets concernés :'
foreach ($item in $Targets) {{ Write-Host "  - $item" }}
Write-Host ''
Write-Host 'Correction recommandée :'
Write-Host {ps_quote(finding.remediation)}
"""


# ----------------------------------------------------------------------------- construction


def build_script(rule: Rule, finding: Finding, result: ScanResult) -> Script:
    tpl = templates().get(rule.id)
    module = "ActiveDirectory"
    scopes: list[str] = []
    if tpl:
        kind, summary, body = tpl["kind"], tpl["summary"], tpl["body"]
        mode = tpl.get("targets", "raw")
        module = tpl.get("module", "ActiveDirectory")
        scopes = tpl.get("scopes", [])
    elif rule.check in GPO_CHECKS:
        body, kind, summary = _gpo_body(rule)
        mode, module = "raw", "GroupPolicy"
        if rule.check == "anom_gpo_registry_missing":
            finding = finding.model_copy(update={"affected": []})  # le libellé n'est pas une GPO
    else:
        kind, summary, body, mode = (
            "guide",
            "Liste les objets concernés et rappelle la correction.",
            _guide_body(finding),
            "raw",
        )
        if rule.category.value == "entra_id":
            module = "Microsoft.Graph"
            scopes = ["Directory.Read.All"]
    header = _header(rule, finding, result, kind, summary, module, scopes)
    text = _wrap(header, _targets_block(finding.affected, mode), body)
    return Script(rule.id, kind, summary, text, f"{_slug(rule.id)}.ps1")


def build_ai_script(rule: Rule, finding: Finding, result: ScanResult, body: str) -> Script:
    errors, warnings = validate_ai_body(body)
    if errors:
        raise ValueError("Brouillon de l'IA refusé : " + " ; ".join(errors))
    module = "Microsoft.Graph" if rule.category.value == "entra_id" else "ActiveDirectory"
    summary = "Proposition de l'IA locale à partir du constat ; relecture et test obligatoires."
    header = _header(rule, finding, result, "ai", summary, module, ["Directory.Read.All"])
    text = _wrap(header, _targets_block(finding.affected, "raw"), body)
    return Script(rule.id, "ai", summary, text, f"{_slug(rule.id)}.brouillon-ia.ps1", warnings)


# ----------------------------------------------------------------------------- garde-fou des brouillons IA

FORBIDDEN = [
    (r"\b(Invoke-Expression|iex)\b", "exécution de code dynamique"),
    (
        r"(DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|Net\.WebClient|\biwr\b|\birm\b)",
        "accès réseau",
    ),
    (r"(FromBase64String|-EncodedCommand|-enc\b)", "code encodé"),
    (r"\bRemove-AD(Object|User|Computer|Group|OrganizationalUnit|ServiceAccount)\b", "suppression d'objets AD"),
    (r"\b(Remove-Item|Format-Volume|Clear-Disk|Stop-Computer|Restart-Computer)\b", "action destructrice locale"),
    (r"\bSet-ADAccountPassword\b", "réinitialisation de mot de passe"),
    (r"\bStart-Process\b|\bcmd(\.exe)?\s*/c\b", "lancement de processus"),
    (r"\$Apply\s*=", "modification du mode simulation"),
]
# Verbes qui modifient : toute commande de ce type doit être dans un bloc Invoke-Change
MODIFYING = re.compile(
    r"\b(Set|Add|Remove|Disable|Enable|New|Clear|Move|Rename|Grant|Revoke|Update|Restore|Unlock)-"
    r"(AD|GP|Mg)[A-Za-z]+\b"
)
KNOWN_PREFIXES = ("AD", "GP", "Mg")


def _code_only(text: str) -> str:
    """Retire le texte des chaînes et des commentaires, en gardant le code des sous-expressions $( ) qui, elles,
    s'exécutent même entre guillemets doubles."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("<#", i):
            end = text.find("#>", i + 2)
            i = n if end < 0 else end + 2
            continue
        if ch == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if ch == "'":
            i += 1
            while i < n and not (text[i] == "'" and not text.startswith("''", i)):
                i += 2 if text.startswith("''", i) else 1
            out.append("''")
            i += 1
            continue
        if ch == '"':
            i += 1
            out.append('"')
            while i < n and text[i] != '"':
                if text[i] == "`":
                    i += 2
                    continue
                if text.startswith("$(", i):
                    depth, j = 1, i + 2
                    while j < n and depth:
                        depth += {"(": 1, ")": -1}.get(text[j], 0)
                        j += 1
                    out.append(" " + text[i + 2 : j - 1] + " ")  # code exécuté : conservé pour l'analyse
                    i = j
                    continue
                i += 1
            out.append('"')
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def validate_ai_body(body: str) -> tuple[list[str], list[str]]:
    """Erreurs bloquantes et avertissements pour un corps de script proposé par l'IA."""
    errors: list[str] = []
    warnings: list[str] = []
    code = _code_only(body)
    for pattern, label in FORBIDDEN:
        if re.search(pattern, code, re.IGNORECASE):
            errors.append(f"commande interdite ({label})")
    # Chaque commande modifiante doit se trouver dans un bloc { } ouvert par Invoke-Change : on calcule, pour
    # chaque position du code, si l'on est à l'intérieur d'un tel bloc.
    stack: list[bool] = []
    inside = [False] * (len(code) + 1)
    pending = False  # « Invoke-Change » vu, en attente de son accolade
    i = 0
    while i < len(code):
        if code.startswith("Invoke-Change", i):
            pending = True
        ch = code[i]
        if ch == "{":
            stack.append(pending)
            pending = False
        elif ch == "}" and stack:
            stack.pop()
        elif ch == "\n":
            pending = False
        inside[i] = any(stack)
        i += 1
    for m in MODIFYING.finditer(code):
        if not inside[m.start()]:
            errors.append(f"{m.group(0)} hors d'un bloc Invoke-Change (simulation non garantie)")
    if stack:
        errors.append("accolades non équilibrées")
    cmdlets = set(re.findall(r"\b([A-Z][a-z]+-[A-Za-z]+)\b", code))
    unknown = sorted(c for c in cmdlets if not c.split("-", 1)[1].startswith(KNOWN_PREFIXES) and c not in CORE_CMDLETS)
    if unknown:
        warnings.append("Commandes à vérifier (non reconnues) : " + ", ".join(unknown))
    return sorted(set(errors)), warnings


CORE_CMDLETS = {
    "Write-Host",
    "Write-Warning",
    "Write-Output",
    "Write-Verbose",
    "Get-Date",
    "Get-Acl",
    "Set-Acl",
    "Select-Object",
    "Where-Object",
    "ForEach-Object",
    "Sort-Object",
    "Group-Object",
    "Measure-Object",
    "Export-Clixml",
    "Export-Csv",
    "Import-Module",
    "Get-Content",
    "Test-Path",
    "Join-Path",
    "Get-Location",
    "Invoke-Change",
    "Save-State",
    "Get-AdsPrincipal",
    "Out-Null",
    "Format-Table",
    "Format-List",
    "Get-Member",
    "Get-ItemProperty",
    "New-Object",
    "Read-Host",
    "Start-Sleep",
}
