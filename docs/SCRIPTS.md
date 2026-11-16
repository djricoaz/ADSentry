# Scripts PowerShell de correction

Chaque constat d'un rapport dispose d'un script PowerShell, visible dans la fiche du constat (« Script de
correction PowerShell ») et téléchargeable seul ou avec tous les autres (bouton « Scripts PowerShell (.zip) » de
la liste des constats). Les scripts sont générés pour le domaine du rapport et pour les objets réellement
concernés.

**ADSentry n'exécute jamais ces scripts.** L'outil reste en lecture seule ; un administrateur relit le script,
le teste, puis le lance lui-même.

## Les quatre sortes de scripts

| Sorte | Signification |
|---|---|
| **Correction** | modèle écrit et vérifié pour la règle : il corrige le constat |
| **Atténuation** | réduit le risque ; une action complémentaire est indiquée (changer un mot de passe, passer en gMSA, modifier une option de sécurité dans la console GPMC…) |
| **Guide** | aucune modification : liste les objets et rappelle la marche à suivre (règles dont la correction dépend du contexte : ADCS, approbations, chemins de contrôle…) |
| **Brouillon de l'IA — à relire** | proposé par l'IA locale pour une règle sans modèle (bouton « Proposer un script avec l'IA », administrateurs) |

## Garanties de chaque script

- **Simulation par défaut** : sans `-Apply`, le script affiche `[SIMULATION] …` pour chaque modification
  prévue et ne change rien.
- **Bon domaine** : le script refuse de s'exécuter si le domaine (ou le tenant Entra) n'est pas celui du rapport.
- **Sauvegarde** de l'état de chaque objet avant modification (`Export-Clixml`, `Backup-GPO`) et **journal**
  complet de la session (`Start-Transcript`), dans un dossier daté (`-BackupPath` pour le choisir).
- **Aucune injection** : les noms d'objets venant de l'annuaire sont insérés comme chaînes littérales.
- Contrôlé par les tests : toute commande modifiante se trouve dans un bloc `Invoke-Change` (simulation).

## Exécution

Sur un poste d'administration (Tier 0 pour l'AD) disposant des modules nécessaires :

| Module | Pour | Installation |
|---|---|---|
| ActiveDirectory | comptes, groupes, délégations, domaine | RSAT : `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| GroupPolicy | règles de GPO | RSAT : `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0` |
| Microsoft.Graph | règles Entra ID | `Install-Module Microsoft.Graph -Scope CurrentUser` |

```powershell
.\A-ASREP-ROASTABLE.ps1          # simulation : lire la sortie
.\A-ASREP-ROASTABLE.ps1 -Apply   # application, après relecture et test
```

Si la stratégie d'exécution bloque le fichier téléchargé : `Unblock-File .\A-ASREP-ROASTABLE.ps1`.

## Règles de GPO

Le script générique modifie les paramètres de registre de la GPO (`Set-GPRegistryValue`,
`Remove-GPRegistryValue`) après `Backup-GPO`. Si la valeur est une **option de sécurité** (fichier
`GptTmpl.inf`), ces commandes ne s'appliquent pas : le script l'indique, donne le chemin dans la console de
gestion des stratégies de groupe, et ne modifie rien. Pour les paramètres manquants, la GPO visée par défaut est
la Default Domain Policy ou la Default Domain Controllers Policy : une GPO dédiée est préférable (`$TargetGpo`).

## Brouillons de l'IA

Le brouillon n'est enregistré que s'il passe le garde-fou : pas d'exécution de code dynamique ni de code
encodé, pas d'accès réseau, pas de suppression d'objets ni de réinitialisation de mot de passe, pas de lancement
de processus, toute modification dans un bloc de simulation, accolades équilibrées. Les commandes inconnues sont
signalées. En cas de refus, l'IA a droit à un second essai avec la liste des erreurs. Un brouillon reste un
point de départ : il doit être relu et testé comme n'importe quel script.

## Pour les développeurs

Modèles : `src/adsentry/remediation/templates.yaml` (conventions en tête de fichier). Générateur et garde-fou :
`src/adsentry/remediation/generator.py`. Les tests (`tests/test_remediation.py`) vérifient la syntaxe de tous
les scripts, la simulation obligatoire et l'échappement ; sur une machine où `pwsh` est installé, ils passent en
plus chaque script au parseur officiel de PowerShell.
