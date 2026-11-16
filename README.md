# ADSentry

Audit de sécurité **Active Directory + PKI (ADCS) + Entra ID**, mappé sur **MITRE ATT&CK**, avec
**analyse IA 100 % locale** (Ollama) et livré sous forme d'**appliance Linux**.

- **230 règles** déterministes, score de risque 0-100 sur 6 catégories : objets obsolètes, comptes à
  privilèges, approbations, anomalies, **PKI / Certificats**, **Entra ID**
- Couverture complète des contrôles d'hygiène AD classiques : comptes, délégations, Kerberos, GPO,
  protocoles, DNS, approbations, RODC, ACL et chemins de contrôle
- **Au-delà** : ADCS ESC1 → ESC16 complet, 34 règles Entra ID
  (MFA, accès conditionnel, PIM, applications à permissions dangereuses, secrets de principaux de
  service, fédération…), corrélations hybrides AD ↔ Entra, chemins de contrôle, BadSuccessor (dMSA)
- **Classification** de chaque modèle de certificat (T0 / Authentification / Agent / Restreint / Inactif)
- **MITRE ATT&CK v20** : chaque constat est relié à des techniques ; export ATT&CK Navigator ; les
  techniques révoquées sont détectées et leur remplaçant proposé (`adsentry mitre-check`)
- **IA locale** : explication pour la direction et les équipes, plan de remédiation, garde-fou
  anti-hallucination ; RAG puis fine-tuning optionnel
- **Appliance** Debian 13 durcie (Packer) : Docker Compose, HTTPS, planification des scans,
  secrets chiffrés, tableau de bord web

## Console web

Tout se pilote depuis le navigateur : cibles AD / Entra ID et leurs secrets (chiffrés), test de connexion,
lancement des scans avec avancement en direct, planification, synthèse IA, rapports et tableaux de bord.
Deux rôles : **Administrateur** (gestion complète) et **Lecteur** (consultation des évaluations).
Chaque constat dispose d'un **script PowerShell de correction** (simulation par défaut, sauvegarde, vérification
du domaine), téléchargeable seul ou en archive ; voir [docs/SCRIPTS.md](docs/SCRIPTS.md).
Notifications (cloche, bureau, e-mail, Teams/Slack), **SIEM** (Syslog CEF, Splunk HEC), **ITSM** (Jira,
ServiceNow), **API documentée** (Swagger) avec jetons d'accès : voir [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).
La vue **Topologie** dessine les chemins des comptes et groupes à risque vers le Tier 0, et la carte des
approbations entre domaines et forêts avec une simulation de compromission.

Trois façons de l'exécuter sous Linux :

| Mode | Pour | Documentation |
|---|---|---|
| Appliance (VM Debian 13 + Docker Compose + HTTPS) | production | [docs/APPLIANCE.md](docs/APPLIANCE.md) |
| Service systemd sans Docker | serveur Linux existant | [docs/INSTALL-LINUX.md](docs/INSTALL-LINUX.md) |
| Processus unique | développement, démonstration | ci-dessous |

## Démarrage rapide (développement)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
pytest
adsentry serve --worker --web appliance/web        # console sur http://127.0.0.1:8000
```

Au premier lancement, la console demande le **jeton d'installation** affiché dans le terminal pour créer
l'administrateur. Importez ensuite `tests/fixtures/vulnerable_snapshot.json` (bouton « Importer un snapshot »)
pour une démonstration sans AD.

En ligne de commande :

```bash
adsentry scan tests/fixtures/vulnerable_snapshot.json -o result.json
adsentry user add alice --role viewer                # comptes de la console (admin | viewer)
```

Collecte réelle (lab uniquement tant que la phase 1 n'est pas validée) :

```bash
adsentry collect --dc 10.0.0.10 --domain lab.local --user auditeur -o snapshot.json
adsentry collect-entra --tenant <id> --client <id> --cert entra.pem --thumbprint <x> --merge snapshot.json -o snapshot.json
adsentry scan snapshot.json
```

## Documentation

| Document | Contenu |
|---|---|
| [docs/ROADMAP.md](docs/ROADMAP.md) | phases de développement (à suivre avec `/phase <n>` dans Claude Code) |
| [docs/APPLIANCE.md](docs/APPLIANCE.md) | construction, flux réseau, comptes et rôles, exploitation de l'appliance |
| [docs/INSTALL-LINUX.md](docs/INSTALL-LINUX.md) | installation sur un serveur Linux sans Docker (systemd) |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | notifications, SIEM, Jira / ServiceNow, API et jetons |
| [docs/SCRIPTS.md](docs/SCRIPTS.md) | scripts PowerShell de correction : sortes, garanties, exécution |
| [docs/COUVERTURE.md](docs/COUVERTURE.md) | ce qui est contrôlé dans l'AD et Entra ID, et ce qui ne l'est pas encore |
| [docs/ENTRA.md](docs/ENTRA.md) | création de l'application d'audit Entra ID (lecture seule) |
| [lab/README.md](lab/README.md) | lab de test et vérité terrain |

## Avertissement

Outil défensif, en lecture seule. À utiliser uniquement sur des systèmes que vous administrez ou
avec une autorisation écrite.
