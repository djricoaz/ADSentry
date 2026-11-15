# ADSentry

Audit de sécurité **Active Directory + PKI (ADCS) + Entra ID**, mappé sur **MITRE ATT&CK**, avec
**analyse IA 100 % locale** (Ollama) et livré sous forme d'**appliance Linux**.

- **216 règles** déterministes, score de risque 0-100 sur 6 catégories : objets obsolètes, comptes à
  privilèges, approbations, anomalies, **PKI / Certificats**, **Entra ID**
- Couverture complète des contrôles d'hygiène AD classiques : comptes, délégations, Kerberos, GPO,
  protocoles, DNS, approbations, RODC, ACL et chemins de contrôle
- **Au-delà** : ADCS ESC1 → ESC16 complet, 29 règles Entra ID
  (MFA, accès conditionnel, PIM, applications à permissions dangereuses, secrets de principaux de
  service, fédération…), corrélations hybrides AD ↔ Entra, chemins de contrôle, BadSuccessor (dMSA)
- **Classification** de chaque modèle de certificat (T0 / Authentification / Agent / Restreint / Inactif)
- **MITRE ATT&CK v20** : chaque constat est relié à des techniques ; export ATT&CK Navigator ; les
  techniques révoquées sont détectées et leur remplaçant proposé (`adsentry mitre-check`)
- **IA locale** : explication pour la direction et les équipes, plan de remédiation, garde-fou
  anti-hallucination ; RAG puis fine-tuning optionnel
- **Appliance** Debian 13 durcie (Packer) : Docker Compose, HTTPS, planification des scans,
  secrets chiffrés, tableau de bord web

## Démarrage rapide (développement)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
pytest
adsentry scan tests/fixtures/vulnerable_snapshot.json -o result.json
ADSENTRY_WEB_DIR=appliance/web adsentry serve      # tableau de bord sur http://127.0.0.1:8000
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
| [docs/APPLIANCE.md](docs/APPLIANCE.md) | construction, flux réseau, exploitation de l'appliance |
| [docs/ENTRA.md](docs/ENTRA.md) | création de l'application d'audit Entra ID (lecture seule) |
| [lab/README.md](lab/README.md) | lab de test et vérité terrain |

## Avertissement

Outil défensif, en lecture seule. À utiliser uniquement sur des systèmes que vous administrez ou
avec une autorisation écrite.
