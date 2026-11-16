# Roadmap ADSentry

Chaque phase se lance dans Claude Code avec `/phase <n>` (voir `.claude/commands/phase.md`).
Une phase = une ou plusieurs sessions ; `/clear` entre deux phases ; commit git à chaque étape verte.

---

## Phase 0 — Socle ✅

- [x] Modèle de données `Snapshot` (AD + Entra) / `Rule` / `Finding` / `ScanResult`
- [x] Moteur de règles YAML + registre `@check` ; périmètres AD / Entra (règles « non évaluées »)
- [x] **216 règles** : 39 objets obsolètes, 52 privilèges, 11 approbations, 58 anomalies, 27 PKI, 29 Entra ID
- [x] Classification des modèles de certificats
- [x] MITRE ATT&CK v20.1 validé en ligne, gestion des techniques révoquées
- [x] Analyseurs SYSVOL (GptTmpl.inf, Registry.pol, audit.csv, scripts.ini, préférences XML)
- [x] Collecteurs : LDAP étendu, SYSVOL (SMB), sondes réseau, Microsoft Graph (testé sur Graph simulé)
- [x] IA : client Ollama (JSON structuré), RAG, garde-fou, dataset (AD + Entra), script de fine-tuning
- [x] Appliance : Dockerfile, Docker Compose durci, Caddy HTTPS, planificateur cron, secrets chiffrés,
      tableau de bord web, assistant `adsentry-setup`, image Packer Debian 13
- [x] Console web : menu latéral, espace **Pilotage** (tableau de bord KPI, évolution de la maturité,
      comparaison de rapports) et espace **Résultats** (vue du scan, constats, ADCS, Entra ID, matrice ATT&CK, synthèse)
- [x] Historisation : maturité 1-5, taux et délai moyen de correction, cycle de vie des constats (réapparitions)
- [x] Domaines de test « vulnérable » (toutes les règles se déclenchent) et « durci » (aucune) — 39 tests (dont 1 en ligne)

## Phase 1 — Validation sur lab (AD + ADCS)

Objectif : prouver que la collecte produit un Snapshot juste sur un vrai domaine.

- [ ] Monter le lab (`lab/README.md`) avec les mauvaises configurations listées
- [ ] `adsentry collect` : corriger le collecteur LDAP (formats ldap3, descripteurs de sécurité, métadonnées
      de réplication, DNS, RODC) — chaque champ du Snapshot vérifié à la main une fois
- [ ] Vérifier le GUID de classe dMSA (`GUID_DMSA_CLASS`) sur un DC 2025
- [ ] **Vérité terrain** : `tests/test_lab.py` vérifie que chaque faille créée dans le lab est trouvée (et
      disparaît après correction) ; contrôle croisé PKI avec `certipy find -vulnerable -json`
- [ ] SYSVOL : lecture des ACL NTFS des scripts et fichiers déployés (règles P-DELEGATION-LOGIN-SCRIPT/FILE)
- [ ] Sondes : valider sur DC 2016/2019/2022/2025 (signature LDAP/SMB, channel binding, pipes de coercition)
- [ ] Kerberos (en plus de NTLM) pour la collecte ; performances sur 100 000 objets

## Phase 1 bis — Validation Entra ID

- [ ] Tenant de développement Microsoft 365 (gratuit) + application d'audit (`docs/ENTRA.md`)
- [ ] Vérifier chaque appel Graph (pagination, `$expand`, licences P1/P2 absentes → None)
- [ ] Version d'Entra Connect : la récupérer côté serveur Connect ou AD (aujourd'hui saisie manuelle)
- [ ] Règles supplémentaires : comptes d'urgence exclus de l'accès conditionnel, enregistrement d'appareils,
      méthodes d'authentification faibles (SMS/voix), journaux d'audit non exportés

## Phase 2 — Collecte hors LDAP restante

- [ ] CA par registre distant (impacket RRP) : `EditFlags`, `InterfaceFlags`, `DisableExtensionList`,
      ACL ManageCA/ManageCertificates → ESC6, ESC7, ESC11, ESC16
- [ ] Sonde HTTP/HTTPS `/certsrv` (NTLM proposé ? EPA ?) → ESC8 ; correctif CVE-2024-49019 → ESC15
- [ ] Registre des DC : `StrongCertificateBindingEnforcement`, `CertificateMappingMethods` → ESC9/ESC10
- [ ] Date de dernière mise à jour des DC (S-DC-NOT-UPDATED), transferts de zone DNS (sonde AXFR)
- [ ] Import de résultats de scanners de vulnérabilités (MS17-010, MS14-068) et de Certipy/BloodHound
- [ ] Détection ROCA sur les certificats (empreinte de module)

## Phase 3 — Rapports

- [ ] Rapport HTML autonome + PDF (jauges, constats, classification PKI, matrice MITRE)
- [ ] Anonymisation (pseudonymes stables) pour partage externe
- [ ] Comparaison entre scans (tendance, nouveaux / corrigés) et alertes (e-mail, syslog/SIEM)
- [ ] Mapping conformité : points de contrôle ANSSI AD, CIS, NIST CSF (champ `compliance`)

## Phase 4 — Dashboard complet et sécurité de l'appliance

- [x] Tableau de bord interactif : synthèse en langage clair, KPI cliquables avec tendances et aide contextuelle,
      filtre de période (KPI recalculés), graphiques cliquables, priorités d'action, suivi des corrections,
      mise à jour automatique, impression / PDF, export CSV des constats, guide de lecture pour les lecteurs
- [ ] Export PDF des comparaisons ; objectifs de maturité par périmètre
- [x] Comptes locaux et rôles **administrateur / lecteur** à la place du basic auth ; sessions, verrouillage,
      protection CSRF, journal d'audit de la console, assistant de premier démarrage (jeton d'installation)
- [ ] **Authentification OIDC Entra ID** + rôle intermédiaire « analyste »
- [ ] SQLite/PostgreSQL au lieu des fichiers JSON ; historique et tendances
- [x] Gestion des cibles et des secrets depuis l'interface ; test de connexion ; lancement de scan avec progression
      (file de tâches API → worker) ; planification ; synthèse IA en tâche de fond
- [ ] Heatmap ATT&CK (tactiques lues depuis le STIX), graphe des chemins d'attaque
- [ ] Chat « analyste IA » contextualisé sur un constat

## Phase 5 — IA locale (dans cet ordre)

1. [ ] `adsentry-setup` télécharge le modèle ; vérifier les temps de réponse CPU sur l'appliance
2. [ ] Alimenter `knowledge/` puis `adsentry rag-index`
3. [ ] **Banc d'évaluation** `ai/eval/` : 30 scans de référence, métriques (JSON valide, règles inventées,
      couverture des critiques, latence) + grille humaine
4. [ ] 30 à 50 analyses « gold » relues dans `ai/dataset/gold/`
5. [ ] Seulement si nécessaire : fine-tuning Colab, import GGUF, comparaison avant/après

## Phase 6 — Industrialisation de l'appliance

- [ ] CI : ruff, pytest, `mitre-check` hebdomadaire, construction Docker + Packer, scan de vulnérabilités des images
- [ ] Signature des images, mises à jour de l'appliance (canal stable), sauvegarde/restauration de la config
- [ ] Chiffrement du disque (vTPM) ; journal d'audit de l'outil ; export syslog
- [ ] Documentation utilisateur, politique de licence

## Phase 7 — Extensions

- [ ] Multi-forêts / multi-tenants, cartographie des approbations
- [ ] Graphe de chemins d'attaque complet (AD + Entra + ADCS)
- [ ] Autres annuaires cloud (Okta…) si besoin
