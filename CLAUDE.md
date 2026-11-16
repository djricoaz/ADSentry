# CLAUDE.md — ADSentry

Outil d'audit de sécurité Active Directory + PKI/ADCS + Entra ID, mappé sur MITRE ATT&CK, avec analyse en langage naturel par un modèle
local (Ollama), livré en appliance Linux (Docker Compose + image Packer Debian 13).
Langue des textes utilisateur : **français**.

## Architecture (lire avant toute modification)

```
collecte (lecture seule)        →  Snapshot JSON  →  moteur de règles (déterministe)  →  ScanResult
  collectors/ldap_collector         models.py          rules/catalog/*.yaml              ├─ scoring.py
  collectors/sysvol_collector                          rules/checks/*.py                 ├─ pki/classification.py
  collectors/probes                                                                      ├─ mitre/navigator.py
  collectors/entra_collector                                                             └─ ai/ (explique, ne décide pas)
appliance/ (runner, planificateur, secrets)  ·  api/ (FastAPI)  ·  appliance/web (tableau de bord)
```

- `src/adsentry/models.py` : Snapshot (données collectées) et Rule/Finding/ScanResult.
- `src/adsentry/rules/catalog/*.yaml` : UNE source de vérité pour titre, sévérité, points, MITRE, remédiation, détection.
- `src/adsentry/rules/checks/*.py` : fonctions `@check("nom")`, pures, sans réseau, entrée = Snapshot.
- `src/adsentry/collectors/` : seule couche qui parle à l'AD et à Graph ; `gpo_parsers.py` = fonctions pures.
- `src/adsentry/appliance/` : cibles (`targets.yaml`), secrets chiffrés, cron, exécution des scans.
- `appliance/` : Docker Compose, Caddy, tableau de bord, systemd, assistant, Packer.
- `src/adsentry/ai/` : client Ollama, prompts, RAG, garde-fou anti-hallucination.
- `ai/` : Modelfile, génération du dataset, script de fine-tuning (Colab).
- `docs/ROADMAP.md` : phases de développement, à suivre dans l'ordre.

## Règles d'or (non négociables)

1. **Lecture seule sur l'AD.** Aucune opération d'écriture LDAP/RPC/SMB. Connexions `read_only=True`.
2. **Détection, pas exploitation.** Pas de code qui exploite une ESC ou une faiblesse, pas de commandes
   d'attaque dans les textes, rapports ou prompts. On décrit le risque, la détection et la correction.
3. **Inconnu ≠ vulnérable.** Une donnée non collectée vaut `None` et la règle ne se déclenche pas
   (sauf mention explicite). Ne jamais deviner une valeur.
4. **L'IA n'invente rien.** Constats et scores viennent uniquement du moteur de règles. L'IA explique,
   priorise et rédige ; `guard_against_hallucinations` doit rester appliqué à toute sortie du modèle.
5. **Aucune donnée réelle** (snapshot client, noms, SIDs) dans le dépôt, les tests ou le dataset d'entraînement.
6. **MITRE ATT&CK** : ne jamais coder les tactiques en dur (elles changent : v19 a scindé Defense Evasion).
   Toute nouvelle technique référencée doit passer `adsentry mitre-check`.
7. **Propriété intellectuelle** : aucun code, texte, identifiant de règle ou nom de produit d'un outil d'audit
   tiers (commercial ou sous licence restrictive) dans le dépôt, le produit, les tests ou la documentation.
   Rédiger nos propres textes à partir des sources publiques (Microsoft, ANSSI, MITRE, recherches publiées)
   citées en `references`. Ne jamais exécuter un outil tiers à licence non commerciale pour développer ou
   valider ADSentry ; la validation se fait sur la vérité terrain du lab.
8. **Appliance** : conteneurs non root, lecture seule, aucun port publié hors Caddy ; seul `worker` sort du réseau
   interne. Les secrets ne sont jamais écrits en clair (SecretStore) ni journalisés.
9. **Entra** : permissions Graph en lecture uniquement ; une donnée non licenciée (403) reste à None.

## Ajouter ou modifier une règle (procédure obligatoire)

1. Entrée YAML dans le bon fichier du catalogue (id `S-|P-|T-|A-|PKI-|E-`, barème : critique 40-50,
   élevé 20-30, moyen 10-15, faible 5) avec `remediation`, `detection`, `mitre`, `references`.
2. Fonction `@check` dans `rules/checks/<catégorie>.py`.
3. Cas positif dans `vulnerable()` ET configuration sûre dans `hardened()` de `tests/fixtures/build_fixtures.py`,
   puis `python tests/fixtures/build_fixtures.py` (les tests exigent : tout se déclenche sur « vulnérable »,
   rien sur « durci »).
4. Assertions précises dans `tests/test_engine.py` si la logique est subtile.
5. Si le Snapshot doit porter une nouvelle donnée : champ optionnel dans `models.py` + collecte dans
   `collectors/` (ou TODO explicite si hors LDAP).
6. `pytest`, `ruff check` et `adsentry mitre-check` verts avant de considérer la tâche terminée.

Raccourci : `/new-rule <description>`.

## Commandes

```bash
pip install -e ".[all]"                         # installation dev
pytest                                          # tests hors réseau
pytest -m network                               # + validation MITRE ATT&CK en ligne
ruff check src tests && ruff format src tests
adsentry scan tests/fixtures/lab_snapshot.json  # démo sans AD
adsentry navigator result.json                  # couche ATT&CK Navigator
adsentry explain result.json                    # analyse IA (Ollama requis)
adsentry serve --worker --web appliance/web     # console + exécution des scans en local
adsentry user add <compte> --role admin|viewer  # comptes de la console
docker compose -f appliance/docker-compose.yml config   # valider la pile de l'appliance
```

## Manière de travailler

- Une phase de `docs/ROADMAP.md` par session ; commencer en mode plan pour les phases 2+.
- Écrire/adapter les tests d'abord, puis le code. Ne pas affaiblir un test pour le faire passer.
- Garder les fonctions de contrôle courtes et pures ; la logique réseau reste dans `collectors/`.
- Toute nouvelle dépendance va dans `pyproject.toml` (extra adapté) avec justification dans le commit.
