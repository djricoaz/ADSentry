---
description: Ajoute une nouvelle règle de détection (YAML + check + fixture + tests)
argument-hint: <description de la faiblesse à détecter>
---

Ajoute une règle de détection pour : $ARGUMENTS

Suis STRICTEMENT la procédure « Ajouter ou modifier une règle » de CLAUDE.md :

1. Vérifie qu'aucune règle existante ne couvre déjà ce cas (`grep` dans `src/adsentry/rules/catalog/`).
2. Propose : identifiant, catégorie, sévérité/points, techniques MITRE ATT&CK, données du Snapshot nécessaires
   (existantes ou à ajouter). Si des données doivent être collectées hors LDAP, dis-le.
3. Implémente : YAML (titre, description, remédiation, détection, références publiques), fonction `@check`,
   cas positif (vulnerable) ET sûr (hardened) dans tests/fixtures/build_fixtures.py.
4. Lance `pytest` et `ruff check src tests` ; corrige jusqu'au vert.
5. Résume en 5 lignes : ce qui est détecté, ce qui ne l'est pas (limites), et les données manquantes éventuelles.

Rappels : détection uniquement (aucun code ni commande d'exploitation), textes en français rédigés par nous.
