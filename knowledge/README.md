# Base de connaissances (RAG)

Déposer ici des fichiers Markdown que l'analyste IA pourra citer : procédures internes de
remédiation, politique Tier 0, contacts des équipes, résumés de guides (ANSSI, Microsoft).

- Un fichier par sujet, sections `## Titre` (le découpage se fait par section).
- Résumer avec vos propres mots plutôt que copier des documents protégés.
- Pas de secrets (mots de passe, clés) : ces textes sont envoyés au modèle.

Puis : `adsentry rag-index --knowledge knowledge`
