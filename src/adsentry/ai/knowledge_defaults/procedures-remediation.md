# Procédures de correction

## Priorités et délais
- Critique : correction ou mesure compensatoire sous [7] jours, information du RSSI immédiate.
- Élevé : correction sous [30] jours.
- Moyen : correction sous [90] jours, regroupable dans un lot.
- Faible : planifiée dans la prochaine campagne d'hygiène.
Un constat qui ouvre un chemin vers le Tier 0 est traité comme critique, quelle que soit sa sévérité affichée.

## Processus de changement
1. Ouvrir un ticket de changement [outil] avec la référence de la règle ADSentry (ex. P-UNCONSTRAINED-DELEGATION).
2. Identifier les applications ou services impactés avec leurs responsables.
3. Exécuter le script ADSentry d'abord en simulation, joindre la sortie au ticket.
4. Tester sur un objet ou une OU pilote, puis appliquer avec -Apply dans la fenêtre de maintenance [créneau].
5. Conserver le dossier de sauvegarde et le journal produits par le script pendant [6] mois.
6. Relancer un scan ADSentry pour vérifier que le constat a disparu.

## Retour arrière
Chaque script sauvegarde l'état des objets avant modification (fichiers XML et sauvegardes de GPO).
En cas de problème : restaurer la GPO avec Restore-GPO depuis le dossier de sauvegarde, ou remettre les
attributs d'origine à partir des fichiers XML, puis prévenir [équipe AD].

## Comptes inactifs
Un compte inactif depuis plus de [180] jours est désactivé, sa description indique la date. Il est supprimé
après [90] jours supplémentaires s'il n'a pas été réclamé. Les comptes de service ne sont jamais désactivés
sans l'accord de leur responsable applicatif.
