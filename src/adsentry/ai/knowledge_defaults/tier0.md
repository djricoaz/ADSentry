# Modèle d'administration et Tier 0

## Définition du Tier 0
Le Tier 0 regroupe tout ce qui permet de contrôler l'annuaire : contrôleurs de domaine, comptes et groupes
d'administration du domaine (Domain Admins, Enterprise Admins, Schema Admins, Administrators, groupes
d'opérateurs), autorités de certification d'entreprise, serveur Entra Connect, serveurs de sauvegarde des DC,
et comptes qui ont des droits de réplication ou de modification sur l'objet domaine ou AdminSDHolder.
Tout ce qui peut agir sur un élément Tier 0 est lui-même Tier 0.

## Règles de cloisonnement
- Un compte Tier 0 ne se connecte qu'aux systèmes Tier 0 et aux postes d'administration dédiés.
- Aucune connexion d'un compte Tier 0 sur un poste utilisateur ou un serveur applicatif (Tier 1 ou Tier 2).
- Chaque administrateur a un compte nominatif séparé pour l'administration, sans messagerie ni navigation web.
- Le compte Administrator intégré n'est utilisé qu'en secours ; son mot de passe est sous enveloppe scellée.

## Protection des comptes Tier 0
- Membres du groupe Protected Users, sauf exception documentée.
- Option « Le compte est sensible et ne peut pas être délégué » cochée.
- Mots de passe d'au moins [16] caractères, changés au moins tous les [12] mois.
- Aucun SPN, aucune délégation, pré-authentification Kerberos toujours exigée.

## Responsables
- Responsable du Tier 0 : [équipe ou personne]
- Validation des ajouts aux groupes d'administration : [processus, ex. ticket validé par le RSSI]
- Revue des membres des groupes Tier 0 : [fréquence, ex. trimestrielle]
