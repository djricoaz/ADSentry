# Comptes de service

## Règles
- Préférer un compte de service géré de groupe (gMSA) : mot de passe long, changé automatiquement.
- À défaut, mot de passe aléatoire d'au moins [25] caractères, stocké dans [coffre-fort de mots de passe].
- Jamais membre d'un groupe d'administration du domaine ; droits limités au strict besoin du service.
- Chiffrement Kerberos AES uniquement ; pas de délégation non contrainte.
- Nommage : [préfixe, ex. svc-] suivi du nom de l'application ; description renseignée avec le responsable.

## Inventaire et responsables
Chaque compte de service a un responsable applicatif et une fiche dans [CMDB ou référentiel].
Un compte de service sans responsable identifié est signalé à [équipe] et désactivé après [30] jours.

## Kerberoasting
Un compte utilisateur avec SPN est exposé aux attaques hors ligne sur son mot de passe. Priorité : passer en
gMSA. Sinon : mot de passe de 25 caractères ou plus et AES uniquement. Surveiller les événements 4769 avec
chiffrement RC4 pour ces comptes.
