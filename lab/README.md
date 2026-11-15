# Lab de test

Ne JAMAIS développer ou tester les règles sur la production. Toutes les mauvaises configurations
ci-dessous sont à créer volontairement dans un environnement isolé.

## Option A — GOAD (Game Of Active Directory, Orange Cyberdefense)

Lab open source prêt à l'emploi, avec ADCS vulnérable. Demande beaucoup de RAM : utiliser la
variante la plus légère compatible avec ta machine, ou un hôte de virtualisation dédié.
https://github.com/Orange-Cyberdefense/GOAD

## Option B — Lab minimal fait main (recommandé avec peu de RAM)

2 VM Windows Server d'évaluation (180 jours) sur Hyper-V / VirtualBox / Proxmox :

| VM | Rôle | RAM |
|----|------|-----|
| DC01 | AD DS + DNS (`lab.local`) | 2-4 Go |
| CA01 | AD CS Enterprise Root CA + inscription web | 2-4 Go |

Configurations à créer (une par modèle dupliqué, pour pouvoir activer/désactiver) :

- **ESC1** : dupliquer « User », cocher *Fournir dans la demande*, inscription *Domain Users*
- **ESC2** : modèle avec EKU *Tous les objectifs*, inscription *Authenticated Users*
- **ESC3** : modèle *Enrollment Agent* ouvert à *Domain Users*
- **ESC4** : donner *Écrire* sur un modèle à *Authenticated Users*
- **ESC6** : `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2`
- **ESC8** : installer *Inscription web* en HTTP
- **ESC13** : politique d'émission liée à un groupe (`msDS-OIDToGroupLink`)
- **ESC15** : publier « WebServer » (schéma v1) ouvert à *Domain Users*, CA sans le correctif de novembre 2024
- AD : un compte admin avec SPN, un compte sans pré-auth Kerberos, `ms-DS-MachineAccountQuota` = 10,
  une machine en délégation non contrainte, un utilisateur avec droits DCSync

## Vérité terrain

La référence est la liste des failles créées volontairement ci-dessus : chacune doit être trouvée par
ADSentry, et une fois corrigée elle doit disparaître au scan suivant. Pour la PKI, un contrôle croisé
est fait avec un outil open source d'énumération ADCS :

- `certipy find -u user@lab.local -p '...' -dc-ip <ip> -vulnerable -json` → constats PKI

Les écarts sont soit des bugs de notre collecteur/règles, soit des différences de périmètre à documenter.
