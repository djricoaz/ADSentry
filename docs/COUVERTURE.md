# Couverture des contrôles — Active Directory et Entra ID

Revue de la couverture du catalogue (230 règles) par rapport aux recommandations publiques : guides de
l'ANSSI sur Active Directory, documentation de sécurité Microsoft (AD DS, ADCS, Entra ID), référentiels CIS
et techniques MITRE ATT&CK. Le détail de chaque règle (risque, correction, détection, références) est dans
`src/adsentry/rules/catalog/*.yaml` et dans la console (Catalogue de règles).

Rappel de principe : une donnée non collectée n'est jamais considérée comme vulnérable. Une famille marquée
« couverte » ne produit donc des constats que si la source correspondante a été lue (LDAP, SYSVOL, sondes,
Microsoft Graph). La vue d'ensemble de chaque rapport liste les règles non évaluées.

## Active Directory

| Famille de contrôles | Règles | Source |
|---|---|---|
| Groupes et comptes d'administration (taille, inactivité, mots de passe, Protected Users, délégation, messagerie, comptes désactivés, comptes d'un autre domaine) | P-ADMIN-*, P-TOO-MANY-ADMINS, P-OPERATORS-NOT-EMPTY, P-SCHEMA-ADMINS, P-DNSADMINS-NOT-EMPTY, **P-DISABLED-ADMINS**, **P-FOREIGN-ADMINS** | LDAP |
| Chemins de contrôle vers le Tier 0 (ACL, propriétaires, AdminSDHolder, DCSync, Exchange, Key Admins) | P-CONTROL-PATH-*, P-ADMINSDHOLDER-BACKDOOR, P-DCSYNC-NON-DC, P-EXCHANGE-*, P-KEY-ADMINS-DELEGATION, P-DC-OWNER, P-DANGEROUS-EXTENDED-RIGHT, P-DELEGATION-EVERYONE | LDAP |
| Délégations Kerberos (non contrainte, contrainte, transition de protocole, RBCD, vers krbtgt, vers les DC, services inexistants) | P-UNCONSTRAINED-DELEGATION, P-DC-*, P-RBCD-ON-DC, P-DELEGATION-KRBTGT, P-UNKNOWN-DELEGATION, **P-DELEGATION-TO-DC** | LDAP |
| Kerberos (SPN, pré-authentification, DES, AES, krbtgt, FAST, SPN invisibles) | A-KERBEROASTABLE, A-ASREP-ROASTABLE, A-DES-ENABLED, S-AES-NOT-ENABLED, P-KRBTGT-OLD, S-KERBEROS-ARMORING*, A-SPN-UNICODE | LDAP, GPO |
| Mots de passe (longueur, verrouillage, réversible, sans mot de passe, n'expire jamais, LM, GPP, ouverture automatique) | A-MIN-PWD-LEN, **A-LOCKOUT-DISABLED**, A-REVERSIBLE-*, S-PWD-*, A-LM-HASH, A-GPP-PASSWORD, A-UNIX-PASSWORD, **A-GPO-AUTOLOGON-PASSWORD**, A-NO-SERVICE-POLICY | LDAP, GPO |
| Protection des identifiants (LSA, WDigest, Credential Manager, mode récupération) | **A-LSA-PROTECTION-DC**, **A-WDIGEST**, P-TRUSTED-CREDMAN, P-RECOVERY-MODE-UNPROTECTED | GPO |
| Élévation de privilèges locale par GPO (MSI, impression, groupes locaux, privilèges) | **A-ALWAYS-INSTALL-ELEVATED**, **A-POINT-AND-PRINT**, A-MEMBERSHIP-EVERYONE, P-PRIVILEGE-EVERYONE, P-LOGIN-DC-EVERYONE, P-LOGON-DENIED | GPO |
| Protocoles (signature LDAP/SMB, channel binding, TLS LDAPS, NTLMv1, SMBv1, LLMNR, sessions nulles, NetCease, coercition, spouleur, WebClient) | A-LDAP-*, A-LDAPS-*, A-SMB-SIGNING-*, A-NTLMV1, S-SMB1, A-NO-GPO-LLMNR, A-NULL-SESSION, A-NETCEASE, A-COERCE-DC, A-SPOOLER-DC, A-WEBCLIENT-DC | sondes, GPO |
| Accès anonymes (dSHeuristics, pré-Windows 2000, RootDSE, GPO) | A-DSHEURISTICS-*, A-PRE2K-*, A-ROOTDSE-ANON-BIND, A-ANONYMOUS-GPO | LDAP, sondes, GPO |
| DNS (ADIDNS, mises à jour non sécurisées, transferts de zone, délégations) | A-DNS-*, P-DNS-DELEGATION | LDAP, sondes |
| GPO et SYSVOL (droits d'écriture, scripts et fichiers déployés, chemins durcis) | P-DELEGATION-GPO-DATA, P-DELEGATION-LOGIN-SCRIPT, P-DELEGATION-FILE-DEPLOYED, A-HARDENED-PATHS, T-SCRIPT-OUT-OF-DOMAIN, T-FILE-DEPLOYED-OUT-OF-DOMAIN | LDAP, SYSVOL |
| Contrôleurs de domaine et RODC (OS, mises à jour, enregistrement, sous-réseaux, sauvegarde, réplication FRS, nombre de DC, RODC) | S-OBSOLETE-DC, S-DC-*, A-BACKUP, A-NTFRS-SYSVOL, A-NOT-ENOUGH-DC, P-RODC-* | LDAP, sondes |
| Hygiène des objets (inactifs, OS obsolètes, LAPS, doublons, SID History, groupe principal, quota de création, corbeille, niveaux fonctionnels, schéma) | S-* , A-MACHINE-ACCOUNT-QUOTA, A-LAPS-JOINED-COMPUTERS, A-ADMINSDHOLDER-ORPHANS | LDAP |
| Approbations (filtrage SID, délégation de TGT, NT4, AES, inactivité, SID History, SSO transparent Entra) | T-* | LDAP |
| Audit et durcissement des postes (stratégie d'audit des DC, PowerShell, ASR, WSUS, RDP, scripts) | A-AUDIT-*, S-DEFENDER-ASR, S-WSUS-*, S-TERMINAL-SERVICES-GPO, S-FOLDER-OPTIONS, S-FIREWALL-SCRIPT | GPO, sondes |
| Nouvelles attaques (BadSuccessor / dMSA, CVE-2021-42291) | P-BAD-SUCCESSOR, A-DSHEURISTICS-LDAP-SECURITY | LDAP |
| PKI / ADCS (ESC1 à ESC16, CA, modèles, cryptographie des certificats) | PKI-* | LDAP, sondes |

En gras : règles ajoutées lors de cette revue.

### Non couvert à ce jour (collecte supplémentaire nécessaire)

| Contrôle | Pourquoi ce n'est pas encore fait | Phase |
|---|---|---|
| Qui peut lire les mots de passe LAPS (droits sur `ms-Mcs-AdmPwd` / `msLAPS-Password`) | lecture des ACE par GUID d'attribut à ajouter au collecteur | 1 |
| Qui peut lire les mots de passe des gMSA (`msDS-GroupMSAMembership`) | attribut et descripteur à collecter | 1 |
| Identifiants « shadow » (`msDS-KeyCredentialLink`) sur les comptes privilégiés et droits d'écriture sur cet attribut | attribut et droits par GUID à collecter | 1 |
| Chiffrement des mots de passe Windows LAPS dans l'AD | paramètre de stratégie (GPO ou Intune) à interpréter | 1 |
| RC4 accepté par les DC (`DefaultDomainSupportedEncTypes`, types de chiffrement des comptes DC) | registre distant des DC | 2 |
| Restriction et audit de NTLM entrant sur les DC (`RestrictNTLM*`) | à ajouter aux règles GPO | 2 |
| Sessions des administrateurs sur des postes de moindre confiance (cloisonnement effectif) | demanderait une collecte sur les postes, hors du périmètre lecture seule des DC | — |
| Taille et transfert des journaux d'événements des DC | registre distant / SIEM | 2 |

## Entra ID

| Famille de contrôles | Règles | Source |
|---|---|---|
| Authentification forte (MFA des administrateurs et des utilisateurs, MFA résistante à l'hameçonnage, méthodes faibles) | E-ADMIN-NO-MFA, E-USERS-NO-MFA, E-CA-NO-MFA-*, **E-CA-ADMINS-NOT-PHISHING-RESISTANT**, **E-WEAK-AUTH-METHODS** | Graph |
| Accès conditionnel (absence, mode rapport, authentification héritée, code d'appareil, risque) | E-NO-CA-POLICIES, E-CA-REPORT-ONLY, E-LEGACY-AUTH, **E-CA-DEVICE-CODE**, **E-CA-NO-RISK-POLICIES** | Graph |
| Rôles privilégiés (nombre d'administrateurs généraux, attributions permanentes / PIM, invités, comptes synchronisés, principaux de service) | E-GLOBAL-ADMINS-COUNT, E-PERMANENT-PRIVILEGED, E-PRIVILEGED-GUESTS, E-SYNCED-PRIVILEGED, E-APP-PRIVILEGED-ROLE | Graph |
| Applications (permissions critiques et larges, secrets longs ou expirés, secrets sur les principaux de service, propriétaires) | E-APP-*, E-SP-PASSWORD-CREDENTIALS | Graph |
| Paramètres du tenant (consentement, inscription d'applications, création de tenants, invités, jonction d'appareils) | E-USER-CONSENT, E-USERS-REGISTER-APPS, E-USERS-CREATE-TENANTS, E-GUEST-*, **E-DEVICE-JOIN-NO-MFA** | Graph |
| Identités hybrides (version d'Entra Connect, domaines fédérés, clé du SSO transparent) | E-CONNECT-VERSION, E-FEDERATED-DOMAINS, T-AZUREAD-SSO | Graph, LDAP |
| Hygiène (comptes et invités inactifs, utilisateurs à risque non traités) | E-STALE-*, E-RISKY-USERS | Graph |

### Non couvert à ce jour

| Contrôle | Pourquoi ce n'est pas encore fait | Phase |
|---|---|---|
| Comptes d'urgence (« bris de glace ») présents et exclus des stratégies d'accès conditionnel | identification des comptes à faire par l'administrateur (réglage à prévoir dans la console) | 1 bis |
| Paramètres PIM : MFA, approbation et justification à l'activation des rôles | lecture des `roleManagementPolicies` à ajouter | 1 bis |
| Paramètres d'accès inter-tenants par défaut (B2B entrant et sortant) | lecture de `crossTenantAccessPolicy` à ajouter | 1 bis |
| Rôles privilégiés attribués à des groupes non protégés (non « role-assignable ») | lecture des groupes à ajouter | 1 bis |
| Comptes d'administration avec boîte aux lettres ou licences de productivité | lecture des licences à ajouter | 1 bis |
| Workflow de demande de consentement administrateur | lecture de `adminConsentRequestPolicy` à ajouter | 1 bis |
| Conservation et export des journaux de connexion et d'audit | paramètres de diagnostic hors Graph (Azure Monitor) | — |

Toutes les lectures Graph restent en lecture seule (règle d'or 9) ; les permissions nécessaires sont dans
[ENTRA.md](ENTRA.md).
