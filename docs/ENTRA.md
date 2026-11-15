# Audit Entra ID : préparation du tenant

ADSentry lit le tenant via Microsoft Graph avec une **application dédiée en lecture seule**,
authentifiée par **certificat** (pas de secret client sur l'appliance).

## 1. Créer l'application

1. Centre d'administration Entra → Applications → Inscriptions d'applications → Nouvelle inscription
   (nom : `ADSentry Audit`, comptes de ce répertoire uniquement, sans URI de redirection).
2. Certificats et secrets → Certificats → importer la partie publique du certificat généré sur l'appliance :

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -subj "/CN=ADSentry Audit" -keyout key.pem -out cert.pem
cat key.pem cert.pem > /etc/adsentry/certs/entra.pem && chmod 440 /etc/adsentry/certs/entra.pem
openssl x509 -in cert.pem -noout -fingerprint -sha1 | tr -d ':' | cut -d= -f2   # empreinte (thumbprint)
```

3. Autorisations d'API → Microsoft Graph → **Autorisations d'application** (toutes en lecture) puis
   « Accorder le consentement administrateur » :

| Permission | Utilisée pour |
|---|---|
| Directory.Read.All | utilisateurs, groupes, domaines, organisation |
| Policy.Read.All | valeurs de sécurité par défaut, autorisations, accès conditionnel |
| RoleManagement.Read.Directory | attributions de rôles |
| RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory | PIM (P2) |
| Application.Read.All | applications, principaux de service, propriétaires, identifiants |
| AuditLog.Read.All | dernière connexion (signInActivity, P1) |
| Reports.Read.All | enregistrement MFA (P1) |
| IdentityRiskyUser.Read.All | utilisateurs à risque (P2) |

## 2. Déclarer la cible

```yaml
targets:
  - name: contoso
    schedule: "47 3 * * *"
    entra:
      tenant_id: <ID du tenant>
      client_id: <ID d'application>
      certificate: /etc/adsentry/certs/entra.pem
      thumbprint: <empreinte SHA-1>
      connect_version: 2.4.27.0   # facultatif : version d'Entra Connect (non exposée par Graph)
```

Une même cible peut contenir `ad:` et `entra:` : les règles hybrides (comptes synchronisés
privilégiés, clé du SSO transparent AZUREADSSOACC) exploitent alors les deux sources.

## Licences et données manquantes

Sans P1/P2, certaines données ne sont pas accessibles : les règles correspondantes ne se
déclenchent pas (inconnu ≠ vulnérable) et le journal du worker indique ce qui n'a pas été collecté.

## Sécurité de l'application d'audit

- L'application ne possède **aucune** permission d'écriture ; protégez néanmoins sa clé privée
  (elle permet de lire tout l'annuaire).
- Restreignez sa connexion à l'IP publique de l'appliance (accès conditionnel pour identités de
  charge de travail, licence Workload ID) et renouvelez le certificat chaque année.
