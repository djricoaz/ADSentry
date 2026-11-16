# Notifications, SIEM, ITSM et API

Tout se règle dans **Administration > Intégrations et API**. Chaque intégration a un interrupteur, ses
réglages, un bouton **Tester** et l'état du dernier envoi.

Les envois partent du **worker**, seul conteneur de l'appliance autorisé à sortir du réseau interne ; l'API
n'émet jamais vers l'extérieur. Mots de passe et jetons sont chiffrés (SecretStore) et jamais réaffichés.
**Une intégration en erreur n'interrompt jamais un scan** : l'erreur est signalée dans la cloche des
administrateurs et dans l'état de l'intégration.

Pensez à ouvrir les flux sortants de l'appliance vers les systèmes visés (pare-feu).

## Notifications

| Canal | Contenu |
|---|---|
| **Cloche** (tous les utilisateurs) | fin de scan (score, nouveaux et corrigés), nouveaux constats graves ; pour les administrateurs : scans en échec, tickets créés, intégrations en erreur |
| **Notifications du bureau** | les nouveautés de la cloche quand l'onglet est en arrière-plan (bouton dans la cloche ; console en HTTPS) |
| **E-mail** (SMTP, STARTTLS ou SSL) | résumé de fin de scan, nouveaux constats à partir de la sévérité choisie, scans en échec |
| **Webhook** | même contenu vers Microsoft Teams, Slack ou tout outil acceptant du JSON (n8n, Power Automate…) |

Renseignez **l'adresse de la console** (réglages communs) pour que les messages contiennent des liens.

## SIEM

| Sortie | Format |
|---|---|
| **Syslog** (UDP, TCP, TCP + TLS) | RFC 5424, message CEF (`CEF:0|ADSentry|ADSentry|…`) ou JSON ; facilité local4, gravité selon la sévérité |
| **Splunk HEC** | événements JSON, `sourcetype` `adsentry:scan`, `adsentry:finding`, `adsentry:audit` |

Événements envoyés : résumé de chaque scan, constats **nouveaux** et **corrigés** (ou **tous** les constats à
chaque scan), et le **journal d'audit** de la console (connexions, échecs, verrouillages, modifications de
cibles, scans…). Champs CEF utilisés : `rt`, `dvchost` (domaine), `cat`, `act` (new / resolved / present),
`msg`, `cs1` (objets), `cn1` (nombre d'objets), `cs2` (techniques MITRE), `cs3` (scan).

## ITSM : Jira et ServiceNow

- **Jira Cloud** : e-mail du compte + jeton d'API Atlassian. **Jira Data Center** : jeton d'accès personnel.
  Le ticket est créé dans le projet et le type indiqués, avec les étiquettes `adsentry` et l'identifiant de la règle.
- **ServiceNow** : compte d'intégration (rôle permettant de créer des incidents) ; urgence et impact déduits de
  la sévérité, groupe d'affectation facultatif.
- Le ticket décrit le domaine, le risque, la correction, la détection, les objets concernés et les techniques
  MITRE, et rappelle que le script PowerShell de correction est disponible dans la fiche du constat.
- **À la demande** : bouton « Créer un ticket » dans la fiche d'un constat (administrateurs).
- **Automatiquement** : pour les nouveaux constats à partir de la sévérité choisie.
- **Sans doublon** : un seul ticket par domaine et par règle ; le lien apparaît dans la fiche du constat.
- **Tester** vérifie l'authentification sans créer de ticket.

## API et jetons d'accès

- **Documentation interactive (Swagger)** : bouton « Documentation de l'API » ou `https://<console>/api/docs`
  (connexion à la console requise). Servie localement, sans dépendance Internet.
- Schéma OpenAPI : `/api/openapi.json` (3.1) — `?compat=1` pour une version 3.0.
- **Jetons d'API** : créés par un administrateur, rôle Lecteur ou Administrateur, expiration au choix, affichés
  une seule fois, conservés sous forme d'empreinte. Utilisation :

```bash
curl -H "Authorization: Bearer ads_…" https://adsentry.entreprise.fr/api/scans
```

Un jeton ne peut pas créer d'autres jetons ; sa révocation est immédiate. Son usage est journalisé sous le nom
« jeton:<nom> ».
