# Appliance Linux ADSentry

Machine virtuelle Debian 13 durcie qui exécute toute la chaîne : collecte en lecture seule (AD, SYSVOL,
sondes, Microsoft Graph), moteur de règles, IA locale et tableau de bord HTTPS. **Aucune donnée
d'annuaire ne quitte l'appliance** (le modèle IA tourne sur place).

## Architecture

```
                 HTTPS 443 (basic auth → OIDC Entra en phase 4)
 Navigateur ───────────────▶ caddy ──/api──▶ api (FastAPI) ──▶ ollama (CPU, réseau interne)
                                 └──/────▶ tableau de bord (statique)
                                              ▲ fichiers de résultats (/var/lib/adsentry/scans)
 worker (planificateur cron) ─────────────────┘
   ├─ LDAP/LDAPS 389/636, SMB 445, RPC  ──▶ contrôleurs de domaine (compte standard, lecture seule)
   └─ HTTPS 443 ──▶ login.microsoftonline.com, graph.microsoft.com (app Entra, certificat)
```

| Conteneur | Réseaux | Particularités |
|---|---|---|
| caddy | edge, internal | seul port publié (80→443), en-têtes de sécurité, TLS interne ou certificat de votre PKI |
| api | internal | lecture seule, non root (uid 10001), aucune sortie réseau |
| worker | internal, egress | seul conteneur qui parle à l'AD et à Graph |
| ollama | internal, models | accès Internet uniquement pour télécharger les modèles (coupable ensuite) |

## Dimensionnement (CPU seul)

| Taille du domaine | vCPU | RAM | Disque |
|---|---|---|---|
| < 5 000 comptes | 4 | 12 Go | 60 Go |
| 5 000 – 50 000 | 8 | 16 Go | 100 Go |
| > 50 000 | 8+ | 24 Go | 150 Go |

Le modèle `qwen3.5:4b` quantifié occupe environ 3,5 Go de RAM ; une analyse prend de 1 à 5 minutes sur CPU.

## Flux réseau à ouvrir

| Source | Destination | Ports |
|---|---|---|
| Postes admin | appliance | 443/tcp (et 22/tcp pour l'administration) |
| appliance | DC | 53, 88, 389, 636, 445, 135 + RPC dynamiques (49152-65535)/tcp, 123/udp |
| appliance | CA ADCS | 80/443 (sonde d'inscription web) |
| appliance | Internet | 443 vers graph.microsoft.com, login.microsoftonline.com ; registre Ollama à l'installation |

## Construire l'image

```bash
cd appliance/packer
tar -czf adsentry.tar.gz -C ../.. --exclude=.git --exclude=appliance/packer/output .
packer init .
packer build -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)" .
qemu-img convert -O vmdk output/adsentry.qcow2 adsentry.vmdk   # VMware
qemu-img convert -O vhdx output/adsentry.qcow2 adsentry.vhdx   # Hyper-V
```

Prérequis : machine Linux avec KVM, Packer ≥ 1.10, accès Internet (miroirs Debian, Docker, PyPI).

## Premier démarrage

```bash
ssh adsentry@<ip>
sudo adsentry-setup        # réseau, DNS = DC, NTP, administrateur de la console, TLS, modèles IA
```

Tout le reste se fait dans la console web `https://<nom de l'appliance>` :

1. **Administration > Cibles d'audit > Ajouter une cible** : domaine AD (DC, compte d'audit standard, mot de passe)
   et/ou tenant Entra ID (application d'audit, certificat PEM ou secret client), planification, synthèse IA.
2. **Tester la connexion**, puis **Lancer le scan** : l'avancement s'affiche en direct (collecte LDAP, SYSVOL,
   sondes, Graph, analyse, IA) ; le rapport apparaît dans les vues dès la fin du scan.
3. **Administration > Comptes et rôles** : créer les comptes des équipes.

## Comptes et rôles de la console

| Rôle | Peut |
|---|---|
| **Administrateur** | tout ce que peut un lecteur ; gérer les cibles et leurs secrets ; lancer/annuler scans, tests et synthèses IA ; importer ou supprimer des rapports ; gérer les comptes ; consulter le journal d'audit |
| **Lecteur** | consulter les évaluations : tableau de bord, maturité, comparaisons, constats, ADCS, Entra ID, MITRE, synthèses, historique, catalogue |

- Mots de passe : 12 caractères minimum, 3 types de caractères ; hachés (scrypt) dans `/var/lib/adsentry/users.json`.
- Sessions : cookie `HttpOnly`, `Secure`, `SameSite=Strict`, expiration après 8 h d'inactivité ; toute requête
  modifiante exige l'en-tête `X-ADSentry` (protection CSRF). Changer le rôle ou le mot de passe d'un compte ferme ses sessions.
- 5 échecs de connexion bloquent l'identifiant et l'adresse 15 minutes.
- Journal d'audit (connexions, cibles, scans, comptes) : `/var/lib/adsentry/audit.log`, visible par les administrateurs.
- Mot de passe administrateur perdu :
  `sudo docker compose -f /opt/adsentry/appliance/docker-compose.yml run --rm api adsentry user passwd <compte>`.

## Exploitation

```bash
cd /opt/adsentry/appliance
sudo docker compose ps
sudo docker compose exec api adsentry user list          # comptes de la console
sudo docker compose exec worker adsentry run corp        # scan immédiat sans passer par la console
sudo journalctl -t adsentry-worker -f                    # journaux du planificateur
```

Les cibles et leur planification sont enregistrées par la console dans `/var/lib/adsentry/targets.yaml`
(un ancien `/etc/adsentry/targets.yaml` reste lu tant que la console n'a rien enregistré). Mots de passe, secrets
clients et certificats Entra sont chiffrés (Fernet) avec `/etc/adsentry/master.key` dans `/var/lib/adsentry/secrets.json`
et ne sont jamais renvoyés au navigateur. L'API dépose les scans dans une file (`/var/lib/adsentry/jobs/`) : seul
le conteneur `worker` contacte l'AD et Microsoft Graph.

## Durcissement appliqué

- nftables : entrée limitée à 22/80/443 ; SSH par clé uniquement, root interdit
- mises à jour de sécurité automatiques (unattended-upgrades), auditd sur la configuration et les secrets
- conteneurs non root, système de fichiers en lecture seule, `no-new-privileges`, capacités retirées
- clés d'hôte SSH et machine-id régénérés au premier démarrage

## Limites connues (à traiter dans la roadmap)

- Comptes locaux à la console : connexion OIDC Entra ID (SSO) et rôle intermédiaire « analyste » à venir (phase 4)
- Le chiffrement du disque n'est pas activé (dépend de l'hyperviseur / TPM virtuel)
- Image Docker non signée ; pas encore de mise à jour en un clic de l'appliance
