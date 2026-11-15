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
sudo adsentry-setup        # réseau, DNS = DC, NTP, compte web, TLS, première cible, modèles IA
```

## Exploitation

```bash
cd /opt/adsentry/appliance
sudo docker compose ps
sudo docker compose exec worker adsentry run corp        # scan immédiat
sudo docker compose exec worker adsentry secret set corp-ad
sudo journalctl -t adsentry-worker -f                    # journaux du planificateur
```

Les cibles et leur planification sont dans `/etc/adsentry/targets.yaml` (format documenté dans
`src/adsentry/appliance/config.py`). Les secrets sont chiffrés (Fernet) avec `/etc/adsentry/master.key`.

## Durcissement appliqué

- nftables : entrée limitée à 22/80/443 ; SSH par clé uniquement, root interdit
- mises à jour de sécurité automatiques (unattended-upgrades), auditd sur la configuration et les secrets
- conteneurs non root, système de fichiers en lecture seule, `no-new-privileges`, capacités retirées
- clés d'hôte SSH et machine-id régénérés au premier démarrage

## Limites connues (à traiter dans la roadmap)

- Authentification web basique : remplacer par OIDC Entra ID + rôles (phase 4)
- Le chiffrement du disque n'est pas activé (dépend de l'hyperviseur / TPM virtuel)
- Image Docker non signée ; pas encore de mise à jour en un clic de l'appliance
