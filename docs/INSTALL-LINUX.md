# Installation sur un serveur Linux (sans Docker)

Pour un serveur Linux existant (Debian 12/13, Ubuntu 24.04, RHEL 9…). Un seul service systemd exécute la console
web en HTTPS et les scans. Pour la production, l'appliance ([APPLIANCE.md](APPLIANCE.md)) reste recommandée :
elle isole l'API (sans accès réseau) du worker (seul à contacter l'AD).

Prérequis : Python ≥ 3.11, accès réseau vers les DC (53, 88, 389/636, 445, 135 + RPC dynamiques) et, pour Entra ID,
vers `login.microsoftonline.com` et `graph.microsoft.com` ; horloge synchronisée avec les DC (NTP).

## 1. Installation

```bash
sudo useradd --system --home-dir /var/lib/adsentry --shell /usr/sbin/nologin adsentry
sudo mkdir -p /opt/adsentry /etc/adsentry/tls /var/lib/adsentry
sudo git clone https://github.com/<organisation>/adsentry.git /opt/adsentry/src
sudo python3 -m venv /opt/adsentry/venv
sudo /opt/adsentry/venv/bin/pip install "/opt/adsentry/src[appliance]"
sudo chown adsentry:adsentry /var/lib/adsentry && sudo chmod 750 /var/lib/adsentry
```

## 2. Clé des secrets et certificat HTTPS

```bash
# Clé maître (chiffre mots de passe, secrets et certificats des cibles)
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | sudo tee /etc/adsentry/master.key >/dev/null
sudo chown root:adsentry /etc/adsentry/master.key && sudo chmod 440 /etc/adsentry/master.key

# Certificat émis par votre PKI (recommandé), ou à défaut auto-signé :
sudo openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=$(hostname -f)" \
  -keyout /etc/adsentry/tls/key.pem -out /etc/adsentry/tls/cert.pem
sudo chown -R root:adsentry /etc/adsentry/tls && sudo chmod 640 /etc/adsentry/tls/*.pem
```

## 3. Administrateur et service

```bash
sudo -u adsentry ADSENTRY_STATE=/var/lib/adsentry /opt/adsentry/venv/bin/adsentry user add admin --role admin
sudo install -m 0644 /opt/adsentry/src/appliance/system/adsentry-native.service /etc/systemd/system/adsentry.service
sudo systemctl daemon-reload && sudo systemctl enable --now adsentry
sudo journalctl -u adsentry -f
```

La console est sur `https://<serveur>:8443` (ouvrir ce port dans le pare-feu pour les postes d'administration).
Sans compte créé à l'étape 3, la console demande le jeton d'installation : `sudo cat /var/lib/adsentry/setup-token`.

## 4. Utilisation

1. **Administration > Cibles d'audit > Ajouter une cible**, puis **Tester la connexion** et **Lancer le scan**.
2. **Administration > Comptes et rôles** : comptes « Lecteur » pour consulter les évaluations.

## IA locale (optionnel)

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Puis dans la console : **Administration > IA locale > Installer le modèle**. Ollama doit écouter sur
`http://localhost:11434` (valeur par défaut) ; sinon, ajoutez `Environment=OLLAMA_HOST=http://hôte:11434` au service.
Prévoir 8 Go de RAM pour le modèle 4B sur CPU.

## Mise à jour

```bash
cd /opt/adsentry/src && sudo git pull
sudo /opt/adsentry/venv/bin/pip install --upgrade "/opt/adsentry/src[appliance]"
sudo systemctl restart adsentry
```

Les données (comptes, cibles, secrets chiffrés, rapports, journal d'audit) sont dans `/var/lib/adsentry` :
à sauvegarder avec `/etc/adsentry/master.key`, sans laquelle les secrets ne sont pas déchiffrables.
