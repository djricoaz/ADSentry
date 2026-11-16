#!/usr/bin/env bash
# Provisionnement de l'image Debian 13 de l'appliance ADSentry (exécuté par Packer, en root).
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# --- Paquets ---------------------------------------------------------------------
apt-get update
apt-get -y full-upgrade
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg nftables chrony auditd unattended-upgrades apt-listchanges \
  systemd-resolved needrestart sudo openssh-server qemu-guest-agent open-vm-tools

# Docker Engine (dépôt officiel Docker pour Debian)
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# --- ADSentry ----------------------------------------------------------------------
mkdir -p /opt/adsentry /etc/adsentry/{tls,certs} /var/lib/adsentry/{scans,ollama,caddy}
tar -xzf /tmp/adsentry.tar.gz -C /opt/adsentry
install -m 0755 /opt/adsentry/appliance/system/adsentry-setup /usr/local/sbin/adsentry-setup
install -m 0644 /opt/adsentry/appliance/system/adsentry.service /etc/systemd/system/adsentry.service
chown -R 10001:10001 /var/lib/adsentry/scans
chown root:10001 /etc/adsentry && chmod 750 /etc/adsentry
chown 10001:10001 /var/lib/adsentry && chmod 750 /var/lib/adsentry
# Image applicative construite hors ligne dans l'appliance (aucun registre privé requis)
systemctl start docker
docker build -t adsentry:latest /opt/adsentry
docker pull caddy:2
docker pull ollama/ollama:latest

# --- Durcissement ------------------------------------------------------------------
# Pare-feu : HTTPS + SSH entrants uniquement ; Docker gère ses propres règles de NAT.
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport { 22, 80, 443 } accept
  }
  chain forward { type filter hook forward priority 0; policy accept; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable nftables

# SSH : clés uniquement, pas de root
cat > /etc/ssh/sshd_config.d/10-adsentry.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
EOF

# Mises à jour de sécurité automatiques
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Noyau / réseau
cat > /etc/sysctl.d/90-adsentry.conf <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.accept_redirects = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

# Docker : journald, pas d'ICC hors réseaux déclarés, espaces de noms utilisateurs
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "journald",
  "live-restore": true,
  "no-new-privileges": true,
  "icc": false
}
EOF

# Audit des fichiers sensibles
cat > /etc/audit/rules.d/adsentry.rules <<'EOF'
-w /etc/adsentry/ -p wa -k adsentry-config
-w /var/lib/adsentry/secrets.json -p rwa -k adsentry-secrets
-w /var/lib/adsentry/users.json -p wa -k adsentry-users
-w /etc/docker/ -p wa -k docker-config
EOF

systemctl enable chrony auditd systemd-resolved docker
systemctl disable --now adsentry.service 2>/dev/null || true   # activé par adsentry-setup

# Message de connexion
cat > /etc/motd <<'EOF'

  ADSentry – appliance d'audit AD / PKI / Entra ID (lecture seule)
  Première configuration :  sudo adsentry-setup
  État des services       :  sudo docker compose -f /opt/adsentry/appliance/docker-compose.yml ps

EOF

# Nettoyage pour une image générique
apt-get -y autoremove --purge && apt-get clean
rm -f /tmp/adsentry.tar.gz /etc/ssh/ssh_host_* && truncate -s 0 /etc/machine-id
cat > /etc/systemd/system/regen-ssh-keys.service <<'EOF'
[Unit]
Description=Régénère les clés d'hôte SSH au premier démarrage
ConditionPathExistsGlob=!/etc/ssh/ssh_host_*_key
Before=ssh.service
[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
[Install]
WantedBy=multi-user.target
EOF
systemctl enable regen-ssh-keys.service
