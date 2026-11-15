# Image de l'appliance ADSentry : Debian 13 (trixie) + Docker + pile ADSentry.
#
#   cd appliance/packer
#   tar -czf adsentry.tar.gz -C ../.. --exclude=.git --exclude=appliance/packer/output .
#   packer init . && packer build -var "ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)" .
#
# Sorties : output/adsentry.qcow2 (Proxmox/KVM) puis conversions :
#   qemu-img convert -O vmdk  output/adsentry.qcow2 adsentry.vmdk    # VMware
#   qemu-img convert -O vhdx  output/adsentry.qcow2 adsentry.vhdx    # Hyper-V

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "debian_version" {
  type        = string
  default     = "13.7.0" # point release courante au 2026-11 ; mettre à jour à chaque version
  description = "Version de l'ISO netinst Debian"
}

variable "ssh_public_key" {
  type        = string
  description = "Clé publique SSH de l'administrateur (aucun mot de passe SSH sur l'appliance)"
}

variable "build_password" {
  type      = string
  default   = "packer-build-only"
  sensitive = true
}

variable "disk_size" {
  type    = string
  default = "60G" # modèles IA (~6 Go) + historique des scans
}

source "qemu" "adsentry" {
  iso_url          = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-${var.debian_version}-amd64-netinst.iso"
  iso_checksum     = "file:https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS"
  output_directory = "output"
  vm_name          = "adsentry.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size
  disk_interface   = "virtio"
  net_device       = "virtio-net"
  accelerator      = "kvm"
  cpus             = 4
  memory           = 8192
  headless         = true
  http_directory   = "http"
  boot_wait        = "5s"
  boot_command = [
    "<esc><wait>",
    "auto preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "debian-installer=fr_FR.UTF-8 locale=fr_FR.UTF-8 keymap=fr hostname=adsentry domain=local ",
    "passwd/user-password=${var.build_password} passwd/user-password-again=${var.build_password} ",
    "<enter>"
  ]
  ssh_username     = "adsentry"
  ssh_password     = var.build_password
  ssh_timeout      = "60m"
  shutdown_command = "echo '${var.build_password}' | sudo -S systemctl poweroff"
}

build {
  sources = ["source.qemu.adsentry"]

  provisioner "file" {
    source      = "adsentry.tar.gz"
    destination = "/tmp/adsentry.tar.gz"
  }

  provisioner "shell" {
    execute_command = "echo '${var.build_password}' | sudo -S -E bash '{{ .Path }}'"
    script          = "provision.sh"
  }

  # Accès administrateur par clé uniquement ; le mot de passe de construction est verrouillé
  provisioner "shell" {
    execute_command = "echo '${var.build_password}' | sudo -S -E bash '{{ .Path }}'"
    inline = [
      "install -d -m 700 -o adsentry -g adsentry /home/adsentry/.ssh",
      "echo '${var.ssh_public_key}' > /home/adsentry/.ssh/authorized_keys",
      "chown adsentry:adsentry /home/adsentry/.ssh/authorized_keys && chmod 600 /home/adsentry/.ssh/authorized_keys",
      "echo 'adsentry ALL=(ALL) NOPASSWD: /usr/local/sbin/adsentry-setup, /usr/bin/docker' > /etc/sudoers.d/adsentry",
      "passwd -l adsentry"
    ]
  }
}
