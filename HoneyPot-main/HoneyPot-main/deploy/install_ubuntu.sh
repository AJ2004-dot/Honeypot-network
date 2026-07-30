#!/usr/bin/env bash
# Installs the SSH honeypot as a systemd service on Ubuntu 22.04/24.04.
# Run as root: sudo ./deploy/install_ubuntu.sh
set -euo pipefail

INSTALL_DIR="/opt/ssh-honeypot"
SERVICE_USER="honeypot"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

echo "==> Installing OS packages"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git ufw

echo "==> Creating unprivileged service user"
id -u "$SERVICE_USER" &>/dev/null || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

echo "==> Copying project files to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
rsync -a --exclude 'venv' --exclude 'logs/*.json' --exclude '.git' ./ "$INSTALL_DIR"/
mkdir -p "$INSTALL_DIR/logs"

echo "==> Creating virtualenv + installing Python dependencies"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "==> Generating SSH host key (if missing)"
if [[ ! -f "$INSTALL_DIR/config/host_key" ]]; then
  "$INSTALL_DIR/venv/bin/python3" -c "import paramiko; k = paramiko.RSAKey.generate(2048); k.write_private_key_file('$INSTALL_DIR/config/host_key')"
fi

echo "==> Fixing ownership/permissions"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/config/host_key"

echo "==> Installing systemd units"
cp "$INSTALL_DIR/deploy/honeypot.service" /etc/systemd/system/ssh-honeypot.service
cp "$INSTALL_DIR/deploy/honeypot-dashboard.service" /etc/systemd/system/ssh-honeypot-dashboard.service
sed -i "s#/opt/ssh-honeypot#$INSTALL_DIR#g" /etc/systemd/system/ssh-honeypot.service
sed -i "s#/opt/ssh-honeypot#$INSTALL_DIR#g" /etc/systemd/system/ssh-honeypot-dashboard.service
systemctl daemon-reload
systemctl enable --now ssh-honeypot.service
systemctl enable --now ssh-honeypot-dashboard.service

echo "==> Configuring firewall (allow honeypot port, keep dashboard local-only)"
ufw allow 2222/tcp || true
# The dashboard binds to 127.0.0.1 only; use an SSH tunnel to view it
# remotely, e.g.: ssh -L 8501:127.0.0.1:8501 user@this-host

echo "==> Done."
echo "    Honeypot:  systemctl status ssh-honeypot"
echo "    Dashboard: systemctl status ssh-honeypot-dashboard (tunnel port 8501 to view)"
echo "    See docs/DEPLOYMENT.md for exposing the honeypot on real port 22."
