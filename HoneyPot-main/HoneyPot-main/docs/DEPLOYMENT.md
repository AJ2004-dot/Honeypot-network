# Deployment Guide

This guide covers running the honeypot safely on a cloud VPS, exposing it
on the real SSH port without conflicting with your management SSH daemon,
firewalling it correctly, and running it under systemd or Docker.

## 1. Threat model / placement

Treat the honeypot host as **hostile territory** the moment it's exposed:

- Run it on a **dedicated VPS or VM**, not on a box with production data,
  credentials, or internal network access.
- Put it in its own network segment / VPC with **no route to internal
  services**. Outbound access isn't required by the honeypot itself (it
  never makes real outbound connections) — block it anyway at the
  firewall/security-group level as defense in depth.
- Keep your **real** administrative SSH access on a non-obvious port, or
  restrict it to a bastion/VPN, so the honeypot can safely squat on 22.

## 2. Ubuntu VPS install (systemd)

```bash
git clone <this-repo> ssh-honeypot && cd ssh-honeypot
sudo ./deploy/install_ubuntu.sh
```

This creates an unprivileged `honeypot` system user, a virtualenv under
`/opt/ssh-honeypot/venv`, generates a host key, and installs+enables two
systemd units: `ssh-honeypot.service` and `ssh-honeypot-dashboard.service`
(dashboard binds to `127.0.0.1` only — view it via an SSH tunnel:
`ssh -L 8501:127.0.0.1:8501 user@vps-ip`, then open http://localhost:8501).

### Exposing it as port 22

The honeypot listens on an unprivileged port (`2222` by default) so it
never needs root. To make it reachable on the real port 22:

**Option A — iptables port redirect (recommended):**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
# persist with iptables-persistent, or add to your cloud-init / netplan hooks
```
Put your **real** admin SSH daemon on a different port first (edit
`/etc/ssh/sshd_config`, `Port 2200`, `systemctl restart ssh`), then apply
the redirect above so port 22 goes to the honeypot instead.

**Option B — authbind / setcap:**
```bash
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f /opt/ssh-honeypot/venv/bin/python3)
# then change config/config.yaml ssh.port to 22 and restart the service
```
Less isolated than Option A since it grants the interpreter a real
capability; prefer the iptables redirect where possible.

## 3. Firewall rules

```bash
# Allow the honeypot's listening port in from anywhere
sudo ufw allow 2222/tcp

# Keep the dashboard OFF the public internet — access via SSH tunnel only
sudo ufw deny 8501/tcp

# If you exposed cosmetic fake-service ports (fake_services.expose_banner_ports: true)
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 3306/tcp
sudo ufw allow 6379/tcp
sudo ufw allow 2375/tcp

# Outbound: the honeypot makes zero real outbound connections, so you can
# safely default-deny outbound at the security-group / iptables OUTPUT
# level for extra assurance.
```

## 4. Docker / Docker Compose

```bash
docker compose build
docker compose up -d
```

This starts two containers on an isolated bridge network:
- `ssh-honeypot` — the fake SSH server, port `2222` published to the host
  (map to `22` in `docker-compose.yml` if you want it on the real port,
  after moving your real sshd off 22 as above).
- `ssh-honeypot-dashboard` — Streamlit, published on `8501`; put this
  behind a reverse proxy with auth, or don't publish it publicly at all
  and use `docker compose exec`/port-forwarding instead.

Logs land in `./logs` on the host (bind-mounted), so `analyze_logs.py`
and the dashboard both work whether they run in-container or on the host.

## 5. Cloud VPS specifics

- **DigitalOcean / Linode / Vultr / EC2**: use the provider's
  security-group firewall to allow inbound 2222 (or 22 after the redirect)
  and deny all outbound except what you need for OS updates.
- Disable any cloud-provider "helpful" auto-SSH-hardening or fail2ban on
  the honeypot's port — you *want* every attempt logged, not blocked.
- Take periodic snapshots/backups of `logs/` off-host (e.g. rsync to a
  separate log-collection host) — a sufficiently determined attacker who
  somehow escapes the simulated shell (they can't, but defense in depth)
  should not be able to destroy your evidence.

## 6. Log rotation & retention

`logs/honeypot.log` rotates automatically (10 MB × 5 backups, see
`src/utils/logging_setup.py`). Session JSON files
(`logs/session_*.json`) and `logs/malware_capture.jsonl` are **not**
auto-rotated — set up a cron job or logrotate config to archive/ship them
off-host periodically, e.g.:

```
# /etc/logrotate.d/ssh-honeypot
/opt/ssh-honeypot/logs/malware_capture.jsonl {
  weekly
  rotate 8
  compress
  missingok
  notifempty
}
```
