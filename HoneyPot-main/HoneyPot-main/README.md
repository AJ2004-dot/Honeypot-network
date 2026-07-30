# SSH Honeypot (Original Implementation)

An educational, production-quality SSH honeypot written from scratch in
Python + Paramiko. It is **inspired by the general concept popularized by
Cowrie** (a fake, interactive SSH server that records attacker behavior)
but shares **no code, no architecture, and no configuration format** with
Cowrie. Everything here — the fake filesystem, the shell interpreter, the
session recorder, the fingerprinting engine, and the dashboard — is an
original design built for this project.

> ⚠️ **This tool never executes attacker input, never downloads files, and
> never makes outbound network connections.** All command output is
> simulated against an in-memory fake filesystem. See [Security](#security).

## Why

Honeypots let defenders observe real-world attacker behavior (credential
stuffing, scanner fingerprints, malware-staging URLs, post-auth command
sequences) without exposing a real system. This project packages that
capability with a live analytics dashboard for research, blue-team
training, and threat-intel collection.

## Features

- **Fake SSH server** (Paramiko) that accepts *any* username/password and
  drops the attacker into a believable Ubuntu shell.
- **Fake filesystem** — an in-memory tree seeded to look like a real
  Ubuntu 22.04 box (`/home`, `/etc`, `/var`, `/root`, `/opt`, `/tmp`,
  `/usr`, `/bin`, plus realistic file contents for `/etc/passwd`,
  `/etc/hostname`, `/etc/os-release`, etc). Changes persist for the
  session but are thrown away on disconnect.
- **Interactive fake shell** supporting 30+ real Linux commands (`ls`,
  `cd`, `cat`, `ps`, `netstat`, `ifconfig`, `ip`, `systemctl`,
  `journalctl`, `vim`, `nano`, `python3`, `sudo`, ...), with realistic
  errors for unknown commands.
- **Malware-staging capture** — `wget`/`curl` are parsed for URL +
  destination filename and logged, but **nothing is ever downloaded**.
- **Session recorder** — structured JSON session logs (IP, timestamps,
  credentials tried, every command, terminal size, failed commands,
  disconnect reason, duration).
- **Client fingerprinting** — identifies Hydra, Medusa, Nmap NSE,
  Masscan, libssh, OpenSSH, PuTTY, Paramiko-based, and Go `golang.org/x/crypto/ssh`
  clients from the SSH banner/kex behavior.
- **Fake auxiliary services** — banner-only stand-ins for Apache, Nginx,
  Docker (API), MySQL, and Redis, so port scans see a "real" multi-service
  host.
- **GeoIP enrichment** using MaxMind GeoLite2 (country, city, ASN, ISP).
- **Streamlit live dashboard** — sessions, top IPs/usernames/passwords/
  commands, world map, heatmap, timeline, and a session→command attack
  graph. Auto-refreshes every 5 seconds.
- **`analyze_logs.py`** — offline analytics/reporting CLI with CSV export.

## Repository layout

```
ssh-honeypot/
├── src/                    # Honeypot core (server, shell, fs, recorder, geoip, fingerprint...)
│   └── utils/              # Logging helper
├── dashboard/               # Streamlit dashboard app
├── config/                  # config.yaml + GeoLite2 DB location
├── logs/                    # JSON session logs (gitkept, runtime-populated)
├── docs/                    # Architecture + deployment docs
├── deploy/                  # systemd unit + Ubuntu install script
├── tests/                   # unit tests (pytest)
├── analyze_logs.py          # offline analytics CLI
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── LICENSE
```

## Quick start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# generate a host key (first run only)
python3 -c "import paramiko; k=paramiko.RSAKey.generate(2048); k.write_private_key_file('config/host_key')"

# start the honeypot (listens on config.yaml's ssh.port, default 2222)
python3 -m src.server

# in another terminal, start the dashboard
streamlit run dashboard/app.py
```

Then, from another machine or `localhost`:

```bash
ssh -p 2222 root@localhost
# any password is accepted
```

## Configuration

All runtime behavior is controlled by `config/config.yaml` — bind
address/port, fake hostname, fake users, banner string, log directory,
GeoLite2 DB path, and which fake auxiliary services to expose. See the
file for inline documentation.

## GeoIP

Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from MaxMind
(free account required) and point `config.yaml`'s `geoip.city_db` /
`geoip.asn_db` at them. If the files are missing, GeoIP fields are
simply reported as `"unknown"` — the honeypot still runs fine without them.

## Security

This project is defensive tooling for research/education. By design:

- Attacker input is **never** passed to a shell, `eval`, `exec`, or any
  interpreter — it's parsed and matched against a fake command table only.
- `wget`/`curl` **never** perform real HTTP requests — URLs are only
  logged.      
- The honeypot **never** initiates outbound connections of any kind.
- Run it as an unprivileged user, in a container, or in a VM/network
  segment with no access to anything sensitive. See `docs/DEPLOYMENT.md`.

## License
