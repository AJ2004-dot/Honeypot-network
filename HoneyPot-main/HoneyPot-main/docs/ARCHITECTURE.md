# Architecture

## Design goals

1. **Believable** — a curious attacker gets a real-feeling Ubuntu shell:
   consistent hostname, users, processes, filesystem, and command output.
2. **Safe by construction** — attacker input is data, never code. There is
   no `eval`, `exec`, `subprocess`, or `os.system` call anywhere in the
   command-handling path, and no networking code that could perform a real
   outbound request.
3. **Observable** — every attacker action (auth attempts, commands,
   fetch attempts, disconnects) is captured in structured logs suitable for
   both live dashboards and offline analytics.
4. **Original** — built from first principles on top of Paramiko's
   low-level `Transport`/`ServerInterface` primitives, not derived from or
   structurally similar to Cowrie (which uses Twisted and a very different
   internal design: a real (contained) shell/FS emulation layer called
   "TTY log" plus a plugin/output-module architecture). This project uses
   a much simpler, single-process, thread-per-connection model with a flat
   command dispatch table and a small in-memory FS tree.

## Component map

```
                     ┌─────────────────────────┐
attacker  ── TCP ──▶ │   HoneypotServer         │  src/server.py
 (ssh client)        │   (socket.accept loop)   │
                     └───────────┬─────────────┘
                                 │ spawns thread per connection
                                 ▼
                     ┌─────────────────────────┐
                     │  ClientSessionHandler    │  owns one paramiko.Transport
                     │  + HoneypotServerInterface│  (auth, pty, shell/exec reqs)
                     └───────────┬─────────────┘
                 ┌───────────────┼───────────────────┐
                 ▼               ▼                   ▼
        FakeFilesystem      FakeShell           SessionRecorder
        (src/filesystem.py) (src/shell.py)      (src/session_recorder.py)
                                 │
                                 ▼
                    MalwareCaptureLogger (src/malware_capture.py)
                                 │
                                 ▼
                       GeoIPResolver / fingerprint_client
                     (src/geoip_lookup.py, src/fingerprint.py)
```

- `src/server.py` — accepts raw TCP, wraps in `paramiko.Transport`, serves
  a fake OpenSSH banner, negotiates auth (always succeeds, after logging),
  handles PTY/shell/exec channel requests, and runs the byte-level
  interactive read loop (handles backspace, Ctrl-C, Ctrl-D, Enter).
- `src/filesystem.py` — an in-memory tree of `FSNode`s seeded to look like
  Ubuntu 22.04. Supports the handful of mutating ops the shell needs
  (`mkdir`, `touch`, `write_file`, `remove`) plus path resolution
  (`normalize`, `resolve`). Cloned per-session so sessions can't see each
  other's changes; discarded on disconnect.
- `src/shell.py` — a flat dispatch table (`Dict[str, Callable]`) mapping
  command names to handler methods that read/mutate the `FakeFilesystem`
  and return canned-but-parameterized output (e.g. `ps`, `netstat`,
  `ifconfig` return realistic, config-driven fake data; `ls`/`cat`/`cd`
  actually consult the fake FS). Unknown commands get a realistic
  `command not found` message. `wget`/`curl` are special-cased to *look*
  like they're trying to fetch a URL (and fail with a believable DNS
  error) while triggering the malware-capture hook.
- `src/malware_capture.py` — pure string parsing (`shlex` + regex) to pull
  a URL/filename out of a `wget`/`curl` invocation. No networking imports
  at all in this module, by design.
- `src/session_recorder.py` — accumulates a `SessionRecord` dataclass
  across the session's lifetime and serializes it to
  `logs/session_<id>.json` on disconnect.
- `src/fingerprint.py` — regex table matching the client's SSH banner
  string (plus an auth-rate heuristic) against known scanner/tool
  signatures (Hydra, Nmap NSE, Masscan, Medusa, libssh, PuTTY, Paramiko,
  Go's `x/crypto/ssh`, plain OpenSSH).
- `src/geoip_lookup.py` — thin, defensively-coded wrapper around
  `geoip2.database.Reader` for MaxMind GeoLite2 City + ASN databases;
  degrades to `"unknown"` fields if the `.mmdb` files aren't present.
- `src/fake_services.py` — optional, disabled-by-default banner-only TCP
  listeners for Apache/Nginx/Docker/MySQL/Redis so a port-scan of the host
  sees a believable multi-service box. Never parses attacker bytes beyond
  deciding whether to send the canned banner/response.
- `dashboard/app.py` — Streamlit app that globs `logs/session_*.json`,
  loads them with `pandas.json_normalize`, and renders tables/charts/maps.
  Fully decoupled from the live server process (reads only from disk), so
  it can safely run on a different, non-exposed host.
- `analyze_logs.py` — the same log corpus, offline, as a CLI report +
  optional CSV export — for scripting, cron jobs, or CI-based reporting.

## Why not just fork Cowrie?

Cowrie is a mature, Twisted-based honeypot with a different internal
architecture (deferred/reactor-driven I/O, a TTY-log/playback recording
format, a plugin "output module" system, and its own user/auth backend
abstractions). This project intentionally does not reuse any of that: it
uses Paramiko + native `threading` instead of Twisted, a flat Python
dataclass/dict-based fake FS instead of Cowrie's shadow-VFS classes, JSON
session dumps instead of the UML/TTY-log format, and a single dispatch
table in `shell.py` instead of Cowrie's per-command plugin classes. The
result is functionally comparable (interactive fake SSH shell + structured
attacker logging) but is a distinct, from-scratch implementation.
