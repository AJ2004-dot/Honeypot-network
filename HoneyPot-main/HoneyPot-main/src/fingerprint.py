"""Fingerprints the connecting SSH client from its identification banner and
key-exchange behavior, to flag likely scanners/brute-forcers vs interactive
attackers.

This never affects how the honeypot responds (no behavioral branching that
would let a scanner detect it's being fingerprinted) — it purely informs
logging/analytics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# Ordered (more specific first) signature table. Each entry is
# (label, compiled regex matched against the raw client SSH banner string).
_SIGNATURES: List[tuple] = [
    ("Hydra", re.compile(r"libssh|hydra", re.I)),
    ("Nmap NSE (ssh script engine)", re.compile(r"nmap|ssh-2\.0-openssh_for_windows_7\.9", re.I)),
    ("Masscan", re.compile(r"masscan", re.I)),
    ("Medusa", re.compile(r"medusa", re.I)),
    ("PuTTY", re.compile(r"putty", re.I)),
    ("Paramiko (scripted client)", re.compile(r"paramiko", re.I)),
    ("Go SSH library (golang.org/x/crypto/ssh)", re.compile(r"golang|go-crypto|ssh2-go", re.I)),
    ("libssh-based tool", re.compile(r"libssh(?!.*openssh)", re.I)),
    ("OpenSSH (interactive/standard client)", re.compile(r"openssh", re.I)),
    ("Dropbear", re.compile(r"dropbear", re.I)),
]

# Nmap's ssh2-enum-algos / ssh-auth-methods NSE scripts frequently present
# an empty or minimal, out-of-order KEX algorithm list. We can't inspect raw
# KEXINIT packets easily via the paramiko Transport public API, so we key
# primarily off the banner string plus timing heuristics supplied by the caller.


@dataclass
class Fingerprint:
    client_banner: str
    label: str
    confidence: str  # "high" | "medium" | "low"
    likely_scanner: bool


def fingerprint_client(client_banner: Optional[str], auth_attempts_per_second: float = 0.0) -> Fingerprint:
    """Classify a client from its SSH-2.0 identification banner.

    Parameters
    ----------
    client_banner:
        The raw string the client sent, e.g. "SSH-2.0-libssh_0.9.6".
    auth_attempts_per_second:
        Optional rate hint (attempts/sec across the session) used to bump
        confidence that a "plain OpenSSH"-looking client is actually a
        scripted brute-forcer using an OpenSSH-compatible library.
    """
    banner = (client_banner or "").strip()

    for label, pattern in _SIGNATURES:
        if pattern.search(banner):
            confidence = "high"
            likely_scanner = label not in ("OpenSSH (interactive/standard client)",)
            if label == "OpenSSH (interactive/standard client)" and auth_attempts_per_second > 2:
                label = "OpenSSH-compatible brute-force script"
                likely_scanner = True
                confidence = "medium"
            return Fingerprint(banner, label, confidence, likely_scanner)

    if not banner:
        return Fingerprint(banner, "Unknown/no banner (possibly a raw scanner)", "low", True)

    if auth_attempts_per_second > 3:
        return Fingerprint(banner, "Unclassified client, high-rate auth (probable brute-forcer)", "medium", True)

    return Fingerprint(banner, "Unclassified client", "low", False)
