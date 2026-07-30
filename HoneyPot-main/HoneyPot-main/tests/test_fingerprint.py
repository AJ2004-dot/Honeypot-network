import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.fingerprint import fingerprint_client


def test_detects_libssh_as_hydra_like():
    fp = fingerprint_client("SSH-2.0-libssh-0.9.6")
    assert fp.likely_scanner


def test_detects_paramiko():
    fp = fingerprint_client("SSH-2.0-paramiko_3.4.0")
    assert "Paramiko" in fp.label
    assert fp.likely_scanner


def test_detects_putty():
    fp = fingerprint_client("SSH-2.0-PuTTY_Release_0.78")
    assert "PuTTY" in fp.label


def test_plain_openssh_is_not_scanner_at_low_rate():
    fp = fingerprint_client("SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1", auth_attempts_per_second=0.1)
    assert not fp.likely_scanner


def test_openssh_high_rate_flagged_as_scripted():
    fp = fingerprint_client("SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1", auth_attempts_per_second=5.0)
    assert fp.likely_scanner


def test_empty_banner_flagged_low_confidence():
    fp = fingerprint_client("")
    assert fp.likely_scanner
    assert fp.confidence == "low"
