import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.filesystem import FakeFilesystem

FAKE_USERS = [{"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
              {"username": "ubuntu", "uid": 1000, "gid": 1000, "home": "/home/ubuntu", "shell": "/bin/bash"}]


def make_fs():
    return FakeFilesystem(hostname="test-host", distro="Ubuntu 22.04.4 LTS",
                           kernel="5.15.0-105-generic", fake_users=FAKE_USERS)


def test_root_dirs_exist():
    fs = make_fs()
    for d in ("home", "etc", "var", "root", "opt", "tmp", "usr", "bin"):
        assert fs.resolve(f"/{d}") is not None, d


def test_normalize_paths():
    fs = make_fs()
    assert fs.normalize("/home/ubuntu", "..") == "/home"
    assert fs.normalize("/home/ubuntu", "../../etc") == "/etc"
    assert fs.normalize("/root", "./x") == "/root/x"


def test_mkdir_touch_persist():
    fs = make_fs()
    assert fs.mkdir("/tmp/attacker") is None
    assert fs.touch("/tmp/attacker/payload.sh") is None
    node = fs.resolve("/tmp/attacker/payload.sh")
    assert node is not None
    assert not node.is_dir


def test_rm_requires_recursive_for_nonempty_dir():
    fs = make_fs()
    fs.mkdir("/tmp/x")
    fs.touch("/tmp/x/file")
    assert fs.remove("/tmp/x") is not None  # should fail without -r
    assert fs.remove("/tmp/x", recursive=True) is None


def test_write_file_and_cat_roundtrip():
    fs = make_fs()
    fs.write_file("/tmp/note.txt", "hello world")
    node = fs.resolve("/tmp/note.txt")
    assert node.content == "hello world"


def test_etc_passwd_contains_fake_users():
    fs = make_fs()
    passwd = fs.resolve("/etc/passwd").content
    assert "root:x:0:0" in passwd
    assert "ubuntu:x:1000:1000" in passwd


def test_clone_is_independent():
    fs = make_fs()
    clone = fs.clone()
    clone.mkdir("/tmp/only-in-clone")
    assert fs.resolve("/tmp/only-in-clone") is None
    assert clone.resolve("/tmp/only-in-clone") is not None
