"""An in-memory fake Linux filesystem used to back the fake shell.

Design notes
------------
The tree is a nested dict of `FSNode` objects. Each node is either a
directory (has `children`) or a file (has `content` + metadata). The tree
is deep-copied per session so that one attacker's `rm -rf /` doesn't
affect anyone else, and is discarded when the session ends (nothing an
attacker does is ever persisted to real disk).
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FSNode:
    name: str
    is_dir: bool
    owner: str = "root"
    group: str = "root"
    mode: str = "755"
    content: str = ""
    mtime: float = field(default_factory=time.time)
    children: Dict[str, "FSNode"] = field(default_factory=dict)

    def size(self) -> int:
        if self.is_dir:
            return 4096
        return len(self.content.encode("utf-8", errors="ignore"))


def _dir(name: str, owner: str = "root", group: str = "root", mode: str = "755") -> FSNode:
    return FSNode(name=name, is_dir=True, owner=owner, group=group, mode=mode)


def _file(name: str, content: str = "", owner: str = "root", group: str = "root", mode: str = "644") -> FSNode:
    return FSNode(name=name, is_dir=False, owner=owner, group=group, mode=mode, content=content)


PASSWD_TEMPLATE = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false\n"
    "redis:x:113:119::/var/lib/redis:/usr/sbin/nologin\n"
    "sshd:x:114:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    "deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash\n"
)

HOSTS_TEMPLATE = (
    "127.0.0.1 localhost\n"
    "127.0.1.1 {hostname}\n"
    "::1 ip6-localhost ip6-loopback\n"
)

OS_RELEASE_TEMPLATE = (
    'PRETTY_NAME="{distro}"\n'
    'NAME="Ubuntu"\n'
    'VERSION_ID="22.04"\n'
    'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
    'ID=ubuntu\n'
    'ID_LIKE=debian\n'
    'HOME_URL="https://www.ubuntu.com/"\n'
    'SUPPORT_URL="https://help.ubuntu.com/"\n'
)


class FakeFilesystem:
    """Builds and manages one attacker session's fake filesystem tree."""

    def __init__(self, hostname: str, distro: str, kernel: str, fake_users: List[dict]):
        self.hostname = hostname
        self.distro = distro
        self.kernel = kernel
        self.fake_users = fake_users
        self.root = self._build_tree()

    # ------------------------------------------------------------------ #
    # Tree construction
    # ------------------------------------------------------------------ #
    def _build_tree(self) -> FSNode:
        root = _dir("/")
        root.children = {
            "home": _dir("home"),
            "etc": self._build_etc(),
            "var": self._build_var(),
            "root": _dir("root", mode="700"),
            "opt": _dir("opt"),
            "tmp": _dir("tmp", mode="1777"),
            "usr": self._build_usr(),
            "bin": self._build_bin(),
            "proc": _dir("proc"),
            "dev": _dir("dev"),
            "srv": _dir("srv"),
            "mnt": _dir("mnt"),
            "lib": _dir("lib"),
            "sbin": _dir("sbin"),
        }
        # Per-user home directories
        for user in self.fake_users:
            home = user.get("home", "")
            if home.startswith("/home/"):
                uname = home.rsplit("/", 1)[-1]
                home_dir = _dir(uname, owner=uname, group=uname)
                home_dir.children = {
                    ".bash_history": _file(".bash_history", "", owner=uname, group=uname, mode="600"),
                    ".bashrc": _file(".bashrc", "# ~/.bashrc\n", owner=uname, group=uname),
                    ".ssh": _dir(".ssh", owner=uname, group=uname, mode="700"),
                }
                root.children["home"].children[uname] = home_dir
        # /root
        root.children["root"].children = {
            ".bash_history": _file(".bash_history", "", mode="600"),
            ".bashrc": _file(".bashrc", "# ~/.bashrc\n"),
            ".ssh": _dir(".ssh", mode="700"),
        }
        return root

    def _build_etc(self) -> FSNode:
        etc = _dir("etc")
        etc.children = {
            "passwd": _file("passwd", PASSWD_TEMPLATE),
            "shadow": _file("shadow", "root:*:19700:0:99999:7:::\n", mode="640"),
            "hostname": _file("hostname", self.hostname + "\n"),
            "hosts": _file("hosts", HOSTS_TEMPLATE.format(hostname=self.hostname)),
            "os-release": _file("os-release", OS_RELEASE_TEMPLATE.format(distro=self.distro)),
            "issue": _file("issue", f"{self.distro} \\n \\l\n\n"),
            "resolv.conf": _file("resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\n"),
            "nginx": _dir("nginx"),
            "apache2": _dir("apache2"),
            "mysql": _dir("mysql"),
            "ssh": _dir("ssh"),
            "cron.d": _dir("cron.d"),
        }
        etc.children["ssh"].children = {
            "sshd_config": _file(
                "sshd_config",
                "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\n"
                "X11Forwarding yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
            )
        }
        return etc

    def _build_var(self) -> FSNode:
        var = _dir("var")
        log = _dir("log")
        log.children = {
            "auth.log": _file(
                "auth.log",
                "sshd[1021]: Server listening on 0.0.0.0 port 22.\n"
                "sshd[1021]: Accepted publickey for deploy from 10.0.4.9 port 51322 ssh2\n",
            ),
            "syslog": _file("syslog", "systemd[1]: Started Daily apt download activities.\n"),
            "nginx": _dir("nginx"),
            "apache2": _dir("apache2"),
            "mysql": _dir("mysql"),
        }
        var.children = {
            "log": log,
            "www": self._build_www(),
            "lib": _dir("lib"),
            "run": _dir("run"),
            "spool": _dir("spool"),
            "cache": _dir("cache"),
            "backups": _dir("backups"),
        }
        return var

    def _build_www(self) -> FSNode:
        www = _dir("www", owner="www-data", group="www-data")
        html = _dir("html", owner="www-data", group="www-data")
        html.children = {
            "index.html": _file(
                "index.html",
                "<html><body><h1>It works!</h1></body></html>\n",
                owner="www-data", group="www-data",
            ),
        }
        www.children = {"html": html}
        return www

    def _build_usr(self) -> FSNode:
        usr = _dir("usr")
        bin_dir = _dir("bin")
        for tool in ("python3", "python3.10", "curl", "wget", "vim", "nano", "docker",
                     "mysql", "redis-cli", "git", "gcc", "make", "perl"):
            bin_dir.children[tool] = _file(tool, "", mode="755")
        usr.children = {"bin": bin_dir, "lib": _dir("lib"), "local": _dir("local"), "share": _dir("share")}
        return usr

    def _build_bin(self) -> FSNode:
        b = _dir("bin")
        for tool in ("bash", "sh", "ls", "cat", "cp", "mv", "rm", "grep", "ps", "netstat"):
            b.children[tool] = _file(tool, "", mode="755")
        return b

    # ------------------------------------------------------------------ #
    # Path helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def normalize(cwd: str, path: str) -> str:
        """Resolve `path` (possibly relative, with . and ..) against cwd."""
        if not path:
            return cwd
        if not path.startswith("/"):
            path = cwd.rstrip("/") + "/" + path
        parts: List[str] = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts)

    def resolve(self, abs_path: str) -> Optional[FSNode]:
        if abs_path in ("", "/"):
            return self.root
        node = self.root
        for part in abs_path.strip("/").split("/"):
            if not node.is_dir or part not in node.children:
                return None
            node = node.children[part]
        return node

    def resolve_parent(self, abs_path: str):
        """Returns (parent_node, basename) or (None, name) if parent missing."""
        if abs_path in ("", "/"):
            return None, ""
        parent_path, _, name = abs_path.rstrip("/").rpartition("/")
        parent = self.resolve(parent_path if parent_path else "/")
        return parent, name

    # ------------------------------------------------------------------ #
    # Mutating operations (all in-memory only)
    # ------------------------------------------------------------------ #
    def mkdir(self, abs_path: str, parents: bool = False) -> Optional[str]:
        parent, name = self.resolve_parent(abs_path)
        if parent is None:
            if parents:
                parent_path = abs_path.rstrip("/").rpartition("/")[0] or "/"
                err = self.mkdir(parent_path, parents=True)
                if err:
                    return err
                parent, name = self.resolve_parent(abs_path)
            else:
                return f"mkdir: cannot create directory '{abs_path}': No such file or directory"
        if not parent.is_dir:
            return f"mkdir: cannot create directory '{abs_path}': Not a directory"
        if name in parent.children:
            if parents:
                return None
            return f"mkdir: cannot create directory '{abs_path}': File exists"
        parent.children[name] = _dir(name)
        return None

    def touch(self, abs_path: str) -> Optional[str]:
        parent, name = self.resolve_parent(abs_path)
        if parent is None or not parent.is_dir:
            return f"touch: cannot touch '{abs_path}': No such file or directory"
        if name in parent.children:
            parent.children[name].mtime = time.time()
        else:
            parent.children[name] = _file(name)
        return None

    def write_file(self, abs_path: str, content: str, append: bool = False) -> Optional[str]:
        parent, name = self.resolve_parent(abs_path)
        if parent is None or not parent.is_dir:
            return f"-bash: {abs_path}: No such file or directory"
        node = parent.children.get(name)
        if node is None:
            node = _file(name)
            parent.children[name] = node
        if node.is_dir:
            return f"-bash: {abs_path}: Is a directory"
        node.content = (node.content + content) if append else content
        node.mtime = time.time()
        return None

    def remove(self, abs_path: str, recursive: bool = False, force: bool = False) -> Optional[str]:
        if abs_path == "/":
            return "rm: it is dangerous to operate recursively on '/'" if recursive else "rm: cannot remove '/': Is a directory"
        parent, name = self.resolve_parent(abs_path)
        if parent is None or name not in parent.children:
            if force:
                return None
            return f"rm: cannot remove '{abs_path}': No such file or directory"
        node = parent.children[name]
        if node.is_dir and node.children and not recursive:
            return f"rm: cannot remove '{abs_path}': Is a directory"
        del parent.children[name]
        return None

    def listdir(self, abs_path: str):
        node = self.resolve(abs_path)
        if node is None:
            return None
        if not node.is_dir:
            return [node]
        return sorted(node.children.values(), key=lambda n: n.name)

    def clone(self) -> "FakeFilesystem":
        clone = copy.copy(self)
        clone.root = copy.deepcopy(self.root)
        return clone
