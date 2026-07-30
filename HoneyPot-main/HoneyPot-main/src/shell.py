"""An interactive fake shell that interprets attacker commands against the
FakeFilesystem, without ever executing anything for real.

Every `cmd_*` method takes the parsed argv (minus the command name itself)
and returns `(output: str, success: bool)`. `success=False` marks a
"failed command" for the session recorder (nonzero exit / not found /
permission denied, mirroring realistic Linux behavior).
"""
from __future__ import annotations

import random
import shlex
import time
from typing import Callable, Dict, List, Optional, Tuple

from .filesystem import FakeFilesystem
from .malware_capture import MalwareCaptureLogger, parse_fetch_command

FAKE_PROCESSES = [
    ("root", 1, "0.0", "0.1", "/sbin/init"),
    ("root", 612, "0.0", "0.3", "/lib/systemd/systemd-journald"),
    ("root", 780, "0.0", "0.2", "/usr/sbin/sshd -D"),
    ("root", 902, "0.1", "0.5", "/usr/sbin/nginx: master process"),
    ("www-data", 903, "0.0", "0.4", "nginx: worker process"),
    ("www-data", 1140, "0.3", "1.2", "/usr/sbin/apache2 -k start"),
    ("mysql", 1188, "0.2", "3.9", "/usr/sbin/mysqld"),
    ("redis", 1201, "0.0", "0.4", "/usr/bin/redis-server 127.0.0.1:6379"),
    ("root", 1340, "0.0", "0.6", "/usr/bin/dockerd -H fd://"),
    ("root", 1355, "0.0", "0.2", "containerd --config /var/run/docker/containerd/containerd.toml"),
    ("root", 2201, "0.0", "0.1", "cron"),
]

NET_CONNECTIONS = [
    ("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", "780/sshd"),
    ("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN", "902/nginx"),
    ("tcp", "127.0.0.1:3306", "0.0.0.0:*", "LISTEN", "1188/mysqld"),
    ("tcp", "127.0.0.1:6379", "0.0.0.0:*", "LISTEN", "1201/redis-server"),
    ("tcp", "0.0.0.0:2375", "0.0.0.0:*", "LISTEN", "1340/dockerd"),
    ("tcp", "10.0.4.17:22", "203.0.113.44:51322", "ESTABLISHED", "780/sshd"),
]


def _fmt_ls_long(node, name_override: Optional[str] = None) -> str:
    perms = ("d" if node.is_dir else "-") + _mode_to_rwx(node.mode)
    links = 2 if node.is_dir else 1
    when = time.strftime("%b %d %H:%M", time.gmtime(node.mtime))
    name = name_override or node.name
    return f"{perms} {links:>2} {node.owner:<8} {node.group:<8} {node.size():>6} {when} {name}"


def _mode_to_rwx(mode: str) -> str:
    mapping = {"0": "---", "1": "--x", "2": "-w-", "3": "-wx", "4": "r--", "5": "r-x", "6": "rw-", "7": "rwx"}
    digits = mode[-3:].rjust(3, "7")
    return "".join(mapping.get(d, "rwx") for d in digits)


class FakeShell:
    """Per-session shell state machine."""

    def __init__(self, username: str, hostname: str, fs: FakeFilesystem,
                 home_dir: str, malware_logger: MalwareCaptureLogger,
                 session_id: str, src_ip: str, on_malware_capture=None):
        self.username = username
        self.hostname = hostname
        self.fs = fs
        self.cwd = home_dir if fs.resolve(home_dir) else "/root"
        self.home_dir = self.cwd
        self.malware_logger = malware_logger
        self.session_id = session_id
        self.src_ip = src_ip
        self.history: List[str] = []
        self.on_malware_capture = on_malware_capture
        self.env = {
            "HOME": self.home_dir,
            "USER": username,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": self.cwd,
        }
        self.uid = 0 if username == "root" else 1000
        self._dispatch: Dict[str, Callable] = {
            "ls": self.cmd_ls, "pwd": self.cmd_pwd, "whoami": self.cmd_whoami,
            "hostname": self.cmd_hostname, "uname": self.cmd_uname, "id": self.cmd_id,
            "history": self.cmd_history, "cat": self.cmd_cat, "touch": self.cmd_touch,
            "mkdir": self.cmd_mkdir, "rm": self.cmd_rm, "wget": self.cmd_wget,
            "curl": self.cmd_curl, "chmod": self.cmd_chmod, "sudo": self.cmd_sudo,
            "find": self.cmd_find, "ps": self.cmd_ps, "netstat": self.cmd_netstat,
            "ifconfig": self.cmd_ifconfig, "ip": self.cmd_ip, "systemctl": self.cmd_systemctl,
            "journalctl": self.cmd_journalctl, "vim": self.cmd_editor, "vi": self.cmd_editor,
            "nano": self.cmd_editor, "python": self.cmd_python, "python3": self.cmd_python,
            "bash": self.cmd_subshell, "sh": self.cmd_subshell, "cd": self.cmd_cd,
            "echo": self.cmd_echo, "clear": self.cmd_clear, "cp": self.cmd_cp, "mv": self.cmd_mv,
            "grep": self.cmd_grep, "df": self.cmd_df, "free": self.cmd_free, "top": self.cmd_top,
            "uptime": self.cmd_uptime, "w": self.cmd_w, "who": self.cmd_w, "last": self.cmd_last,
            "passwd": self.cmd_passwd, "apt": self.cmd_apt, "apt-get": self.cmd_apt,
            "service": self.cmd_service, "kill": self.cmd_kill, "man": self.cmd_man,
            "export": self.cmd_export, "env": self.cmd_env, "which": self.cmd_which,
            "ssh": self.cmd_ssh, "scp": self.cmd_noop_success, "tar": self.cmd_noop_success,
            "unzip": self.cmd_noop_success, "gcc": self.cmd_gcc, "make": self.cmd_make,
            "reboot": self.cmd_reboot, "shutdown": self.cmd_reboot, "crontab": self.cmd_crontab,
        }

    # ------------------------------------------------------------------ #
    # Prompt / dispatch
    # ------------------------------------------------------------------ #
    def prompt(self) -> str:
        marker = "#" if self.username == "root" else "$"
        short_home = self.cwd
        if self.cwd == self.home_dir:
            short_home = "~"
        elif self.cwd.startswith(self.home_dir + "/"):
            short_home = "~" + self.cwd[len(self.home_dir):]
        return f"{self.username}@{self.hostname}:{short_home}{marker} "

    def execute(self, line: str) -> Tuple[str, bool, Optional[str]]:
        """Runs one line of shell input.

        Returns (output, success, exit_command) where exit_command is set
        to a reason string if this line should terminate the session
        (e.g. `exit`, `logout`).
        """
        line = line.strip()
        if not line:
            return "", True, None
        self.history.append(line)

        segments = [seg.strip() for seg in line.split("&&")]
        outputs = []
        overall_success = True
        for seg in segments:
            out, ok, exit_reason = self._execute_single(seg)
            if out:
                outputs.append(out)
            overall_success = overall_success and ok
            if exit_reason:
                return "\n".join(outputs), overall_success, exit_reason
            if not ok:
                break
        return "\n".join(outputs), overall_success, None

    def _execute_single(self, line: str) -> Tuple[str, bool, Optional[str]]:
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        if not tokens:
            return "", True, None

        cmd, *args = tokens

        if cmd in ("exit", "logout"):
            return "logout", True, "user exited shell"

        redirect_target, append, args = self._extract_redirect(args)

        handler = self._dispatch.get(cmd)
        if handler is None:
            return f"{cmd}: command not found", False, None

        try:
            output, success = handler(args)
        except Exception:
            output, success = f"{cmd}: an unexpected error occurred", False

        if redirect_target:
            abs_target = self.fs.normalize(self.cwd, redirect_target)
            err = self.fs.write_file(abs_target, (output + "\n" if output else ""), append=append)
            if err:
                return err, False, None
            return "", success, None

        return output, success, None

    @staticmethod
    def _extract_redirect(args: List[str]):
        for i, tok in enumerate(args):
            if tok == ">":
                if i + 1 < len(args):
                    return args[i + 1], False, args[:i]
            elif tok == ">>":
                if i + 1 < len(args):
                    return args[i + 1], True, args[:i]
            elif tok.startswith(">>") and len(tok) > 2:
                return tok[2:], True, args[:i]
            elif tok.startswith(">") and len(tok) > 1:
                return tok[1:], False, args[:i]
        return None, False, args

    # ------------------------------------------------------------------ #
    # Filesystem-facing commands
    # ------------------------------------------------------------------ #
    def cmd_pwd(self, args):
        return self.cwd, True

    def cmd_cd(self, args):
        target = args[0] if args else self.home_dir
        abs_path = self.fs.normalize(self.cwd, target)
        node = self.fs.resolve(abs_path)
        if node is None:
            return f"-bash: cd: {target}: No such file or directory", False
        if not node.is_dir:
            return f"-bash: cd: {target}: Not a directory", False
        self.cwd = abs_path
        self.env["PWD"] = abs_path
        return "", True

    def cmd_ls(self, args):
        long_fmt = "-l" in args or "-la" in args or "-al" in args or "-alh" in args or "-lh" in args
        show_all = "-a" in args or "-la" in args or "-al" in args or "-alh" in args
        targets = [a for a in args if not a.startswith("-")] or ["."]
        outputs = []
        for target in targets:
            abs_path = self.fs.normalize(self.cwd, target)
            nodes = self.fs.listdir(abs_path)
            if nodes is None:
                outputs.append(f"ls: cannot access '{target}': No such file or directory")
                continue
            if not show_all:
                nodes = [n for n in nodes if not n.name.startswith(".")]
            if long_fmt:
                lines = [f"total {len(nodes) * 4}"] + [_fmt_ls_long(n) for n in nodes]
                outputs.append("\n".join(lines))
            else:
                outputs.append("  ".join(n.name for n in nodes))
        return "\n".join(outputs), True

    def cmd_cat(self, args):
        if not args:
            return "", True
        outputs = []
        ok = True
        for target in args:
            if target.startswith("-"):
                continue
            abs_path = self.fs.normalize(self.cwd, target)
            node = self.fs.resolve(abs_path)
            if node is None:
                outputs.append(f"cat: {target}: No such file or directory")
                ok = False
            elif node.is_dir:
                outputs.append(f"cat: {target}: Is a directory")
                ok = False
            else:
                outputs.append(node.content.rstrip("\n"))
        return "\n".join(outputs), ok

    def cmd_touch(self, args):
        if not args:
            return "touch: missing file operand", False
        ok = True
        for target in args:
            abs_path = self.fs.normalize(self.cwd, target)
            err = self.fs.touch(abs_path)
            if err:
                ok = False
        return "", ok

    def cmd_mkdir(self, args):
        parents = "-p" in args
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return "mkdir: missing operand", False
        outputs, ok = [], True
        for target in targets:
            abs_path = self.fs.normalize(self.cwd, target)
            err = self.fs.mkdir(abs_path, parents=parents)
            if err:
                outputs.append(err)
                ok = False
        return "\n".join(outputs), ok

    def cmd_rm(self, args):
        recursive = any(f in args for f in ("-r", "-rf", "-fr", "-R"))
        force = any(f in args for f in ("-f", "-rf", "-fr"))
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return "rm: missing operand", False
        outputs, ok = [], True
        for target in targets:
            abs_path = self.fs.normalize(self.cwd, target)
            err = self.fs.remove(abs_path, recursive=recursive, force=force)
            if err:
                outputs.append(err)
                ok = False
        return "\n".join(outputs), ok

    def cmd_cp(self, args):
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            return "cp: missing destination file operand", False
        src_path = self.fs.normalize(self.cwd, targets[0])
        node = self.fs.resolve(src_path)
        if node is None:
            return f"cp: cannot stat '{targets[0]}': No such file or directory", False
        dst_path = self.fs.normalize(self.cwd, targets[-1])
        self.fs.write_file(dst_path, node.content if not node.is_dir else "")
        return "", True

    def cmd_mv(self, args):
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            return "mv: missing destination file operand", False
        src_path = self.fs.normalize(self.cwd, targets[0])
        node = self.fs.resolve(src_path)
        if node is None:
            return f"mv: cannot stat '{targets[0]}': No such file or directory", False
        dst_path = self.fs.normalize(self.cwd, targets[-1])
        self.fs.write_file(dst_path, node.content if not node.is_dir else "")
        self.fs.remove(src_path, recursive=True, force=True)
        return "", True

    def cmd_grep(self, args):
        pattern = None
        files = []
        for a in args:
            if a.startswith("-"):
                continue
            if pattern is None:
                pattern = a
            else:
                files.append(a)
        if pattern is None:
            return "Usage: grep [OPTION]... PATTERNS [FILE]...", False
        outputs = []
        for f in files:
            abs_path = self.fs.normalize(self.cwd, f)
            node = self.fs.resolve(abs_path)
            if node is None or node.is_dir:
                outputs.append(f"grep: {f}: No such file or directory")
                continue
            for line in node.content.splitlines():
                if pattern in line:
                    outputs.append(line)
        return "\n".join(outputs), True

    def cmd_echo(self, args):
        return " ".join(a.strip('"').strip("'") for a in args), True

    def cmd_clear(self, args):
        return "\x1b[H\x1b[2J", True

    # ------------------------------------------------------------------ #
    # Identity / system-info commands
    # ------------------------------------------------------------------ #
    def cmd_whoami(self, args):
        return self.username, True

    def cmd_hostname(self, args):
        return self.hostname, True

    def cmd_uname(self, args):
        if "-a" in args:
            return f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux", True
        if "-r" in args:
            return "5.15.0-105-generic", True
        if "-m" in args:
            return "x86_64", True
        return "Linux", True

    def cmd_id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)", True
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)", True

    def cmd_history(self, args):
        return "\n".join(f"{i+1}  {c}" for i, c in enumerate(self.history)), True

    def cmd_passwd(self, args):
        return "passwd: Authentication token manipulation error\npasswd: password unchanged", False

    def cmd_export(self, args):
        for a in args:
            if "=" in a:
                k, _, v = a.partition("=")
                self.env[k] = v
        return "", True

    def cmd_env(self, args):
        return "\n".join(f"{k}={v}" for k, v in self.env.items()), True

    def cmd_which(self, args):
        if not args:
            return "", True
        known = {"bash", "sh", "python3", "python", "curl", "wget", "vim", "nano", "ls", "cat", "ssh"}
        target = args[0]
        if target in known:
            return f"/usr/bin/{target}", True
        return "", False

    # ------------------------------------------------------------------ #
    # Network / process visibility commands
    # ------------------------------------------------------------------ #
    def cmd_ps(self, args):
        header = "USER         PID %CPU %MEM COMMAND"
        rows = [f"{u:<12} {pid:>4} {cpu:>4} {mem:>4} {cmd}" for u, pid, cpu, mem, cmd in FAKE_PROCESSES]
        return "\n".join([header] + rows), True

    def cmd_top(self, args):
        header = (
            f"top - {time.strftime('%H:%M:%S')} up 14 days,  3:27,  1 user,  load average: 0.08, 0.05, 0.01\n"
            "Tasks: 118 total,   1 running, 117 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.1 wa\n"
            "MiB Mem :   3928.0 total,   2891.4 free,    612.7 used,    423.9 buff/cache\n\n"
            "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"
        )
        rows = [f"{pid:>5} {u:<9} 20   0  412300  38200  12800 S  {cpu:>5} {mem:>5}   0:12.44 {cmd.split()[0]}"
                for u, pid, cpu, mem, cmd in FAKE_PROCESSES]
        return header + "\n" + "\n".join(rows), True

    def cmd_netstat(self, args):
        header = "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
        rows = [f"{proto:<5} 0      0      {local:<23} {foreign:<23} {state:<11} {pid}" for proto, local, foreign, state, pid in NET_CONNECTIONS]
        return "\n".join([header] + rows), True

    def cmd_ifconfig(self, args):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.4.17  netmask 255.255.255.0  broadcast 10.0.4.255\n"
            "        ether 02:42:0a:00:04:11  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 918213  bytes 812744192 (812.7 MB)\n"
            "        TX packets 542011  bytes 91827362 (91.8 MB)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
        ), True

    def cmd_ip(self, args):
        sub = args[0] if args else ""
        if sub in ("a", "addr", "address"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
                "    inet 10.0.4.17/24 brd 10.0.4.255 scope global eth0\n"
            ), True
        if sub in ("r", "route"):
            return "default via 10.0.4.1 dev eth0 proto dhcp metric 100\n10.0.4.0/24 dev eth0 proto kernel scope link src 10.0.4.17", True
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }", False

    # ------------------------------------------------------------------ #
    # Service-management commands
    # ------------------------------------------------------------------ #
    def cmd_systemctl(self, args):
        services = {
            "ssh": "active (running)", "sshd": "active (running)",
            "nginx": "active (running)", "apache2": "active (running)",
            "mysql": "active (running)", "docker": "active (running)",
            "redis-server": "active (running)", "cron": "active (running)",
        }
        if not args:
            return "Usage: systemctl [OPTIONS...] COMMAND ...", False
        sub = args[0]
        if sub == "status" and len(args) > 1:
            svc = args[1].replace(".service", "")
            state = services.get(svc)
            if state is None:
                return f"Unit {svc}.service could not be found.", False
            return (
                f"\u25cf {svc}.service - {svc.capitalize()} service\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)\n"
                f"     Active: {state} since Mon 2026-07-14 09:12:03 UTC; 2 weeks ago"
            ), True
        if sub == "list-units":
            lines = [f"{s}.service{' ' * (25-len(s))}loaded active running {s}" for s in services]
            return "\n".join(lines), True
        if sub in ("restart", "start", "stop", "reload") and len(args) > 1:
            return "", True
        return f"systemctl: unrecognized command '{' '.join(args)}'", False

    def cmd_service(self, args):
        if len(args) < 2:
            return "Usage: service <name> {start|stop|restart|status}", False
        name, action = args[0], args[1]
        if action == "status":
            return f" * {name} is running", True
        return f" * {action}ing {name} ", True

    def cmd_journalctl(self, args):
        lines = [
            "-- Logs begin at Mon 2026-07-14 09:11:58 UTC. --",
            "Jul 27 08:01:12 " + self.hostname + " sshd[2211]: Accepted password for deploy from 10.0.4.9 port 44120 ssh2",
            "Jul 27 08:03:44 " + self.hostname + " systemd[1]: Started Session 118 of user deploy.",
            "Jul 27 09:14:02 " + self.hostname + " CRON[3390]: (root) CMD (/usr/bin/certbot renew --quiet)",
            "Jul 27 10:22:51 " + self.hostname + " kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.4",
        ]
        return "\n".join(lines), True

    def cmd_apt(self, args):
        if args and args[0] == "update":
            return "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\nReading package lists... Done", True
        if args and args[0] in ("install", "upgrade"):
            return "Reading package lists... Done\nBuilding dependency tree... Done\n0 upgraded, 0 newly installed, 0 to remove.", True
        return "apt: usage error", False

    def cmd_kill(self, args):
        return "", True

    def cmd_crontab(self, args):
        if "-l" in args:
            return "no crontab for " + self.username, False
        return "", True

    def cmd_reboot(self, args):
        return "", True

    # ------------------------------------------------------------------ #
    # Fetch / privilege / interpreter commands
    # ------------------------------------------------------------------ #
    def cmd_wget(self, args):
        raw = "wget " + " ".join(args)
        parsed = parse_fetch_command(raw)
        if not parsed:
            return "wget: missing URL", False
        if self.on_malware_capture:
            self.on_malware_capture(raw)
        return (
            f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {parsed['url']}\n"
            f"Resolving host... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address"
        ), False

    def cmd_curl(self, args):
        raw = "curl " + " ".join(args)
        parsed = parse_fetch_command(raw)
        if not parsed:
            return "curl: try 'curl --help' for more information", False
        if self.on_malware_capture:
            self.on_malware_capture(raw)
        return "curl: (6) Could not resolve host: " + parsed["url"].split("//", 1)[-1].split("/")[0], False

    def cmd_chmod(self, args):
        return "", True

    def cmd_sudo(self, args):
        if not args:
            return "usage: sudo [command]", False
        inner = " ".join(args)
        return self._execute_single(inner)[0:2][0], True

    def cmd_find(self, args):
        start = "."
        for a in args:
            if not a.startswith("-"):
                start = a
                break
        abs_path = self.fs.normalize(self.cwd, start)
        results = []

        def walk(path, node):
            results.append(path)
            if node.is_dir:
                for child_name in sorted(node.children):
                    child = node.children[child_name]
                    walk((path.rstrip("/") + "/" + child_name), child)

        node = self.fs.resolve(abs_path)
        if node is None:
            return f"find: '{start}': No such file or directory", False
        walk(abs_path if abs_path != "" else "/", node)
        return "\n".join(results), True

    def cmd_python(self, args):
        if not args:
            return ">>> ", True
        if args[0] == "-c" and len(args) > 1:
            code = args[1]
            if "import socket" in code or "import os" in code:
                return "", True
            return "", True
        return f"python3: can't open file '{args[0]}': [Errno 2] No such file or directory", False

    def cmd_subshell(self, args):
        if args and args[0] == "-c" and len(args) > 1:
            return self._execute_single(args[1])[0:2][0], True
        return "", True

    def cmd_ssh(self, args):
        target = args[-1] if args else "?"
        return f"ssh: connect to host {target.split('@')[-1]} port 22: Connection refused", False

    def cmd_noop_success(self, args):
        return "", True

    def cmd_gcc(self, args):
        if not args:
            return "gcc: fatal error: no input files\ncompilation terminated.", False
        return "", True

    def cmd_make(self, args):
        return "make: *** No targets specified and no makefile found.  Stop.", False

    def cmd_man(self, args):
        if not args:
            return "What manual page do you want?", False
        return f"No manual entry for {args[0]}", False

    def cmd_editor(self, args):
        target = args[0] if args else "[No Name]"
        return (
            f'"{target}" [New] 0L, 0C\n'
            "~\n" * 3 +
            f'"{target}" written'
        ), True

    def cmd_df(self, args):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        30G   13G   16G  45% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm"
        ), True

    def cmd_free(self, args):
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:         4021928      636221     2961876        1560      423831     3141234\n"
            "Swap:              0           0           0"
        ), True

    def cmd_uptime(self, args):
        return " 10:41:02 up 14 days,  3:27,  1 user,  load average: 0.08, 0.05, 0.01", True

    def cmd_w(self, args):
        return (
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{self.username}     pts/0    {self.src_ip}    {time.strftime('%H:%M')}    0.00s  0.04s  0.01s  -bash"
        ), True

    def cmd_last(self, args):
        return (
            f"{self.username}     pts/0        {self.src_ip}    {time.strftime('%a %b %d %H:%M')}   still logged in\n"
            "reboot   system boot  5.15.0-105-generic Mon Jul 14 09:11   still running"
        ), True
