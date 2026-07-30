"""Original SSH honeypot server built on Paramiko.

High-level flow
----------------
1. Bind a TCP socket, accept connections.
2. For each connection, wrap it in a paramiko.Transport and negotiate SSH
   using a fake Ubuntu OpenSSH banner + a `HoneypotServerInterface` that
   accepts (and logs) any username/password.
3. Once a channel + PTY + shell request come in, hand control to an
   interactive loop that reads raw bytes, does basic line-editing
   (backspace, history), and feeds completed lines to a `FakeShell`
   instance backed by a per-session `FakeFilesystem`.
4. Every attacker action is written to a `SessionRecorder`; on disconnect
   the full session is flushed to `logs/session_<id>.json`.

Nothing in this file (or anything it calls) ever executes attacker input,
downloads a file, or opens an outbound connection. See README's "Security"
section.
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import threading
import time
from typing import Optional

import paramiko

from .config_loader import HoneypotConfig
from .fake_services import FakeServiceListener
from .filesystem import FakeFilesystem
from .fingerprint import fingerprint_client
from .geoip_lookup import GeoIPResolver
from .malware_capture import MalwareCaptureLogger
from .session_recorder import SessionRecorder
from .shell import FakeShell
from .utils.logging_setup import setup_logging

logger = logging.getLogger("honeypot")

BACKSPACE = {0x08, 0x7F}
CTRL_C = 0x03
CTRL_D = 0x04
ENTER = {ord("\r"), ord("\n")}


class HoneypotServerInterface(paramiko.ServerInterface):
    """Accepts every username/password (after an optional simulated delay),
    while logging each attempt through the SessionRecorder."""

    def __init__(self, recorder: SessionRecorder, cfg: HoneypotConfig):
        super().__init__()
        self.recorder = recorder
        self.cfg = cfg
        self.event = threading.Event()
        self.term = ""
        self.term_width = 80
        self.term_height = 24
        self._auth_count = 0
        self.accepted_username: Optional[str] = None

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        self._auth_count += 1
        time.sleep(self.cfg.ssh.auth_delay_seconds)

        # Accept on the first attempt (or after max_auth_tries as a fallback)
        # so brute-forcers that expect several tries still get logged
        # realistically, but interactive attackers aren't kept waiting.
        accept = True
        self.recorder.log_auth_attempt(username, password, accepted=accept)
        if accept:
            self.accepted_username = username
        return paramiko.AUTH_SUCCESSFUL if accept else paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        # Attackers sometimes do `ssh host "whoami"` (non-interactive exec).
        # NOTE: paramiko's Channel class already defines a method named
        # `exec_command` (client-side API), so we must not reuse that name
        # for our own marker attribute or every channel would look like an
        # exec request. Use a distinct, honeypot-specific attribute instead.
        self.event.set()
        channel._hp_exec_command = command  # type: ignore[attr-defined]
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        self.term = term.decode() if isinstance(term, bytes) else str(term)
        self.term_width, self.term_height = width, height
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight) -> bool:
        self.term_width, self.term_height = width, height
        return True


class ClientSessionHandler:
    """Owns the full lifecycle of one accepted TCP connection."""

    def __init__(self, client_sock: socket.socket, addr, cfg: HoneypotConfig,
                 geoip: GeoIPResolver, malware_logger: MalwareCaptureLogger):
        self.client_sock = client_sock
        self.src_ip, self.src_port = addr[0], addr[1]
        self.cfg = cfg
        self.geoip = geoip
        self.malware_logger = malware_logger
        self.recorder = SessionRecorder(self.src_ip, self.src_port, cfg.logging.log_dir)

    def run(self):
        transport: Optional[paramiko.Transport] = None
        disconnect_reason = "client disconnected"
        try:
            transport = paramiko.Transport(self.client_sock)
            transport.local_version = self.cfg.ssh.banner
            host_key = self._load_host_key()
            transport.add_server_key(host_key)

            server_iface = HoneypotServerInterface(self.recorder, self.cfg)
            transport.start_server(server=server_iface)

            client_banner = transport.remote_version or ""
            self.recorder.set_client_banner(client_banner)
            fp = fingerprint_client(client_banner)
            self.recorder.set_fingerprint(fp.label, fp.confidence, fp.likely_scanner)
            if fp.likely_scanner:
                logger.info("Likely scanner/tool from %s: %s", self.src_ip, fp.label)

            geo = self.geoip.lookup(self.src_ip)
            self.recorder.set_geo(geo.country, geo.city, geo.asn, geo.isp)

            channel = transport.accept(20)
            if channel is None:
                disconnect_reason = "no channel opened (likely a scanner probe)"
                return

            server_iface.event.wait(10)
            self.recorder.set_terminal(server_iface.term, server_iface.term_width, server_iface.term_height)

            username = server_iface.accepted_username or "root"

            if hasattr(channel, "_hp_exec_command"):
                disconnect_reason = self._handle_exec(channel, username)
            else:
                disconnect_reason = self._handle_interactive_shell(channel, username, server_iface)

        except (EOFError, ConnectionResetError, paramiko.SSHException) as exc:
            disconnect_reason = f"connection error: {exc}"
        except Exception as exc:  # pragma: no cover - defensive catch-all
            logger.exception("Unhandled error in session from %s", self.src_ip)
            disconnect_reason = f"internal error: {exc}"
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            self.recorder.finalize(disconnect_reason)
            path = self.recorder.flush()
            logger.info("Session %s from %s closed (%s) -> %s",
                        self.recorder.record.session_id, self.src_ip, disconnect_reason, path)

    # ------------------------------------------------------------------ #
    def _build_shell(self, username: str) -> FakeShell:
        fake_users = self.cfg.fake_users()
        user_entry = next((u for u in fake_users if u["username"] == username), None)
        home_dir = user_entry["home"] if user_entry else f"/home/{username}"

        fs = FakeFilesystem(
            hostname=self.cfg.identity.hostname,
            distro=self.cfg.identity.distro,
            kernel=self.cfg.identity.kernel,
            fake_users=fake_users,
        )

        def on_fetch(command: str):
            rec = self.malware_logger.record(self.recorder.record.session_id, self.src_ip, command)
            if rec:
                from dataclasses import asdict
                self.recorder.log_malware_fetch(asdict(rec))

        return FakeShell(
            username=username,
            hostname=self.cfg.identity.hostname,
            fs=fs,
            home_dir=home_dir,
            malware_logger=self.malware_logger,
            session_id=self.recorder.record.session_id,
            src_ip=self.src_ip,
            on_malware_capture=on_fetch,
        )

    def _handle_exec(self, channel, username: str) -> str:
        shell = self._build_shell(username)
        command = channel._hp_exec_command.decode(errors="replace")  # type: ignore[attr-defined]
        output, success, _ = shell.execute(command)
        self.recorder.log_command(command, success, output.count("\n") + 1 if output else 0)
        try:
            channel.send((output + "\n").encode() if output else b"")
            channel.send_exit_status(0 if success else 1)
        except Exception:
            pass
        return "exec command completed"

    def _handle_interactive_shell(self, channel, username: str, server_iface: HoneypotServerInterface) -> str:
        shell = self._build_shell(username)
        channel.settimeout(self.cfg.ssh.idle_timeout_seconds)

        motd = self.cfg.identity.motd.format(
            timestamp=time.strftime("%a %b %d %H:%M:%S %Y"),
            last_login=time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(time.time() - 86400)),
        )
        self._send(channel, motd + "\r\n" + shell.prompt())

        line_buf = ""
        history_idx = -1

        while True:
            try:
                data = channel.recv(1024)
            except socket.timeout:
                return "idle timeout"
            if not data:
                return "client closed channel"

            for byte in data:
                if byte in ENTER:
                    self._send(channel, "\r\n")
                    if line_buf.strip():
                        output, success, exit_reason = shell.execute(line_buf)
                        self.recorder.log_command(line_buf, success, output.count("\n") + 1 if output else 0)
                        if output:
                            self._send(channel, output.replace("\n", "\r\n") + "\r\n")
                        if exit_reason:
                            self._send(channel, "logout\r\n")
                            return exit_reason
                    line_buf = ""
                    history_idx = -1
                    self._send(channel, shell.prompt())
                elif byte in BACKSPACE:
                    if line_buf:
                        line_buf = line_buf[:-1]
                        self._send(channel, "\b \b")
                elif byte == CTRL_C:
                    line_buf = ""
                    self._send(channel, "^C\r\n" + shell.prompt())
                elif byte == CTRL_D:
                    self._send(channel, "logout\r\n")
                    return "client sent EOF (Ctrl-D)"
                elif 32 <= byte < 127:
                    ch = chr(byte)
                    line_buf += ch
                    self._send(channel, ch)
                # else: ignore other control/escape sequences (arrow keys etc.)

    @staticmethod
    def _send(channel, text: str):
        try:
            channel.send(text.encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _load_host_key(self) -> paramiko.PKey:
        path = self.cfg.ssh.host_key_path
        if not os.path.exists(path):
            logger.warning("Host key not found at %s, generating a new one.", path)
            key = paramiko.RSAKey.generate(2048)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            key.write_private_key_file(path)
            return key
        return paramiko.RSAKey.from_private_key_file(path)


class HoneypotServer:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.cfg = HoneypotConfig.load(config_path)
        setup_logging(self.cfg.logging.app_log_file, self.cfg.logging.level)
        self.geoip = GeoIPResolver(
            self.cfg.geoip.city_db, self.cfg.geoip.asn_db, enabled=self.cfg.geoip.enabled
        )
        self.malware_logger = MalwareCaptureLogger(
            self.cfg.malware_capture.capture_log, enabled=self.cfg.malware_capture.enabled
        )
        self._fake_listeners = []
        self._running = False

    def _start_fake_services(self):
        if not self.cfg.fake_services.expose_banner_ports:
            return
        for name in self.cfg.fake_services.enabled:
            if name == "ssh":
                continue  # the real honeypot already serves this "protocol"
            port = self.cfg.fake_services.ports.get(name)
            if not port:
                continue
            listener = FakeServiceListener(name, self.cfg.ssh.bind_address, port)
            try:
                listener.start()
                self._fake_listeners.append(listener)
            except OSError as exc:
                logger.warning("Could not bind fake service %s on port %s: %s", name, port, exc)

    def serve_forever(self):
        self._running = True
        self._start_fake_services()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.cfg.ssh.bind_address, self.cfg.ssh.port))
        sock.listen(100)
        logger.info("SSH honeypot listening on %s:%s (fake hostname=%s)",
                    self.cfg.ssh.bind_address, self.cfg.ssh.port, self.cfg.identity.hostname)

        active_sessions = 0
        try:
            while self._running:
                client_sock, addr = sock.accept()
                if active_sessions >= self.cfg.ssh.max_sessions:
                    logger.warning("Max sessions reached, dropping connection from %s", addr[0])
                    client_sock.close()
                    continue

                def worker(cs=client_sock, a=addr):
                    nonlocal active_sessions
                    active_sessions += 1
                    try:
                        ClientSessionHandler(cs, a, self.cfg, self.geoip, self.malware_logger).run()
                    finally:
                        active_sessions -= 1

                threading.Thread(target=worker, daemon=True).start()
        except KeyboardInterrupt:
            logger.info("Shutting down (KeyboardInterrupt).")
        finally:
            self._running = False
            for listener in self._fake_listeners:
                listener.stop()
            sock.close()
            self.geoip.close()


def main():
    parser = argparse.ArgumentParser(description="Original educational SSH honeypot")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    args = parser.parse_args()
    HoneypotServer(args.config).serve_forever()


if __name__ == "__main__":
    main()
