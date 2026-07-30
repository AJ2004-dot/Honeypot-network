"""Cosmetic, banner-only stand-ins for other services (Apache, Nginx, Docker
API, MySQL, Redis) so that a port scan of the honeypot host sees a
believable multi-service Linux box.

Safety invariant: these listeners only ever *send* a static banner and then
close the connection (or, for a couple of protocols, reply to a single
trivial probe with a canned response). They never parse or act on
attacker-supplied bytes beyond deciding whether to send the canned reply,
and they never reach out to any other host or process.
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Dict

logger = logging.getLogger("honeypot")

# Static banners / greetings sent immediately on connect, mimicking what a
# real service prints before any protocol negotiation.
_BANNERS: Dict[str, bytes] = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "mysql": bytes([
        0x4a, 0x00, 0x00, 0x00, 0x0a,  # rough MySQL handshake-packet shape
    ]) + b"8.0.36-0ubuntu0.22.04.1\x00",
    "redis-server": b"-ERR unknown command 'GET'\r\n",
}

_HTTP_BANNERS: Dict[str, bytes] = {
    "apache2": (
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\nContent-Length: 45\r\n\r\n"
        b"<html><body><h1>It works!</h1></body></html>"
    ),
    "nginx": (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\nContent-Length: 15\r\n\r\n"
        b"<html>OK</html>"
    ),
    "docker": (
        b"HTTP/1.1 200 OK\r\nApi-Version: 1.43\r\nServer: Docker/24.0.5\r\n"
        b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
    ),
}


class FakeServiceListener:
    """A single tiny TCP listener that sends a canned banner/response and
    disconnects. Runs in its own thread; started/stopped by the server.
    """

    def __init__(self, name: str, bind_address: str, port: int):
        self.name = name
        self.bind_address = bind_address
        self.port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_address, self.port))
        self._sock.listen(20)
        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()
        logger.info("Fake %s banner listener up on %s:%s", self.name, self.bind_address, self.port)

    def _serve_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn: socket.socket, addr):
        try:
            conn.settimeout(3.0)
            payload = _BANNERS.get(self.name) or _HTTP_BANNERS.get(self.name) or b""
            if self.name in _HTTP_BANNERS:
                try:
                    conn.recv(4096)  # drain the request line; never parsed/executed
                except Exception:
                    pass
            conn.sendall(payload)
            logger.info("Fake-service '%s' hit from %s:%s", self.name, addr[0], addr[1])
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
