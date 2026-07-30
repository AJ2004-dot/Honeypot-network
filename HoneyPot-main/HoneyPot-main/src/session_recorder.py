"""Records everything about one attacker session and dumps it as JSON."""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CommandEvent:
    timestamp: str
    command: str
    success: bool
    output_lines: int = 0


@dataclass
class AuthAttempt:
    timestamp: str
    username: str
    password: str
    accepted: bool


@dataclass
class SessionRecord:
    session_id: str
    src_ip: str
    src_port: int
    start_time: str
    client_banner: str = ""
    fingerprint_label: str = ""
    fingerprint_confidence: str = ""
    likely_scanner: bool = False
    geo_country: str = "unknown"
    geo_city: str = "unknown"
    geo_asn: str = "unknown"
    geo_isp: str = "unknown"
    auth_attempts: List[Dict[str, Any]] = field(default_factory=list)
    accepted_username: Optional[str] = None
    accepted_password: Optional[str] = None
    terminal: str = ""
    term_width: int = 0
    term_height: int = 0
    commands: List[Dict[str, Any]] = field(default_factory=list)
    failed_commands: List[str] = field(default_factory=list)
    malware_fetches: List[Dict[str, Any]] = field(default_factory=list)
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    disconnect_reason: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


class SessionRecorder:
    """One instance per connected client. Call methods as events happen,
    then `finalize()` + `flush()` on disconnect."""

    def __init__(self, src_ip: str, src_port: int, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._start_monotonic = time.monotonic()
        self.record = SessionRecord(
            session_id=uuid.uuid4().hex[:12],
            src_ip=src_ip,
            src_port=src_port,
            start_time=_now_iso(),
        )

    # -- setters ---------------------------------------------------------
    def set_client_banner(self, banner: str):
        self.record.client_banner = banner

    def set_fingerprint(self, label: str, confidence: str, likely_scanner: bool):
        self.record.fingerprint_label = label
        self.record.fingerprint_confidence = confidence
        self.record.likely_scanner = likely_scanner

    def set_geo(self, country: str, city: str, asn: str, isp: str):
        self.record.geo_country = country
        self.record.geo_city = city
        self.record.geo_asn = asn
        self.record.geo_isp = isp

    def set_terminal(self, term: str, width: int, height: int):
        self.record.terminal = term
        self.record.term_width = width
        self.record.term_height = height

    # -- events ------------------------------------------------------------
    def log_auth_attempt(self, username: str, password: str, accepted: bool):
        self.record.auth_attempts.append(
            asdict(AuthAttempt(_now_iso(), username, password, accepted))
        )
        if accepted:
            self.record.accepted_username = username
            self.record.accepted_password = password

    def log_command(self, command: str, success: bool = True, output_lines: int = 0):
        self.record.commands.append(
            asdict(CommandEvent(_now_iso(), command, success, output_lines))
        )
        if not success:
            self.record.failed_commands.append(command)

    def log_malware_fetch(self, capture_record: dict):
        self.record.malware_fetches.append(capture_record)

    # -- lifecycle ---------------------------------------------------------
    def finalize(self, disconnect_reason: str = "client disconnected"):
        self.record.end_time = _now_iso()
        self.record.duration_seconds = round(time.monotonic() - self._start_monotonic, 3)
        self.record.disconnect_reason = disconnect_reason

    def flush(self) -> str:
        filename = f"session_{self.record.session_id}.json"
        path = os.path.join(self.log_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.record.to_json())
        return path
