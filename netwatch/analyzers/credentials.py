"""Cleartext credentials (RF5): FTP, POP3, HTTP Basic and HTTP POST forms.

The real password never leaves this module: it is masked as soon as it is found.
Telnet is not covered: it sends one keystroke per packet and needs stream reassembly.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import parse_qs

from netwatch.analyzers.alerts import SEVERITY_HIGH, Alert
from netwatch.capture.packet import PacketInfo

USER_PASS_PORTS = {21: "FTP", 110: "POP3"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")
BASIC_RE = re.compile(rb"^authorization:\s*basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE | re.MULTILINE)
FORM_USER_KEYS = ("user", "username", "usuario", "login", "email", "uname")
FORM_PASS_KEYS = ("password", "pass", "passwd", "pwd", "contrasena", "contraseña", "clave")


def mask(password: str) -> str:
    """Keep only the first and last character: 'Secreto123' -> 'S********3'."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


@dataclass
class Credential:
    ts: float
    protocol: str
    src_ip: str
    dst_ip: str
    dport: int
    username: str | None
    password_masked: str

    def to_alert(self) -> Alert:
        user = self.username or "(desconocido)"
        return Alert(self.ts, "CLEARTEXT_CREDENTIALS", SEVERITY_HIGH,
                     f"{self.protocol}:{self.src_ip}->{self.dst_ip}:{user}",
                     f"Credenciales {self.protocol} en texto plano: usuario '{user}', "
                     f"contraseña {self.password_masked} ({self.src_ip} → {self.dst_ip}:{self.dport})")


class CredentialDetector:
    def __init__(self):
        self._pending_user: dict[tuple, str] = {}  # FTP/POP3 stream -> USER seen, waiting for PASS

    def process(self, info: PacketInfo) -> list[Credential]:
        if not info.payload or info.dport is None:
            return []
        if info.dport in USER_PASS_PORTS:
            return self._user_pass(info)
        if info.payload.startswith(HTTP_METHODS):
            return self._http(info)
        return []

    def _found(self, info: PacketInfo, protocol: str, user: str | None, password: str) -> Credential:
        return Credential(info.ts, protocol, info.src_ip, info.dst_ip, info.dport, user, mask(password))

    def _user_pass(self, info: PacketInfo) -> list[Credential]:
        stream = (info.src_ip, info.sport, info.dst_ip, info.dport)
        line = info.payload.decode("latin-1").strip()
        command, _, arg = line.partition(" ")
        if command.upper() == "USER":
            self._pending_user[stream] = arg.strip()
        elif command.upper() == "PASS" and arg:
            user = self._pending_user.pop(stream, None)
            return [self._found(info, USER_PASS_PORTS[info.dport], user, arg.strip())]
        return []

    def _http(self, info: PacketInfo) -> list[Credential]:
        head, _, body = info.payload.partition(b"\r\n\r\n")
        found = []
        match = BASIC_RE.search(head)
        if match:
            try:
                decoded = base64.b64decode(match.group(1), validate=True).decode("latin-1")
            except (binascii.Error, ValueError):
                decoded = ""
            if ":" in decoded:
                user, password = decoded.split(":", 1)
                found.append(self._found(info, "HTTP Basic", user, password))
        if head.startswith(b"POST ") and b"application/x-www-form-urlencoded" in head.lower() and body:
            fields = {k.lower(): v[0] for k, v in parse_qs(body.decode("latin-1")).items()}
            password = next((fields[k] for k in FORM_PASS_KEYS if k in fields), None)
            if password:
                user = next((fields[k] for k in FORM_USER_KEYS if k in fields), None)
                found.append(self._found(info, "HTTP POST", user, password))
        return found
