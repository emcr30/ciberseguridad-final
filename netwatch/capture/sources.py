"""Packet sources: .pcap file (RF2) and live interface (RF1). Both only read."""
from __future__ import annotations

import ctypes
import os
import time
from pathlib import Path
from typing import Callable

from scapy.all import AsyncSniffer, PcapReader, conf

from netwatch.scope import in_scope

PRIVILEGES_HELP = "Se necesitan privilegios (Mac: sudo; Windows: Npcap + terminal de administrador)."


def has_capture_privileges() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def list_interfaces(networks: list[str]) -> list[dict]:
    return [{"name": i.name, "ip": i.ip or None, "mac": i.mac or None, "in_lab": in_scope(i.ip, networks)}
            for i in conf.ifaces.values()]


def file_source(path: Path) -> PcapReader:
    """Open a .pcap file; iterate it to get raw Scapy packets. Raises if the file is not a capture."""
    return PcapReader(str(path))


class LiveSource:
    """Live capture with AsyncSniffer; each packet goes to `callback`."""

    def __init__(self, iface: str, callback: Callable):
        self.iface = iface
        # Scapy prints whatever `prn` returns, so the wrapper always returns None.
        self._sniffer = AsyncSniffer(iface=iface, prn=lambda pkt: callback(pkt) and None, store=False)

    def start(self, timeout: float = 2.0) -> None:
        """Start sniffing. AsyncSniffer fails inside its thread, so wait until it runs or fails."""
        self._sniffer.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            exc = self._sniffer.exception
            if exc is not None:
                raise RuntimeError(f"No se pudo capturar en '{self.iface}': {exc}. {PRIVILEGES_HELP}") from exc
            if getattr(self._sniffer, "continue_sniff", False):
                return
            time.sleep(0.05)

    def stop(self) -> None:
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        except Exception:  # the sniffer thread already died; nothing to stop
            pass
