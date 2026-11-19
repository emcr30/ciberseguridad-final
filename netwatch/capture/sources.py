"""Packet sources: .pcap file (RF2) and live interface (RF1). Both only read."""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterator

from scapy.all import AsyncSniffer, PcapReader


def file_source(path: Path) -> Iterator:
    """Yield raw Scapy packets from a .pcap file."""
    with PcapReader(str(path)) as reader:
        yield from reader


class LiveSource:
    """Live capture with AsyncSniffer; each packet goes to `callback`."""

    def __init__(self, iface: str, callback: Callable):
        self.iface = iface
        # Scapy prints whatever `prn` returns, so the wrapper always returns None.
        self._sniffer = AsyncSniffer(iface=iface, prn=lambda pkt: callback(pkt) and None, store=False)

    def start(self) -> None:
        try:
            self._sniffer.start()
        except (PermissionError, OSError) as exc:
            raise RuntimeError(
                f"No se pudo capturar en '{self.iface}': {exc}. "
                "Se necesitan privilegios (Mac: sudo; Windows: Npcap + administrador)."
            ) from exc

    def stop(self) -> None:
        if self._sniffer.running:
            self._sniffer.stop()
