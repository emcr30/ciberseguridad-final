"""Shared flow for live and .pcap: source -> normalize -> lab scope filter -> stats."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from typing import Callable

from scapy.all import IPv6

from netwatch.capture.packet import PacketInfo, normalize
from netwatch.capture.sources import file_source
from netwatch.scope import in_scope

DISCARD_IPV6 = "IPv6"
DISCARD_OUT_OF_SCOPE = "IPv4 fuera de las redes de laboratorio"
DISCARD_NO_IP = "sin IP (otros)"


class Pipeline:
    def __init__(self, networks: list[str], on_packet: Callable[[PacketInfo], None] | None = None):
        self.networks = networks
        self.on_packet = on_packet
        self.total = 0
        self.discarded: Counter = Counter()
        self.protocols: Counter = Counter()

    def _discard_reason(self, raw_pkt, info: PacketInfo) -> str | None:
        if raw_pkt.haslayer(IPv6):
            return DISCARD_IPV6
        if info.src_ip is None and info.dst_ip is None:
            return DISCARD_NO_IP
        if not (in_scope(info.src_ip, self.networks) or in_scope(info.dst_ip, self.networks)):
            return DISCARD_OUT_OF_SCOPE
        return None

    def handle(self, raw_pkt) -> PacketInfo | None:
        """Process one raw Scapy packet. Returns the PacketInfo if in scope."""
        self.total += 1
        info = normalize(raw_pkt)
        reason = self._discard_reason(raw_pkt, info)
        if reason:
            self.discarded[reason] += 1
            return None
        self.protocols[info.protocol] += 1
        if self.on_packet:
            self.on_packet(info)
        return info

    def summary(self) -> dict:
        discarded = sum(self.discarded.values())
        return {
            "total": self.total,
            "discarded": discarded,
            "discarded_by_reason": {r: self.discarded[r] for r in (DISCARD_IPV6, DISCARD_OUT_OF_SCOPE, DISCARD_NO_IP)},
            "analyzed": self.total - discarded,
            "protocols": dict(self.protocols.most_common()),
        }


def analyze_file(path: Path, networks: list[str], on_packet: Callable | None = None) -> dict:
    pipeline = Pipeline(networks, on_packet)
    for pkt in file_source(path):
        pipeline.handle(pkt)
    return pipeline.summary()
