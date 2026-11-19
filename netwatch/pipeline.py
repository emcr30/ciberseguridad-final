"""Shared flow for live and .pcap: source -> normalize -> lab scope filter -> stats."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from netwatch.capture.packet import PacketInfo, normalize
from netwatch.capture.sources import file_source
from netwatch.scope import in_scope


class Pipeline:
    def __init__(self, networks: list[str]):
        self.networks = networks
        self.total = 0
        self.discarded = 0
        self.protocols: Counter = Counter()

    def handle(self, raw_pkt) -> PacketInfo | None:
        """Process one raw Scapy packet. Returns the PacketInfo if in scope."""
        self.total += 1
        info = normalize(raw_pkt)
        if not (in_scope(info.src_ip, self.networks) or in_scope(info.dst_ip, self.networks)):
            self.discarded += 1
            return None
        self.protocols[info.protocol] += 1
        return info

    def summary(self) -> dict:
        return {
            "total": self.total,
            "discarded": self.discarded,
            "analyzed": self.total - self.discarded,
            "protocols": dict(self.protocols.most_common()),
        }


def analyze_file(path: Path, networks: list[str]) -> dict:
    pipeline = Pipeline(networks)
    for pkt in file_source(path):
        pipeline.handle(pkt)
    return pipeline.summary()
