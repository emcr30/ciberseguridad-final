"""Shared flow for live and .pcap: source -> normalize -> lab scope filter -> SQLite."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from scapy.all import IPv6

from netwatch.capture.packet import PacketInfo, normalize
from netwatch.analyzers.conversations import conversation_key
from netwatch.analyzers.ip_mac import ip_mac_pair
from netwatch.capture.sources import file_source
from netwatch.db.repository import Repository
from netwatch.scope import in_scope

DISCARD_IPV6 = "IPv6"
DISCARD_OUT_OF_SCOPE = "IPv4 fuera de las redes de laboratorio"
DISCARD_NO_IP = "sin IP (otros)"


class Pipeline:
    def __init__(self, networks: list[str], on_packet: Callable[[PacketInfo], None] | None = None,
                 repo: Repository | None = None, session_id: int | None = None):
        self.networks = networks
        self.on_packet = on_packet
        self.repo = repo
        self.session_id = session_id
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
        if self.repo:
            self._store(info)
        if self.on_packet:
            self.on_packet(info)
        return info

    def _store(self, info: PacketInfo) -> None:
        self.repo.add_packet(self.session_id, info)
        conv = conversation_key(info)
        if conv:
            self.repo.update_conversation(self.session_id, *conv, info.length, info.ts)
        pair = ip_mac_pair(info, self.networks)
        if pair:
            self.repo.update_ip_mac(self.session_id, *pair, info.ts)

    def summary(self) -> dict:
        discarded = sum(self.discarded.values())
        return {
            "total": self.total,
            "discarded": discarded,
            "discarded_by_reason": {r: self.discarded[r] for r in (DISCARD_IPV6, DISCARD_OUT_OF_SCOPE, DISCARD_NO_IP)},
            "analyzed": self.total - discarded,
            "protocols": dict(self.protocols.most_common()),
            "session_id": self.session_id,
        }

    def finish(self) -> dict:
        summary = self.summary()
        if self.repo:
            self.repo.finish_session(self.session_id, summary["total"], summary["discarded"])
        return summary


def analyze_file(path: Path, networks: list[str], on_packet: Callable | None = None,
                 repo: Repository | None = None) -> dict:
    session_id = repo.create_session("file", path.name) if repo else None
    pipeline = Pipeline(networks, on_packet, repo, session_id)
    for pkt in file_source(path):
        pipeline.handle(pkt)
    return pipeline.finish()
