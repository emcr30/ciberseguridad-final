"""Shared flow for live and .pcap: source -> normalize -> lab scope filter -> SQLite."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from scapy.all import IP, TCP, UDP, IPv6, PcapWriter, Raw

from netwatch.analyzers.alerts import Alert, Deduplicator
from netwatch.analyzers.arp_spoof import ArpSpoofDetector
from netwatch.analyzers.conversations import conversation_key
from netwatch.analyzers.credentials import CredentialDetector
from netwatch.analyzers.ip_mac import ip_mac_pair
from netwatch.analyzers.port_scan import PortScanDetector
from netwatch.capture.packet import PacketInfo, normalize
from netwatch.capture.sources import file_source
from netwatch.db.repository import Repository
from netwatch.scope import in_scope

DISCARD_IPV6 = "IPv6"
DISCARD_OUT_OF_SCOPE = "IPv4 fuera de las redes de laboratorio"
DISCARD_NO_IP = "sin IP (otros)"
REDACTED = b"[NetWatch: contenido eliminado porque tenia credenciales]"


def redact(raw_pkt):
    """Copy of the packet without its payload, so the session .pcap never keeps a real password."""
    pkt = raw_pkt.copy()
    pkt[Raw].load = REDACTED
    for layer, fields in ((IP, ("len", "chksum")), (TCP, ("chksum",)), (UDP, ("len", "chksum"))):
        if pkt.haslayer(layer):
            for name in fields:
                setattr(pkt[layer], name, None)  # recomputed when written
    return pkt


class Pipeline:
    def __init__(self, networks: list[str], on_packet: Callable[[PacketInfo], None] | None = None,
                 repo: Repository | None = None, session_id: int | None = None, gateway: str | None = None,
                 pcap_path: Path | None = None):
        self.networks = networks
        self.pcap_path = pcap_path
        self._pcap = None
        if pcap_path:
            pcap_path.parent.mkdir(parents=True, exist_ok=True)
            self._pcap = PcapWriter(str(pcap_path), sync=True)
        self.detectors = [ArpSpoofDetector(gateway), PortScanDetector()]
        self.cred_detector = CredentialDetector()
        self.credentials = 0
        self.dedup = Deduplicator()
        self.alerts: list[Alert] = []
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
        for detector in self.detectors:
            for alert in detector.process(info):
                self._raise(alert)
        creds = self.cred_detector.process(info)
        for cred in creds:
            self.credentials += 1
            if self.repo:
                self.repo.add_credential(self.session_id, cred)
            self._raise(cred.to_alert())
        if self._pcap:
            self._pcap.write(redact(raw_pkt) if creds and raw_pkt.haslayer(Raw) else raw_pkt)
        if self.repo:
            self._store(info)
        if self.on_packet:
            self.on_packet(info)
        return info

    def _raise(self, alert: Alert) -> None:
        if alert.id is not None:  # already raised: only its detail changed
            if self.repo:
                self.repo.update_alert_detail(alert.id, alert.detail)
            return
        if not self.dedup.allow(alert):
            return
        self.alerts.append(alert)
        if self.repo:
            alert.id = self.repo.add_alert(self.session_id, alert.ts, alert.type, alert.severity, alert.detail)
        else:
            alert.id = len(self.alerts)

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
            "alerts": len(self.alerts),
            "credentials": self.credentials,
            "session_id": self.session_id,
        }

    def finish(self) -> dict:
        summary = self.summary()
        if self._pcap:
            self._pcap.close()
            self._pcap = None
        if self.repo:
            self.repo.finish_session(self.session_id, summary["total"], summary["discarded"])
        return summary


def session_pcap(sessions_dir: Path, session_id: int) -> Path:
    return sessions_dir / f"session_{session_id}.pcap"


def analyze_file(path: Path, networks: list[str], on_packet: Callable | None = None,
                 repo: Repository | None = None, gateway: str | None = None,
                 sessions_dir: Path | None = None, name: str | None = None) -> dict:
    """Analyze a .pcap. Raises (before creating a session) if the file is not a valid capture."""
    with file_source(path) as reader:
        session_id = repo.create_session("file", name or path.name) if repo else None
        pcap_path = session_pcap(sessions_dir, session_id) if sessions_dir and repo else None
        pipeline = Pipeline(networks, on_packet, repo, session_id, gateway, pcap_path)
        try:
            for pkt in reader:
                pipeline.handle(pkt)
        finally:  # a file damaged half-way still closes its session
            summary = pipeline.finish()
    return summary
