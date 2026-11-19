"""Port scan detection (RF9), using packet timestamps."""
from __future__ import annotations

from dataclasses import dataclass, field

from netwatch.analyzers.alerts import DEDUP_SECONDS, SEVERITY_HIGH, Alert
from netwatch.capture.packet import PacketInfo

WINDOW_SECONDS = 10
PORT_THRESHOLD = 15


@dataclass
class _Pair:
    recent: dict[int, float] = field(default_factory=dict)  # port -> last SYN ts (sliding window)
    scanned: set[int] = field(default_factory=set)          # ports SYN'd since the alert
    open: set[int] = field(default_factory=set)             # ports that answered SYN/ACK
    alert: Alert | None = None


class PortScanDetector:
    def __init__(self, window: float = WINDOW_SECONDS, threshold: int = PORT_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.pairs: dict[tuple[str, str], _Pair] = {}

    def _pair(self, src: str, dst: str) -> _Pair:
        return self.pairs.setdefault((src, dst), _Pair())

    def _detail(self, src: str, dst: str, pair: _Pair) -> str:
        ports = sorted(pair.scanned)
        open_ports = ", ".join(map(str, sorted(pair.open))) or "ninguno"
        return (f"{src} envió SYN a {len(ports)} puertos distintos de {dst} "
                f"(>= {self.threshold} en {self.window:g} s; rango {ports[0]}-{ports[-1]}). "
                f"Puertos abiertos (respondieron SYN/ACK): {open_ports}")

    def process(self, info: PacketInfo) -> list[Alert]:
        """Return a new PORT_SCAN alert, or the active one with its detail updated."""
        flags = info.tcp_flags
        if "S" not in flags or info.dport is None or not info.src_ip or not info.dst_ip:
            return []
        ts = info.ts

        if "A" in flags:  # SYN/ACK: the server answered, so the port is open
            pair = self.pairs.get((info.dst_ip, info.src_ip))
            if pair is None or info.sport in pair.open:
                return []
            pair.open.add(info.sport)
            return self._update(info.dst_ip, info.src_ip, pair, ts)

        pair = self._pair(info.src_ip, info.dst_ip)
        pair.recent[info.dport] = ts
        for port in [p for p, last in pair.recent.items() if ts - last > self.window]:
            del pair.recent[port]

        if pair.alert and ts - pair.alert.ts < DEDUP_SECONDS:
            if info.dport in pair.scanned:
                return []
            pair.scanned.add(info.dport)
            return self._update(info.src_ip, info.dst_ip, pair, ts)

        if len(pair.recent) >= self.threshold:
            pair.scanned = set(pair.recent)
            pair.alert = Alert(ts, "PORT_SCAN", SEVERITY_HIGH, f"{info.src_ip}->{info.dst_ip}",
                               self._detail(info.src_ip, info.dst_ip, pair))
            return [pair.alert]
        return []

    def _update(self, src: str, dst: str, pair: _Pair, ts: float) -> list[Alert]:
        if pair.alert is None or ts - pair.alert.ts >= DEDUP_SECONDS:
            return []
        pair.alert.detail = self._detail(src, dst, pair)
        return [pair.alert]
