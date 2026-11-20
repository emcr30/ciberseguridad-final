"""ARP spoofing (RF7) and possible MITM (RF8) detection, using packet timestamps."""
from __future__ import annotations

from collections import defaultdict

from netwatch.analyzers.alerts import SEVERITY_CRITICAL, SEVERITY_HIGH, Alert
from netwatch.capture.packet import PacketInfo

WINDOW_SECONDS = 30


class ArpSpoofDetector:
    def __init__(self, gateway: str | None = None, window: float = WINDOW_SECONDS):
        self.gateway = gateway
        self.window = window
        self.ip_macs: dict[str, dict[str, float]] = defaultdict(dict)  # ip -> {mac: last seen}
        self.mac_ips: dict[str, dict[str, float]] = defaultdict(dict)  # mac -> {ip: last seen}

    def _recent(self, seen: dict[str, float], ts: float) -> list[str]:
        for key in [k for k, last in seen.items() if ts - last > self.window]:
            del seen[key]
        return sorted(seen)

    def process(self, info: PacketInfo) -> list[Alert]:
        """Only ARP packets are used: the sender IP/MAC pair is what ARP poisoning forges."""
        if info.protocol != "ARP" or not info.src_ip or not info.src_mac or info.src_ip == "0.0.0.0":
            return []
        ip, mac, ts = info.src_ip, info.src_mac.lower(), info.ts
        self.ip_macs[ip][mac] = ts
        self.mac_ips[mac][ip] = ts
        macs = self._recent(self.ip_macs[ip], ts)
        ips = self._recent(self.mac_ips[mac], ts)

        alerts = []
        if len(macs) >= 2:
            alerts.append(Alert(ts, "ARP_SPOOFING", SEVERITY_HIGH, ip,
                                f"La IP {ip} aparece con {len(macs)} MAC distintas en "
                                f"{self.window:g} s: {', '.join(macs)}", src_ip=ip))
            if ip == self.gateway:
                alerts.append(Alert(ts, "MITM", SEVERITY_CRITICAL, f"gateway:{ip}",
                                    f"Posible MITM: conflicto ARP sobre el gateway {ip} "
                                    f"(MAC: {', '.join(macs)}). Última MAC: {mac}", src_ip=ip))
        if len(ips) >= 2:
            alerts.append(Alert(ts, "MITM", SEVERITY_CRITICAL, f"mac:{mac}",
                                f"Posible MITM: la MAC {mac} reclama {len(ips)} IPs en "
                                f"{self.window:g} s: {', '.join(ips)}", src_ip=ip))
        return alerts
