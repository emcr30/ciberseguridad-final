"""IP <-> MAC table (RF6), learned from ARP and IP packets."""
from __future__ import annotations

from netwatch.capture.packet import PacketInfo
from netwatch.scope import in_scope


def ip_mac_pair(info: PacketInfo, networks: list[str]) -> tuple[str, str] | None:
    """Return (ip, mac) for the sender of the packet, or None.

    Only IPs inside the lab networks are learned: a packet from an external IP
    carries the router's MAC, which would be a false mapping.
    """
    if not info.src_ip or not info.src_mac or info.src_ip == "0.0.0.0":
        return None
    if not in_scope(info.src_ip, networks):
        return None
    return info.src_ip, info.src_mac.lower()
