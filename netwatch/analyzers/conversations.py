"""Conversations between IP pairs (RF4)."""
from __future__ import annotations

from netwatch.capture.packet import PacketInfo


def conversation_key(info: PacketInfo) -> tuple[str, str] | None:
    """Return the IP pair in a fixed order (A<->B == B<->A), or None for non-IP packets."""
    if info.protocol == "ARP" or not info.src_ip or not info.dst_ip:
        return None
    return tuple(sorted((info.src_ip, info.dst_ip)))
