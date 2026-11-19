"""Lab network scope (RF14): only packets inside declared networks are analyzed."""
from __future__ import annotations

import ipaddress


def validate_cidr(cidr: str) -> str:
    """Return the normalized CIDR or raise ValueError."""
    return str(ipaddress.ip_network(cidr.strip(), strict=False))


def in_scope(ip: str | None, networks: list[str]) -> bool:
    """True if ip belongs to any of the declared networks."""
    if not ip or not networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)
