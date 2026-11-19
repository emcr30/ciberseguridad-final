"""Normalize Scapy packets into a simple dataclass and classify the protocol (RF3)."""
from __future__ import annotations

from dataclasses import dataclass

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw

PORT_PROTOCOLS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 8080: "HTTP",
}


@dataclass
class PacketInfo:
    ts: float
    length: int
    protocol: str
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str = ""
    arp_op: int | None = None
    payload: bytes = b""


def classify(pkt) -> str:
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if l4 is not None:
        for port in (l4.dport, l4.sport):
            if port in PORT_PROTOCOLS:
                return PORT_PROTOCOLS[port]
        return "TCP" if pkt.haslayer(TCP) else "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP):
        return "IP"
    return "OTHER"


def normalize(pkt) -> PacketInfo:
    info = PacketInfo(ts=float(pkt.time), length=len(pkt), protocol=classify(pkt))
    if pkt.haslayer(Ether):
        info.src_mac, info.dst_mac = pkt[Ether].src, pkt[Ether].dst
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info.src_ip, info.dst_ip, info.arp_op = arp.psrc, arp.pdst, int(arp.op)
        info.src_mac = arp.hwsrc
    elif pkt.haslayer(IP):
        info.src_ip, info.dst_ip = pkt[IP].src, pkt[IP].dst
    l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if l4 is not None:
        info.sport, info.dport = int(l4.sport), int(l4.dport)
    if pkt.haslayer(TCP):
        info.tcp_flags = str(pkt[TCP].flags)
    if pkt.haslayer(Raw):
        info.payload = bytes(pkt[Raw].load)
    return info
