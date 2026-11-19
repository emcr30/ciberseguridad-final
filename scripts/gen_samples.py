"""Generate sample .pcap files offline with wrpcap (nothing is sent to the network).

Usage: python scripts/gen_samples.py [output_dir]
"""
from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

GW_IP, GW_MAC = "192.168.56.1", "02:00:00:00:00:01"
SRV_IP, SRV_MAC = "192.168.56.10", "02:00:00:00:00:10"
PC_IP, PC_MAC = "192.168.56.20", "02:00:00:00:00:20"
ATK_IP, ATK_MAC = "192.168.56.66", "02:00:00:00:00:66"
BCAST = "ff:ff:ff:ff:ff:ff"
T0 = 1_700_000_000.0


def _stamp(packets: list, start: float = T0, step: float = 0.5) -> list:
    for i, p in enumerate(packets):
        p.time = start + i * step
    return packets


def _tcp(src_mac, dst_mac, src, dst, sport, dport, flags, payload=b"", seq=1000):
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    return pkt / Raw(payload) if payload else pkt


def normal() -> list:
    pkts = [
        Ether(src=PC_MAC, dst=BCAST) / ARP(op=1, hwsrc=PC_MAC, psrc=PC_IP, pdst=GW_IP),
        Ether(src=GW_MAC, dst=PC_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=PC_MAC, pdst=PC_IP),
        Ether(src=PC_MAC, dst=GW_MAC) / IP(src=PC_IP, dst=GW_IP) / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="lab.local")),
        Ether(src=GW_MAC, dst=PC_MAC) / IP(src=GW_IP, dst=PC_IP) / UDP(sport=53, dport=5353)
        / DNS(qr=1, qd=DNSQR(qname="lab.local"), an=DNSRR(rrname="lab.local", rdata=SRV_IP)),
        Ether(src=PC_MAC, dst=SRV_MAC) / IP(src=PC_IP, dst=SRV_IP) / ICMP(type=8),
        Ether(src=SRV_MAC, dst=PC_MAC) / IP(src=SRV_IP, dst=PC_IP) / ICMP(type=0),
        _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, 40000, 80, "S"),
        _tcp(SRV_MAC, PC_MAC, SRV_IP, PC_IP, 80, 40000, "SA"),
        _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, 40000, 80, "A"),
        _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, 40000, 80, "PA", b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n"),
        _tcp(SRV_MAC, PC_MAC, SRV_IP, PC_IP, 80, 40000, "PA", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, 40001, 443, "S"),
        _tcp(SRV_MAC, PC_MAC, SRV_IP, PC_IP, 443, 40001, "SA"),
        _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, 40001, 443, "PA", b"\x16\x03\x01\x00\x05hello"),
        _tcp(SRV_MAC, PC_MAC, SRV_IP, PC_IP, 443, 40001, "PA", b"\x16\x03\x03\x00\x05hello"),
    ]
    return _stamp(pkts)


def arp_spoof() -> list:
    pkts = [
        Ether(src=GW_MAC, dst=PC_MAC) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=PC_MAC, pdst=PC_IP),
        Ether(src=PC_MAC, dst=GW_MAC) / ARP(op=2, hwsrc=PC_MAC, psrc=PC_IP, hwdst=GW_MAC, pdst=GW_IP),
    ]
    # Attacker claims to be the gateway (to the PC) and the PC (to the gateway).
    for _ in range(3):
        pkts.append(Ether(src=ATK_MAC, dst=PC_MAC) / ARP(op=2, hwsrc=ATK_MAC, psrc=GW_IP, hwdst=PC_MAC, pdst=PC_IP))
        pkts.append(Ether(src=ATK_MAC, dst=GW_MAC) / ARP(op=2, hwsrc=ATK_MAC, psrc=PC_IP, hwdst=GW_MAC, pdst=GW_IP))
    return _stamp(pkts, step=2.0)


def port_scan() -> list:
    open_ports = {22, 80}
    pkts = []
    for port in [*range(20, 40), 80]:
        pkts.append(_tcp(ATK_MAC, SRV_MAC, ATK_IP, SRV_IP, 55555, port, "S"))
        flags = "SA" if port in open_ports else "RA"
        pkts.append(_tcp(SRV_MAC, ATK_MAC, SRV_IP, ATK_IP, port, 55555, flags))
    return _stamp(pkts, step=0.1)


def creds() -> list:
    c = lambda sport, dport, flags, data=b"": _tcp(PC_MAC, SRV_MAC, PC_IP, SRV_IP, sport, dport, flags, data)  # noqa: E731
    s = lambda sport, dport, flags, data=b"": _tcp(SRV_MAC, PC_MAC, SRV_IP, PC_IP, sport, dport, flags, data)  # noqa: E731
    form = b"username=alice&password=Secreto123"
    pkts = [
        # FTP
        c(41000, 21, "S"), s(21, 41000, "SA"), c(41000, 21, "A"),
        s(21, 41000, "PA", b"220 FTP lab\r\n"),
        c(41000, 21, "PA", b"USER alice\r\n"), s(21, 41000, "PA", b"331 Password required\r\n"),
        c(41000, 21, "PA", b"PASS Secreto123\r\n"), s(21, 41000, "PA", b"230 Login OK\r\n"),
        # HTTP Basic (YWxpY2U6U2VjcmV0bzEyMw== -> alice:Secreto123)
        c(41001, 80, "S"), s(80, 41001, "SA"), c(41001, 80, "A"),
        c(41001, 80, "PA", b"GET /admin HTTP/1.1\r\nHost: lab.local\r\n"
                           b"Authorization: Basic YWxpY2U6U2VjcmV0bzEyMw==\r\n\r\n"),
        s(80, 41001, "PA", b"HTTP/1.1 200 OK\r\n\r\n"),
        # HTTP POST form
        c(41002, 80, "S"), s(80, 41002, "SA"), c(41002, 80, "A"),
        c(41002, 80, "PA", b"POST /login HTTP/1.1\r\nHost: lab.local\r\n"
                           b"Content-Type: application/x-www-form-urlencoded\r\n"
                           b"Content-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form),
        s(80, 41002, "PA", b"HTTP/1.1 302 Found\r\n\r\n"),
        # POP3
        c(41003, 110, "S"), s(110, 41003, "SA"), c(41003, 110, "A"),
        s(110, 41003, "PA", b"+OK POP3 ready\r\n"),
        c(41003, 110, "PA", b"USER bob\r\n"), s(110, 41003, "PA", b"+OK\r\n"),
        c(41003, 110, "PA", b"PASS Correo2024\r\n"), s(110, 41003, "PA", b"+OK logged in\r\n"),
    ]
    return _stamp(pkts, step=0.2)


def out_of_scope() -> list:
    a_mac, b_mac = "02:00:00:00:aa:01", "02:00:00:00:aa:02"
    pkts = [
        Ether(src=a_mac, dst=BCAST) / ARP(op=1, hwsrc=a_mac, psrc="10.0.0.5", pdst="10.0.0.1"),
        Ether(src=a_mac, dst=b_mac) / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        _tcp(a_mac, b_mac, "10.0.0.5", "93.184.216.34", 42000, 80, "S"),
        _tcp(a_mac, b_mac, "10.0.0.5", "93.184.216.34", 42001, 443, "S"),
        Ether(src=a_mac, dst=b_mac) / IP(src="10.0.0.5", dst="1.1.1.1") / ICMP(type=8),
    ]
    return _stamp(pkts)


SAMPLES = {
    "normal.pcap": normal,
    "arp_spoof.pcap": arp_spoof,
    "port_scan.pcap": port_scan,
    "creds.pcap": creds,
    "out_of_scope.pcap": out_of_scope,
}


def build_samples(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, builder in SAMPLES.items():
        path = out_dir / name
        wrpcap(str(path), builder())
        paths.append(path)
    return paths


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples"
    for p in build_samples(target):
        print(f"Creado: {p}")
