import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw

from netwatch.capture.packet import classify, normalize
from netwatch.__main__ import VERBOSE_LIMIT, _packet_printer
from netwatch.capture.sources import LiveSource
from netwatch.pipeline import (DISCARD_IPV6, DISCARD_NO_IP, DISCARD_OUT_OF_SCOPE,
                               Pipeline, analyze_file)
from tests.conftest import LAB


def E(**kw):
    """Ether with explicit MACs: without dst, Scapy would resolve it by sending ARP/NDP."""
    kw.setdefault("src", "02:00:00:00:00:01")
    kw.setdefault("dst", "02:00:00:00:00:02")
    return Ether(**kw)


@pytest.mark.parametrize("pkt, expected", [
    (E() / ARP(), "ARP"),
    (E() / IP() / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="a.b")), "DNS"),
    (E() / IP() / TCP(dport=80), "HTTP"),
    (E() / IP() / TCP(sport=443, dport=50000), "HTTPS"),
    (E() / IP() / TCP(dport=21), "FTP"),
    (E() / IP() / ICMP(), "ICMP"),
    (E() / IP() / TCP(sport=40000, dport=40001), "TCP"),
    (E() / IP() / UDP(sport=40000, dport=40001), "UDP"),
])
def test_classify(pkt, expected):
    assert classify(pkt) == expected


def test_normalize_tcp_fields():
    pkt = E(src="02:00:00:00:00:01") / IP(src="192.168.56.1", dst="192.168.56.2") \
        / TCP(sport=1234, dport=80, flags="S") / Raw(b"hola")
    pkt.time = 1000.5
    info = normalize(pkt)
    assert (info.src_ip, info.dst_ip, info.sport, info.dport) == ("192.168.56.1", "192.168.56.2", 1234, 80)
    assert info.ts == 1000.5 and info.tcp_flags == "S" and info.payload == b"hola"
    assert info.src_mac == "02:00:00:00:00:01"


def test_normalize_arp_uses_arp_fields():
    info = normalize(E() / ARP(op=2, hwsrc="02:00:00:00:00:66", psrc="192.168.56.1", pdst="192.168.56.20"))
    assert info.src_ip == "192.168.56.1" and info.src_mac == "02:00:00:00:00:66" and info.arp_op == 2


def test_pipeline_discards_out_of_scope():
    p = Pipeline(LAB)
    assert p.handle(E() / IP(src="10.0.0.1", dst="8.8.8.8") / ICMP()) is None
    assert p.handle(E() / IP(src="192.168.56.5", dst="8.8.8.8") / ICMP()) is not None
    assert p.summary()["discarded"] == 1


def test_discard_reasons():
    p = Pipeline(LAB)
    p.handle(E() / IPv6(src="fe80::1", dst="fe80::2") / UDP())
    p.handle(E() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    p.handle(E(type=0x88CC) / Raw(b"lldp"))
    p.handle(E() / IP(src="192.168.56.5", dst="192.168.56.6") / ICMP())
    s = p.summary()
    assert s["discarded_by_reason"] == {DISCARD_IPV6: 1, DISCARD_OUT_OF_SCOPE: 1, DISCARD_NO_IP: 1}
    assert s["discarded"] == 3 and s["analyzed"] == 1


def test_verbose_prints_at_most_limit(capsys):
    show = _packet_printer(True)
    pkt = normalize(E() / IP(src="192.168.56.5", dst="192.168.56.6") / TCP(sport=1, dport=80) / Raw(b"secreto"))
    for _ in range(VERBOSE_LIMIT + 5):
        show(pkt)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == VERBOSE_LIMIT
    assert "192.168.56.5:1 → 192.168.56.6:80" in lines[0] and "secreto" not in lines[0]


def test_verbose_disabled():
    assert _packet_printer(False) is None


def test_live_callback_returns_none():
    """Scapy prints whatever prn returns; the wrapper must return None."""
    src = LiveSource("lo0", lambda pkt: "algo")
    assert src._sniffer.kwargs["prn"](E()) is None


def test_analyze_normal(samples):
    s = analyze_file(samples / "normal.pcap", LAB)
    assert s["total"] == 15 and s["discarded"] == 0
    assert s["protocols"]["ARP"] == 2 and s["protocols"]["DNS"] == 2
    assert s["protocols"]["HTTP"] == 5 and s["protocols"]["HTTPS"] == 4


def test_analyze_out_of_scope(samples):
    s = analyze_file(samples / "out_of_scope.pcap", LAB)
    assert s["total"] == s["discarded"] == 5 and s["protocols"] == {}
    assert s["discarded_by_reason"][DISCARD_OUT_OF_SCOPE] == 5


def test_all_samples_readable(samples):
    for name in ["arp_spoof.pcap", "port_scan.pcap", "creds.pcap"]:
        assert analyze_file(samples / name, LAB)["analyzed"] > 0
