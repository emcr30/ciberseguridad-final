import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from netwatch.capture.packet import classify, normalize
from netwatch.pipeline import Pipeline, analyze_file
from tests.conftest import LAB


@pytest.mark.parametrize("pkt, expected", [
    (Ether() / ARP(), "ARP"),
    (Ether() / IP() / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="a.b")), "DNS"),
    (Ether() / IP() / TCP(dport=80), "HTTP"),
    (Ether() / IP() / TCP(sport=443, dport=50000), "HTTPS"),
    (Ether() / IP() / TCP(dport=21), "FTP"),
    (Ether() / IP() / ICMP(), "ICMP"),
    (Ether() / IP() / TCP(sport=40000, dport=40001), "TCP"),
    (Ether() / IP() / UDP(sport=40000, dport=40001), "UDP"),
])
def test_classify(pkt, expected):
    assert classify(pkt) == expected


def test_normalize_tcp_fields():
    pkt = Ether(src="02:00:00:00:00:01") / IP(src="192.168.56.1", dst="192.168.56.2") \
        / TCP(sport=1234, dport=80, flags="S") / Raw(b"hola")
    pkt.time = 1000.5
    info = normalize(pkt)
    assert (info.src_ip, info.dst_ip, info.sport, info.dport) == ("192.168.56.1", "192.168.56.2", 1234, 80)
    assert info.ts == 1000.5 and info.tcp_flags == "S" and info.payload == b"hola"
    assert info.src_mac == "02:00:00:00:00:01"


def test_normalize_arp_uses_arp_fields():
    info = normalize(Ether() / ARP(op=2, hwsrc="02:00:00:00:00:66", psrc="192.168.56.1", pdst="192.168.56.20"))
    assert info.src_ip == "192.168.56.1" and info.src_mac == "02:00:00:00:00:66" and info.arp_op == 2


def test_pipeline_discards_out_of_scope():
    p = Pipeline(LAB)
    assert p.handle(Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / ICMP()) is None
    assert p.handle(Ether() / IP(src="192.168.56.5", dst="8.8.8.8") / ICMP()) is not None
    assert p.summary()["discarded"] == 1


def test_analyze_normal(samples):
    s = analyze_file(samples / "normal.pcap", LAB)
    assert s["total"] == 15 and s["discarded"] == 0
    assert s["protocols"]["ARP"] == 2 and s["protocols"]["DNS"] == 2
    assert s["protocols"]["HTTP"] == 5 and s["protocols"]["HTTPS"] == 4


def test_analyze_out_of_scope(samples):
    s = analyze_file(samples / "out_of_scope.pcap", LAB)
    assert s["total"] == s["discarded"] == 5 and s["protocols"] == {}


def test_all_samples_readable(samples):
    for name in ["arp_spoof.pcap", "port_scan.pcap", "creds.pcap"]:
        assert analyze_file(samples / name, LAB)["analyzed"] > 0
