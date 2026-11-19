import pytest

from netwatch.analyzers.port_scan import PortScanDetector
from netwatch.capture.packet import PacketInfo
from netwatch.db.repository import Repository
from netwatch.pipeline import analyze_file
from tests.conftest import LAB

ATK, SRV = "192.168.56.66", "192.168.56.10"


@pytest.fixture
def repo(tmp_path):
    r = Repository(tmp_path / "test.db")
    yield r
    r.close()


def tcp(ts, src, dst, sport, dport, flags):
    return PacketInfo(ts=ts, length=54, protocol="TCP", src_ip=src, dst_ip=dst,
                      sport=sport, dport=dport, tcp_flags=flags)


def syn(ts, port, src=ATK, dst=SRV):
    return tcp(ts, src, dst, 55555, port, "S")


def synack(ts, port):
    return tcp(ts, SRV, ATK, port, 55555, "SA")


def scan(d, ports, step=0.1):
    alerts = []
    for i, port in enumerate(ports):
        alerts += d.process(syn(i * step, port))
    return alerts


def test_14_ports_is_not_a_scan():
    assert scan(PortScanDetector(), range(1, 15)) == []


def test_15_ports_in_10s_is_a_scan():
    alerts = scan(PortScanDetector(), range(1, 16))
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.type, a.severity, a.ts) == ("PORT_SCAN", "alta", pytest.approx(1.4))
    assert ATK in a.detail and SRV in a.detail and "15 puertos" in a.detail


def test_slow_scan_outside_window_is_not_detected():
    assert scan(PortScanDetector(), range(1, 30), step=1.0) == []  # only ~11 ports per 10 s


def test_same_port_repeated_is_not_a_scan():
    assert scan(PortScanDetector(), [80] * 50) == []


def test_ack_and_rst_packets_are_ignored():
    d = PortScanDetector()
    assert all(d.process(tcp(0, ATK, SRV, 55555, p, "A")) == [] for p in range(1, 30))
    assert all(d.process(tcp(0, ATK, SRV, 55555, p, "R")) == [] for p in range(1, 30))


def test_different_destinations_are_counted_apart():
    d = PortScanDetector()
    alerts = []
    for i, port in enumerate(range(1, 21)):
        alerts += d.process(syn(i * 0.1, port, dst=SRV if port % 2 else "192.168.56.11"))
    assert alerts == []  # 10 ports to each destination


def test_open_ports_are_included_and_updated():
    d = PortScanDetector()
    d.process(syn(0.0, 22))
    d.process(synack(0.05, 22))
    alerts = scan(d, range(100, 114))  # 14 more ports -> 15 total
    alert = alerts[-1]
    assert "Puertos abiertos (respondieron SYN/ACK): 22" in alert.detail
    updated = d.process(synack(2.0, 80)) + d.process(syn(2.1, 80))
    assert all(u is alert for u in updated)  # same alert object, not a new one
    assert "22, 80" in alert.detail and "16 puertos" in alert.detail


def test_synack_without_scan_creates_nothing():
    assert PortScanDetector().process(synack(0, 80)) == []


def test_port_scan_pcap(repo, samples):
    s = analyze_file(samples / "port_scan.pcap", LAB, repo=repo)
    alerts = repo.alerts(s["session_id"])
    assert len(alerts) == 1 and alerts[0]["type"] == "PORT_SCAN"
    assert "21 puertos" in alerts[0]["detail"]
    assert "Puertos abiertos (respondieron SYN/ACK): 22, 80" in alerts[0]["detail"]


def test_normal_pcap_has_no_alerts(repo, samples):
    s = analyze_file(samples / "normal.pcap", LAB, repo=repo, gateway="192.168.56.1")
    assert repo.alerts(s["session_id"]) == []
