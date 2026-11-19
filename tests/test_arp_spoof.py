import pytest

from netwatch.analyzers.alerts import Alert, Deduplicator
from netwatch.analyzers.arp_spoof import ArpSpoofDetector
from netwatch.analyzers.conversations import conversation_key
from netwatch.capture.packet import PacketInfo
from netwatch.db.repository import Repository
from netwatch.pipeline import analyze_file
from tests.conftest import LAB

GW = "192.168.56.1"
GW_MAC, PC_MAC, ATK_MAC = "02:00:00:00:00:01", "02:00:00:00:00:20", "02:00:00:00:00:66"


@pytest.fixture
def repo(tmp_path):
    r = Repository(tmp_path / "test.db")
    yield r
    r.close()


def arp(ts, ip, mac, proto="ARP"):
    return PacketInfo(ts=ts, length=42, protocol=proto, src_ip=ip, dst_ip="192.168.56.20", src_mac=mac, arp_op=2)


def types(alerts):
    return sorted(a.type for a in alerts)


# --- ARP_SPOOFING (RF7) ---

def test_same_ip_two_macs_within_window():
    d = ArpSpoofDetector()
    assert d.process(arp(0, "192.168.56.10", PC_MAC)) == []
    alerts = d.process(arp(10, "192.168.56.10", ATK_MAC))
    assert types(alerts) == ["ARP_SPOOFING"]
    assert alerts[0].severity == "alta" and ATK_MAC in alerts[0].detail and alerts[0].ts == 10


def test_two_macs_outside_window_is_not_spoofing():
    d = ArpSpoofDetector()
    d.process(arp(0, "192.168.56.10", PC_MAC))
    assert d.process(arp(31, "192.168.56.10", ATK_MAC)) == []  # e.g. NIC replaced


def test_same_mac_repeated_is_not_spoofing():
    d = ArpSpoofDetector(gateway=GW)
    assert all(d.process(arp(t, GW, GW_MAC)) == [] for t in range(0, 20, 2))


def test_non_arp_packets_are_ignored():
    d = ArpSpoofDetector()
    d.process(arp(0, "192.168.56.10", PC_MAC, proto="TCP"))
    assert d.process(arp(1, "192.168.56.10", ATK_MAC, proto="TCP")) == []


# --- MITM (RF8) ---

def test_gateway_conflict_is_critical_mitm():
    d = ArpSpoofDetector(gateway=GW)
    d.process(arp(0, GW, GW_MAC))
    alerts = d.process(arp(2, GW, ATK_MAC))
    assert types(alerts) == ["ARP_SPOOFING", "MITM"]
    mitm = next(a for a in alerts if a.type == "MITM")
    assert mitm.severity == "crítica" and "gateway" in mitm.detail


def test_mac_claiming_several_ips_is_mitm():
    d = ArpSpoofDetector()
    d.process(arp(0, "192.168.56.10", ATK_MAC))
    alerts = d.process(arp(1, "192.168.56.11", ATK_MAC))
    assert types(alerts) == ["MITM"] and alerts[0].severity == "crítica"
    assert "192.168.56.10" in alerts[0].detail and "192.168.56.11" in alerts[0].detail


# --- de-duplication (RF12) ---

def test_dedup_60_seconds_by_packet_time():
    dd = Deduplicator()
    a = lambda ts, subject="x": Alert(ts, "ARP_SPOOFING", "alta", subject, "d")  # noqa: E731
    assert dd.allow(a(0))
    assert not dd.allow(a(59))
    assert dd.allow(a(0.5, subject="y"))  # other subject
    assert dd.allow(a(60))


# --- whole flow with the sample files ---

def test_arp_spoof_pcap_alerts(repo, samples):
    s = analyze_file(samples / "arp_spoof.pcap", LAB, repo=repo, gateway=GW)
    alerts = repo.alerts(s["session_id"])
    assert sorted((a["type"], a["severity"]) for a in alerts) == [
        ("ARP_SPOOFING", "alta"), ("ARP_SPOOFING", "alta"), ("MITM", "crítica"), ("MITM", "crítica")]
    assert all(a["ts"] >= 1_700_000_000 and a["detail"] for a in alerts)  # packet time + detail


def test_arp_spoof_pcap_without_gateway_still_mitm(repo, samples):
    s = analyze_file(samples / "arp_spoof.pcap", LAB, repo=repo)
    assert [a["type"] for a in repo.alerts(s["session_id"])].count("MITM") == 1  # MAC claims 2 IPs


def test_normal_pcap_has_no_alerts(repo, samples):
    s = analyze_file(samples / "normal.pcap", LAB, repo=repo, gateway=GW)
    assert s["alerts"] == 0 and repo.alerts(s["session_id"]) == []


# --- extra: numeric ordering in conversations ---

def test_conversation_key_numeric_order():
    info = PacketInfo(ts=0, length=1, protocol="TCP", src_ip="192.168.56.10", dst_ip="192.168.56.9")
    assert conversation_key(info) == ("192.168.56.9", "192.168.56.10")  # text order would put .10 first
