import pytest

from netwatch.analyzers.conversations import conversation_key
from netwatch.analyzers.ip_mac import ip_mac_pair
from netwatch.capture.packet import PacketInfo
from netwatch.db.repository import Repository
from netwatch.pipeline import analyze_file
from tests.conftest import LAB


@pytest.fixture
def repo(tmp_path):
    r = Repository(tmp_path / "test.db")
    yield r
    r.close()


def _info(proto="TCP", src="192.168.56.20", dst="192.168.56.10", mac="02:00:00:00:00:20"):
    return PacketInfo(ts=1.0, length=60, protocol=proto, src_ip=src, dst_ip=dst, src_mac=mac)


# --- conversations (RF4) ---

def test_conversation_key_is_symmetric():
    assert conversation_key(_info(src="192.168.56.20", dst="192.168.56.10")) == \
           conversation_key(_info(src="192.168.56.10", dst="192.168.56.20")) == ("192.168.56.10", "192.168.56.20")


def test_conversation_key_ignores_arp_and_missing_ip():
    assert conversation_key(_info(proto="ARP")) is None
    assert conversation_key(_info(dst=None)) is None


def test_conversations_count_packets_and_bytes(repo):
    sid = repo.create_session("file", "x")
    repo.update_conversation(sid, "a", "b", 100, 5.0)
    repo.update_conversation(sid, "a", "b", 50, 2.0)
    repo.update_conversation(sid, "a", "c", 10, 3.0)
    top = repo.top_conversations(sid)
    assert (top[0]["ip_a"], top[0]["ip_b"], top[0]["packets"], top[0]["bytes"]) == ("a", "b", 2, 150)
    assert (top[0]["first_ts"], top[0]["last_ts"]) == (2.0, 5.0)
    assert len(top) == 2


# --- IP <-> MAC (RF6) ---

def test_ip_mac_from_ip_and_arp():
    assert ip_mac_pair(_info(), LAB) == ("192.168.56.20", "02:00:00:00:00:20")
    assert ip_mac_pair(_info(proto="ARP", mac="02:00:00:00:00:AA"), LAB) == ("192.168.56.20", "02:00:00:00:00:aa")


def test_ip_mac_ignores_external_and_probe_ips():
    assert ip_mac_pair(_info(src="8.8.8.8"), LAB) is None  # would carry the router's MAC
    assert ip_mac_pair(_info(src="0.0.0.0"), LAB) is None  # ARP probe
    assert ip_mac_pair(_info(mac=None), LAB) is None


def test_ip_mac_keeps_several_macs_per_ip(repo):
    sid = repo.create_session("file", "x")
    repo.update_ip_mac(sid, "192.168.56.1", "02:00:00:00:00:01", 1.0)
    repo.update_ip_mac(sid, "192.168.56.1", "02:00:00:00:00:01", 9.0)
    repo.update_ip_mac(sid, "192.168.56.1", "02:00:00:00:00:66", 5.0)
    rows = repo.ip_mac_table(sid)
    assert [(r["mac"], r["first_seen"], r["last_seen"]) for r in rows] == [
        ("02:00:00:00:00:01", 1.0, 9.0), ("02:00:00:00:00:66", 5.0, 5.0)]


# --- connected to the flow ---

def test_normal_pcap_conversations_and_ip_mac(repo, samples):
    sid = analyze_file(samples / "normal.pcap", LAB, repo=repo)["session_id"]
    top = repo.top_conversations(sid)
    assert [(c["ip_a"], c["ip_b"], c["packets"]) for c in top] == [
        ("192.168.56.10", "192.168.56.20", 11), ("192.168.56.1", "192.168.56.20", 2)]
    table = {(r["ip"], r["mac"]) for r in repo.ip_mac_table(sid)}
    assert table == {("192.168.56.1", "02:00:00:00:00:01"), ("192.168.56.10", "02:00:00:00:00:10"),
                     ("192.168.56.20", "02:00:00:00:00:20")}


def test_arp_spoof_pcap_shows_two_macs_for_gateway(repo, samples):
    sid = analyze_file(samples / "arp_spoof.pcap", LAB, repo=repo)["session_id"]
    gw_macs = {r["mac"] for r in repo.ip_mac_table(sid) if r["ip"] == "192.168.56.1"}
    assert gw_macs == {"02:00:00:00:00:01", "02:00:00:00:00:66"}
