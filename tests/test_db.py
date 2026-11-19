import pytest

from netwatch.capture.packet import PacketInfo
from netwatch.db.repository import TABLES, Repository
from netwatch.pipeline import analyze_file
from tests.conftest import LAB


@pytest.fixture
def repo(tmp_path):
    r = Repository(tmp_path / "test.db")
    yield r
    r.close()


def _pkt(ts, proto="HTTP", src="192.168.56.20", dst="192.168.56.10", sport=40000, dport=80):
    return PacketInfo(ts=ts, length=60, protocol=proto, src_ip=src, dst_ip=dst, sport=sport, dport=dport,
                      payload=b"no-se-guarda")


def test_schema_creates_all_tables(repo):
    assert set(repo.table_counts()) == set(TABLES)


def test_session_lifecycle(repo):
    sid = repo.create_session("file", "x.pcap")
    repo.finish_session(sid, total=10, discarded=3)
    row = repo.conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    assert (row["source"], row["name"], row["total"], row["discarded"]) == ("file", "x.pcap", 10, 3)
    assert row["ended_at"] is not None


def test_packet_row_limit(tmp_path):
    r = Repository(tmp_path / "limit.db", max_packets=50)
    sid = r.create_session("file", "x.pcap")
    for i in range(500):
        r.add_packet(sid, _pkt(i))
    r.flush()
    rows = r.filter_packets(limit=1000)
    assert len(rows) == 50
    assert min(p["ts"] for p in rows) == 450  # only the newest are kept
    r.close()


def test_payload_is_not_stored(repo):
    sid = repo.create_session("file", "x.pcap")
    repo.add_packet(sid, _pkt(1))
    repo.flush()
    assert "payload" not in repo.filter_packets()[0]


def test_filter_packets(repo):
    sid = repo.create_session("file", "x.pcap")
    repo.add_packet(sid, _pkt(1, "HTTP", dport=80))
    repo.add_packet(sid, _pkt(2, "DNS", src="192.168.56.30", dst="192.168.56.1", sport=5353, dport=53))
    repo.add_packet(sid, _pkt(3, "HTTPS", dport=443))
    repo.flush()
    assert len(repo.filter_packets(session_id=sid)) == 3
    assert [p["ts"] for p in repo.filter_packets(ip="192.168.56.30")] == [2]
    assert [p["ts"] for p in repo.filter_packets(protocol="https")] == [3]
    assert [p["ts"] for p in repo.filter_packets(port=53)] == [2]
    assert [p["ts"] for p in repo.filter_packets(ip="192.168.56.20", port=80)] == [1]
    assert repo.filter_packets(session_id=sid + 1) == []


def test_filter_is_parameterized(repo):
    sid = repo.create_session("file", "x.pcap")
    repo.add_packet(sid, _pkt(1))
    repo.flush()
    assert repo.filter_packets(ip="' OR 1=1 --") == []
    assert repo.filter_packets(protocol="HTTP' OR '1'='1") == []
    assert repo.table_counts()["packets"] == 1


def test_analyze_saves_to_db(repo, samples):
    s = analyze_file(samples / "normal.pcap", LAB, repo=repo)
    counts = repo.table_counts()
    assert counts["sessions"] == 1 and counts["packets"] == s["analyzed"] == 15
    s2 = analyze_file(samples / "out_of_scope.pcap", LAB, repo=repo)
    assert repo.table_counts()["packets"] == 15  # discarded packets are not stored
    assert s2["session_id"] == s["session_id"] + 1
