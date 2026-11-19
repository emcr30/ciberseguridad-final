import base64

import pytest

from netwatch.analyzers.credentials import CredentialDetector, mask
from netwatch.capture.packet import PacketInfo
from netwatch.db.repository import Repository
from netwatch.pipeline import analyze_file
from tests.conftest import LAB

PC, SRV = "192.168.56.20", "192.168.56.10"
REAL_PASSWORDS = ["Secreto123", "Correo2024"]  # the passwords inside creds.pcap


@pytest.fixture
def repo(tmp_path):
    r = Repository(tmp_path / "test.db")
    yield r
    r.close()


def pkt(payload: bytes, dport=80, sport=40000, ts=1.0):
    return PacketInfo(ts=ts, length=60 + len(payload), protocol="TCP", src_ip=PC, dst_ip=SRV,
                      sport=sport, dport=dport, tcp_flags="PA", payload=payload)


def test_mask():
    assert mask("Secreto123") == "S********3"
    assert mask("ab") == "**" and mask("") == ""


def test_ftp_user_pass():
    d = CredentialDetector()
    assert d.process(pkt(b"USER alice\r\n", dport=21)) == []
    [c] = d.process(pkt(b"PASS Secreto123\r\n", dport=21))
    assert (c.protocol, c.username, c.password_masked) == ("FTP", "alice", "S********3")


def test_pop3_user_pass():
    d = CredentialDetector()
    d.process(pkt(b"USER bob\r\n", dport=110))
    [c] = d.process(pkt(b"PASS Correo2024\r\n", dport=110))
    assert (c.protocol, c.username, c.password_masked) == ("POP3", "bob", "C********4")


def test_pass_from_other_stream_has_no_user():
    d = CredentialDetector()
    d.process(pkt(b"USER alice\r\n", dport=21, sport=1111))
    [c] = d.process(pkt(b"PASS x123\r\n", dport=21, sport=2222))
    assert c.username is None


def test_http_basic():
    token = base64.b64encode(b"alice:Secreto123")
    [c] = CredentialDetector().process(pkt(b"GET / HTTP/1.1\r\nAuthorization: Basic " + token + b"\r\n\r\n"))
    assert (c.protocol, c.username, c.password_masked) == ("HTTP Basic", "alice", "S********3")


def test_http_basic_invalid_base64_is_ignored():
    assert CredentialDetector().process(pkt(b"GET / HTTP/1.1\r\nAuthorization: Basic !!!\r\n\r\n")) == []


def test_http_post_form():
    body = b"usuario=carla&clave=Hola1234&recordar=1"
    payload = (b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body)
    [c] = CredentialDetector().process(pkt(payload))
    assert (c.protocol, c.username, c.password_masked) == ("HTTP POST", "carla", "H******4")


def test_http_post_without_password_or_not_form():
    d = CredentialDetector()
    assert d.process(pkt(b"POST /s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=hola")) == []
    assert d.process(pkt(b'POST /s HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"password":"x"}')) == []
    assert d.process(pkt(b"HTTP/1.1 200 OK\r\n\r\npassword=x", sport=80, dport=40000)) == []


def test_alert_has_no_real_password():
    d = CredentialDetector()
    d.process(pkt(b"USER alice\r\n", dport=21))
    [c] = d.process(pkt(b"PASS Secreto123\r\n", dport=21))
    alert = c.to_alert()
    assert alert.type == "CLEARTEXT_CREDENTIALS" and "alice" in alert.detail
    assert "Secreto123" not in alert.detail and "S********3" in alert.detail


def test_creds_pcap_detects_all(repo, samples):
    s = analyze_file(samples / "creds.pcap", LAB, repo=repo)
    creds = repo.credentials(s["session_id"])
    assert [(c["protocol"], c["username"], c["password_masked"]) for c in creds] == [
        ("FTP", "alice", "S********3"),
        ("HTTP Basic", "alice", "S********3"),
        ("HTTP POST", "alice", "S********3"),
        ("POP3", "bob", "C********4"),
    ]
    alerts = repo.alerts(s["session_id"])
    assert len(alerts) == 4 and {a["type"] for a in alerts} == {"CLEARTEXT_CREDENTIALS"}


def test_real_password_never_in_database(tmp_path, samples):
    """Scan every text cell of every table, and the raw .db file bytes."""
    db = tmp_path / "check.db"
    r = Repository(db)
    analyze_file(samples / "creds.pcap", LAB, repo=r)
    tables = [row[0] for row in r.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    cells = [str(v) for t in tables for row in r.conn.execute(f"SELECT * FROM {t}") for v in tuple(row)]
    r.close()
    assert len(cells) > 0
    raw = db.read_bytes()
    for password in REAL_PASSWORDS:
        assert not any(password in cell for cell in cells)
        assert password.encode() not in raw
    assert base64.b64encode(b"alice:Secreto123") not in raw  # nor the Basic token
