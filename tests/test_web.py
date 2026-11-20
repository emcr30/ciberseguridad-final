import csv
import io
import json

import pytest
from scapy.all import PcapReader

from netwatch.capture import sources
from netwatch.web.app import create_app

LAB = "192.168.56.0/24"
FAKE_IFACES = [{"name": "lab0", "ip": "192.168.56.5", "mac": "02:00:00:00:00:05", "in_lab": True}]


@pytest.fixture
def app(tmp_path):
    app = create_app(tmp_path)
    app.config["TESTING"] = True
    yield app
    app.extensions["netwatch"]["repo"].close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def ready(client):
    """Lab network declared and warning accepted."""
    client.post("/api/settings", json={"networks": [LAB], "gateway": "192.168.56.1", "warning_accepted": True})
    return client


def upload(client, path, name=None):
    with open(path, "rb") as f:
        return client.post("/api/upload", data={"file": (f, name or path.name)},
                           content_type="multipart/form-data")


# --- status / settings ---

def test_status_shows_warning(client):
    data = client.get("/api/status").get_json()
    assert "ADVERTENCIA" in data["warning"] and data["warning_accepted"] is False
    assert data["capture"]["running"] is False and data["latest_session_id"] is None


def test_settings_roundtrip_and_validation(client):
    r = client.post("/api/settings", json={"networks": ["192.168.56.10/24"], "warning_accepted": True})
    assert r.status_code == 200 and r.get_json()["networks"] == ["192.168.56.0/24"]
    assert client.get("/api/settings").get_json()["warning_accepted"] is True
    assert client.post("/api/settings", json={"networks": ["no-es-red"]}).status_code == 400
    assert client.post("/api/settings", json={"gateway": "999.1.1.1"}).status_code == 400
    assert client.post("/api/settings", data="networks=x").status_code == 400  # JSON only


def test_interfaces(client, monkeypatch):
    monkeypatch.setattr(sources, "list_interfaces", lambda nets: FAKE_IFACES)
    assert client.get("/api/interfaces").get_json() == FAKE_IFACES


# --- capture rules ---

def test_capture_rejected_without_warning(client):
    client.post("/api/settings", json={"networks": [LAB]})
    r = client.post("/api/capture/start", json={"iface": "lab0"})
    assert r.status_code == 403 and "advertencia" in r.get_json()["error"]


def test_capture_rejected_without_networks(client):
    client.post("/api/settings", json={"warning_accepted": True})
    r = client.post("/api/capture/start", json={"iface": "lab0"})
    assert r.status_code == 400 and "red de laboratorio" in r.get_json()["error"]


def test_capture_rejected_unknown_iface(ready, monkeypatch):
    monkeypatch.setattr(sources, "list_interfaces", lambda nets: FAKE_IFACES)
    assert ready.post("/api/capture/start", json={"iface": "nope"}).status_code == 400


def test_capture_rejected_without_privileges(ready, monkeypatch):
    monkeypatch.setattr(sources, "list_interfaces", lambda nets: FAKE_IFACES)
    monkeypatch.setattr(sources, "has_capture_privileges", lambda: False)
    r = ready.post("/api/capture/start", json={"iface": "lab0"})
    assert r.status_code == 403 and "privilegios" in r.get_json()["error"]


def test_capture_start_stop_with_fake_source(ready, monkeypatch, samples):
    """Live flow without the network: a fake source feeds normal.pcap packets to the pipeline."""
    class FakeSource:
        def __init__(self, iface, callback):
            self.callback = callback

        def start(self):
            for pkt in PcapReader(str(samples / "normal.pcap")):
                self.callback(pkt)

        def stop(self):
            pass

    monkeypatch.setattr(sources, "list_interfaces", lambda nets: FAKE_IFACES)
    monkeypatch.setattr(sources, "has_capture_privileges", lambda: True)
    monkeypatch.setattr(sources, "LiveSource", FakeSource)
    r = ready.post("/api/capture/start", json={"iface": "lab0"})
    assert r.status_code == 200
    sid = r.get_json()["session_id"]
    assert ready.post("/api/capture/start", json={"iface": "lab0"}).status_code == 409
    stats = ready.get("/api/stats").get_json()
    assert stats["live"]["analyzed"] == 15
    stop = ready.post("/api/capture/stop").get_json()
    assert stop["running"] is False and stop["summary"]["total"] == 15
    assert ready.get(f"/api/stats?session={sid}").get_json()["session"]["source"] == "live"
    assert ready.post("/api/capture/stop").status_code == 409


def test_live_source_reports_thread_error():
    """AsyncSniffer fails inside its thread; LiveSource.start must raise it."""
    src = sources.LiveSource("lo0", lambda p: None)

    class DeadSniffer:
        exception = PermissionError("Permission denied: /dev/bpf0")
        running = False

        def start(self):
            pass

    src._sniffer = DeadSniffer()
    with pytest.raises(RuntimeError, match="privilegios"):
        src.start(timeout=0.2)


# --- upload ---

def test_upload_requires_networks(client, samples):
    assert upload(client, samples / "normal.pcap").status_code == 400


def test_upload_rejects_bad_files(ready, tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"esto no es un pcap")
    assert upload(ready, bad).status_code == 400
    txt = tmp_path / "x.txt"
    txt.write_bytes(b"hola")
    assert upload(ready, txt).status_code == 400
    assert ready.post("/api/upload").status_code == 400


def test_upload_and_data_endpoints(ready, samples, tmp_path):
    r = upload(ready, samples / "normal.pcap")
    assert r.status_code == 200 and r.get_json()["analyzed"] == 15
    assert not any((tmp_path / "uploads").iterdir())  # uploaded original is deleted
    stats = ready.get("/api/stats").get_json()
    assert stats["protocols"]["HTTP"] == 5 and sum(p["packets"] for p in stats["packets_per_second"]) == 15
    assert ready.get("/api/conversations").get_json()[0]["packets"] == 11
    assert len(ready.get("/api/ip-mac").get_json()) == 3
    assert ready.get("/api/alerts").get_json() == []
    assert ready.get("/api/credentials").get_json() == []


def test_packets_filters(ready, samples):
    upload(ready, samples / "normal.pcap")
    assert len(ready.get("/api/packets?protocol=dns").get_json()) == 2
    assert len(ready.get("/api/packets?port=443").get_json()) == 4
    assert len(ready.get("/api/packets?ip=192.168.56.1").get_json()) == 4
    assert len(ready.get("/api/packets?limit=3").get_json()) == 3
    assert ready.get("/api/packets?port=abc").status_code == 400
    assert ready.get("/api/packets?ip=1.2.3").status_code == 400


def test_unknown_session_is_404(ready):
    assert ready.get("/api/alerts").status_code == 404
    assert ready.get("/api/alerts?session=99").status_code == 404


# --- export (RF13) ---

def test_export_alerts_csv_json(ready, samples):
    upload(ready, samples / "port_scan.pcap")
    data = json.loads(ready.get("/api/export/alerts.json").data)
    assert data[0]["type"] == "PORT_SCAN"
    r = ready.get("/api/export/alerts.csv")
    assert "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(r.data.decode())))
    assert rows[0]["type"] == "PORT_SCAN" and "22, 80" in rows[0]["detail"]


def test_export_packets_csv(ready, samples):
    upload(ready, samples / "normal.pcap")
    rows = list(csv.DictReader(io.StringIO(ready.get("/api/export/packets.csv").data.decode())))
    assert len(rows) == 15 and rows[0]["protocol"] == "ARP"  # oldest first


def test_export_session_pcap_has_no_real_password(ready, samples):
    upload(ready, samples / "creds.pcap")
    r = ready.get("/api/export/session.pcap")
    assert r.status_code == 200 and r.data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    assert b"Secreto123" not in r.data and b"Correo2024" not in r.data
    assert b"YWxpY2U6U2VjcmV0bzEyMw==" not in r.data
    assert b"USER alice" in r.data  # other packets are kept intact


def test_export_unknown_kind(ready, samples):
    upload(ready, samples / "normal.pcap")
    assert ready.get("/api/export/nada").status_code == 404


def test_csv_formula_injection_is_neutralized(app, ready):
    repo = app.extensions["netwatch"]["repo"]
    sid = repo.create_session("file", "x")
    repo.add_alert(sid, 1.0, "CLEARTEXT_CREDENTIALS", "alta", "=HYPERLINK(\"http://x\")")
    rows = list(csv.DictReader(io.StringIO(ready.get(f"/api/export/alerts.csv?session={sid}").data.decode())))
    assert rows[0]["detail"].startswith("'=")


# --- local-only protections ---

def test_rejects_non_local_host_and_cross_origin_post(client):
    assert client.get("/api/status", headers={"Host": "evil.example"}).status_code == 403
    r = client.post("/api/settings", json={"warning_accepted": True}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


# --- fecha_hora and src_ip in exports ---

def test_exports_have_fecha_hora_and_src_ip(ready, samples):
    import time
    upload(ready, samples / "port_scan.pcap")
    rows = list(csv.DictReader(io.StringIO(ready.get("/api/export/alerts.csv").data.decode())))
    assert list(rows[0])[:6] == ["id", "fecha_hora", "ts", "type", "severity", "src_ip"]
    assert rows[0]["src_ip"] == "192.168.56.66"
    expected = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(rows[0]["ts"])))
    assert rows[0]["fecha_hora"] == expected
    data = json.loads(ready.get("/api/export/alerts.json").data)
    assert data[0]["fecha_hora"] == expected and data[0]["src_ip"] == "192.168.56.66"
    pkts = list(csv.DictReader(io.StringIO(ready.get("/api/export/packets.csv").data.decode())))
    assert list(pkts[0])[:3] == ["id", "fecha_hora", "ts"]
    assert pkts[0]["fecha_hora"] == time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(pkts[0]["ts"])))


def test_alert_src_ip_per_detector(ready, samples):
    for name, expected in [("arp_spoof.pcap", {"192.168.56.1", "192.168.56.20"}),
                           ("creds.pcap", {"192.168.56.20"})]:
        upload(ready, samples / name)
        assert {a["src_ip"] for a in ready.get("/api/alerts").get_json()} == expected


def test_old_database_gets_src_ip_column(tmp_path):
    import sqlite3
    from netwatch.db.repository import Repository
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)  # alerts table as it was before src_ip existed
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, "
                 "ts REAL NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, detail TEXT NOT NULL)")
    conn.execute("INSERT INTO alerts (session_id, ts, type, severity, detail) VALUES (1, 1.0, 'X', 'alta', 'vieja')")
    conn.commit()
    conn.close()
    repo = Repository(db)
    repo.add_alert(1, 2.0, "Y", "alta", "nueva", "192.168.56.9")
    assert [(a["detail"], a["src_ip"]) for a in repo.alerts(1)] == [("vieja", None), ("nueva", "192.168.56.9")]
    repo.close()
