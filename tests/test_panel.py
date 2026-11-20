import re
from pathlib import Path

import pytest

from netwatch.web.app import create_app

STATIC = Path(__file__).resolve().parent.parent / "netwatch" / "web" / "static"


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path)
    yield app.test_client()
    app.extensions["netwatch"]["repo"].close()


def test_index_served_with_fixed_warning_banner(client):
    r = client.get("/")
    html = r.data.decode()
    assert r.status_code == 200 and r.mimetype == "text/html"
    assert 'id="banner"' in html and "ADVERTENCIA" in html and 'id="accept-warning"' in html
    assert "position: sticky" in (STATIC / "style.css").read_text()


def test_panel_has_all_sections(client):
    html = client.get("/").data.decode()
    for element_id in ["networks", "gateway", "iface", "capture-start", "capture-stop", "pcap-file", "upload",
                       "pps-chart", "proto-chart", "alerts-body", "conversations-body", "ipmac-body",
                       "credentials-body", "packets-body", "f-ip", "f-protocol", "f-port", "session"]:
        assert f'id="{element_id}"' in html, element_id
    for kind in ["alerts.csv", "alerts.json", "packets.csv", "session.pcap"]:
        assert f'data-export="{kind}"' in html


def test_chartjs_is_local(client):
    html = client.get("/").data.decode()
    scripts = re.findall(r'<script[^>]*src="([^"]+)"', html)
    assert scripts == ["/static/chart.umd.min.js", "/static/app.js"]
    assert not re.search(r'(src|href)="(https?:)?//', html)  # no CDN or external resources
    r = client.get("/static/chart.umd.min.js")
    assert r.status_code == 200 and b"Chart.js v4" in r.data[:200]


def test_no_inline_scripts(client):
    html = client.get("/").data.decode()
    assert re.findall(r"<script(?![^>]*src=)[^>]*>", html) == []
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE)  # no onclick=... handlers


def test_app_js_never_uses_innerhtml():
    js = (STATIC / "app.js").read_text()
    for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("]:
        assert sink not in js, sink
    assert "textContent" in js


def test_refresh_every_2_seconds():
    assert "REFRESH_MS = 2000" in (STATIC / "app.js").read_text()


def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "default-src 'self'" in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in client.get("/api/status").headers
