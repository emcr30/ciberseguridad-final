"""Flask JSON API (RF1, RF2, RF13) and web panel (RF10, RF11, RF15). Listens only on 127.0.0.1."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, send_file
from werkzeug.utils import secure_filename

from netwatch import config
from netwatch.capture import sources
from netwatch.db.repository import MAX_PACKETS, Repository
from netwatch.legal import WARNING
from netwatch.pipeline import Pipeline, analyze_file, session_pcap

LOCAL_HOSTS = {"127.0.0.1", "localhost"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_MB = 100
CSV_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")
# Only local files: Chart.js is served from static/, no CDN, no inline scripts.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class CaptureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.source = None
        self.pipeline = None
        self.iface = None

    @property
    def running(self) -> bool:
        return self.source is not None


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _csv_cell(value):
    """Avoid CSV formula injection: network data (e.g. usernames) could start with '='."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_CHARS):
        return "'" + value
    return value


def _with_datetime(rows: list[dict]) -> list[dict]:
    """Add a readable local date-time (fecha_hora) next to the epoch timestamp ts."""
    return [{"fecha_hora": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), **r} for r in rows]


def _csv_response(rows: list[dict], columns: list[str], filename: str) -> Response:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_cell(row.get(c)) for c in columns])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


def create_app(data_dir: Path = config.DATA_DIR) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    settings_file = data_dir / "settings.json"
    sessions_dir = data_dir / "sessions"
    uploads_dir = data_dir / "uploads"
    repo = Repository(data_dir / "netwatch.db")
    capture = CaptureState()
    app.extensions["netwatch"] = {"repo": repo, "capture": capture}

    def settings() -> dict:
        return config.load_settings(settings_file)

    def session_id_arg() -> int | None:
        return request.args.get("session", type=int) or repo.latest_session_id()

    def with_session(fn):
        """Run fn(session_id), or 404 if there is no such session."""
        sid = session_id_arg()
        if sid is None or repo.get_session(sid) is None:
            return _error("No hay ninguna sesión con ese id (analice un .pcap o inicie una captura).", 404)
        return fn(sid)

    # --- security: local only, and no cross-site POST from a browser ---
    @app.before_request
    def local_only():
        if request.host.split(":")[0] not in LOCAL_HOSTS:
            return _error("Solo se permite acceso local.", 403)
        origin = request.headers.get("Origin")
        if request.method == "POST" and origin and urlparse(origin).hostname not in LOCAL_HOSTS:
            return _error("Origen no permitido.", 403)
        return None

    @app.after_request
    def security_headers(response):
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.errorhandler(413)
    def too_large(_e):
        return _error(f"Archivo demasiado grande (máximo {MAX_UPLOAD_MB} MB).", 413)

    # --- status / interfaces / settings ---
    @app.get("/api/status")
    def status():
        s = settings()
        return jsonify({
            "warning": WARNING,
            "warning_accepted": s["warning_accepted"],
            "privileges": sources.has_capture_privileges(),
            "networks": s["networks"],
            "gateway": s["gateway"],
            "capture": {"running": capture.running, "iface": capture.iface,
                        "session_id": capture.pipeline.session_id if capture.running else None},
            "latest_session_id": repo.latest_session_id(),
            "sessions": repo.sessions(),
        })

    @app.get("/api/interfaces")
    def interfaces():
        return jsonify(sources.list_interfaces(settings()["networks"]))

    @app.get("/api/settings")
    def get_settings():
        return jsonify(settings())

    @app.post("/api/settings")
    def post_settings():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _error("Se esperaba un cuerpo JSON.", 400)
        networks = body.get("networks")
        if networks is not None and not (isinstance(networks, list) and all(isinstance(n, str) for n in networks)):
            return _error("'networks' debe ser una lista de CIDR.", 400)
        try:
            new = config.update_settings(networks, body.get("gateway"), body.get("warning_accepted"),
                                         path=settings_file)
        except ValueError as exc:
            return _error(f"Valor inválido: {exc}", 400)
        return jsonify(new)

    # --- live capture (RF1) ---
    @app.post("/api/capture/start")
    def capture_start():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _error("Se esperaba un cuerpo JSON con 'iface'.", 400)
        s = settings()
        if not s["warning_accepted"]:
            return _error("Debe aceptar la advertencia legal antes de capturar.", 403)
        if not s["networks"]:
            return _error("Debe declarar al menos una red de laboratorio antes de capturar.", 400)
        iface = body.get("iface")
        if iface not in {i["name"] for i in sources.list_interfaces(s["networks"])}:
            return _error("Interfaz desconocida.", 400)
        if not sources.has_capture_privileges():
            return _error(f"Sin privilegios de captura. {sources.PRIVILEGES_HELP} "
                          "El análisis de .pcap sigue disponible.", 403)
        with capture.lock:
            if capture.running:
                return _error("Ya hay una captura en curso.", 409)
            sid = repo.create_session("live", iface)
            pipeline = Pipeline(s["networks"], repo=repo, session_id=sid, gateway=s["gateway"],
                                pcap_path=session_pcap(sessions_dir, sid))
            source = sources.LiveSource(iface, pipeline.handle)
            try:
                source.start()
            except RuntimeError as exc:
                source.stop()
                pipeline.finish()
                return _error(str(exc), 500)
            capture.source, capture.pipeline, capture.iface = source, pipeline, iface
        return jsonify({"running": True, "iface": iface, "session_id": sid})

    @app.post("/api/capture/stop")
    def capture_stop():
        with capture.lock:
            if not capture.running:
                return _error("No hay ninguna captura en curso.", 409)
            capture.source.stop()
            summary = capture.pipeline.finish()
            capture.source = capture.pipeline = capture.iface = None
        return jsonify({"running": False, "summary": summary})

    # --- .pcap upload (RF2) ---
    @app.post("/api/upload")
    def upload():
        file = request.files.get("file")
        if file is None or not file.filename:
            return _error("Falta el archivo (campo 'file').", 400)
        name = secure_filename(file.filename) or "captura.pcap"
        if Path(name).suffix.lower() not in PCAP_EXTENSIONS:
            return _error("Solo se aceptan archivos .pcap, .pcapng o .cap.", 400)
        s = settings()
        if not s["networks"]:
            return _error("Debe declarar al menos una red de laboratorio antes de analizar.", 400)
        uploads_dir.mkdir(parents=True, exist_ok=True)
        tmp = uploads_dir / f"{uuid.uuid4().hex}.pcap"  # never use the client name as a path
        file.save(tmp)
        try:
            summary = analyze_file(tmp, s["networks"], repo=repo, gateway=s["gateway"],
                                   sessions_dir=sessions_dir, name=name)
        except Exception as exc:  # Scapy raises several types for broken files
            return _error(f"No se pudo leer el archivo como captura: {exc}", 400)
        finally:
            tmp.unlink(missing_ok=True)  # the original may contain real passwords
        return jsonify(summary)

    # --- data (RF4, RF5, RF6, RF10, RF11, RF12) ---
    @app.get("/api/stats")
    def stats():
        def build(sid):
            live = capture.pipeline.summary() if capture.running and capture.pipeline.session_id == sid else None
            return jsonify({"session": repo.get_session(sid), "live": live,
                            "protocols": repo.protocol_counts(sid),
                            "packets_per_second": repo.packets_per_second(sid),
                            "alerts": len(repo.alerts(sid)), "credentials": len(repo.credentials(sid))})
        return with_session(build)

    @app.get("/api/conversations")
    def conversations():
        limit = min(request.args.get("limit", 50, type=int), 1000)
        return with_session(lambda sid: jsonify(repo.top_conversations(sid, limit)))

    @app.get("/api/ip-mac")
    def ip_mac():
        return with_session(lambda sid: jsonify(repo.ip_mac_table(sid)))

    @app.get("/api/alerts")
    def alerts():
        return with_session(lambda sid: jsonify(repo.alerts(sid)))

    @app.get("/api/credentials")
    def credentials():
        return with_session(lambda sid: jsonify(repo.credentials(sid)))

    @app.get("/api/packets")
    def packets():
        ip = request.args.get("ip") or None
        protocol = request.args.get("protocol") or None
        port = request.args.get("port") or None
        limit = request.args.get("limit", 100, type=int)
        try:
            if ip:
                ipaddress.ip_address(ip)
            if port is not None:
                port = int(port)
                if not 0 <= port <= 65535:
                    raise ValueError(port)
        except ValueError:
            return _error("Filtro inválido: 'ip' debe ser una IP y 'port' un número entre 0 y 65535.", 400)
        limit = max(1, min(limit, 1000))
        return with_session(lambda sid: jsonify(repo.filter_packets(sid, ip, protocol, port, limit)))

    # --- export (RF13) ---
    @app.get("/api/export/<kind>")
    def export(kind):
        def build(sid):
            if kind == "alerts.json":
                body = json.dumps(_with_datetime(repo.alerts(sid)), ensure_ascii=False, indent=2)
                return Response(body, mimetype="application/json",
                                headers={"Content-Disposition": f"attachment; filename=alertas_{sid}.json"})
            if kind == "alerts.csv":
                return _csv_response(_with_datetime(repo.alerts(sid)),
                                     ["id", "fecha_hora", "ts", "type", "severity", "src_ip", "detail"],
                                     f"alertas_{sid}.csv")
            if kind == "packets.csv":
                rows = _with_datetime(list(reversed(repo.filter_packets(sid, limit=MAX_PACKETS))))
                cols = ["id", "fecha_hora", "ts", "protocol", "src_mac", "dst_mac", "src_ip", "dst_ip", "sport", "dport",
                        "length", "tcp_flags"]
                return _csv_response(rows, cols, f"paquetes_{sid}.csv")
            if kind == "session.pcap":
                path = session_pcap(sessions_dir, sid)
                if not path.exists():
                    return _error("Esta sesión no tiene archivo .pcap.", 404)
                return send_file(path, mimetype="application/vnd.tcpdump.pcap", as_attachment=True,
                                 download_name=f"sesion_{sid}.pcap")
            return _error("Exportación desconocida. Use alerts.csv, alerts.json, packets.csv o session.pcap.", 404)
        return with_session(build)

    return app
