"""CLI: python -m netwatch <command>."""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
import time
from pathlib import Path

from netwatch import config
from netwatch.legal import WARNING


def has_capture_privileges() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def cmd_interfaces(_args) -> None:
    from scapy.all import conf

    from netwatch.scope import in_scope

    networks = config.load_settings()["networks"]
    print("Interfaces disponibles (* = IP dentro de una red de laboratorio declarada):")
    print(f"    {'NOMBRE':<10} {'IP':<16} MAC")
    for iface in conf.ifaces.values():
        mark = "*" if in_scope(iface.ip, networks) else " "
        print(f"  {mark} {iface.name:<10} {iface.ip or '-':<16} {iface.mac or '-'}")
    if has_capture_privileges():
        print("Privilegios de captura: SÍ")
    else:
        print("Privilegios de captura: NO (Mac: sudo; Windows: Npcap + terminal de administrador). "
              "El análisis de .pcap sigue disponible.")


def cmd_config(args) -> None:
    try:
        if args.add_network:
            config.add_network(args.add_network)
        if args.remove_network:
            config.remove_network(args.remove_network)
        if args.gateway:
            config.set_gateway(args.gateway)
    except ValueError as exc:
        print(f"Error: red inválida ({exc})")
        sys.exit(1)
    settings = config.load_settings()
    print("Redes de laboratorio:", ", ".join(settings["networks"]) or "(ninguna)")
    print("Gateway:", settings["gateway"] or "(no definido)")


def _require_networks() -> list[str]:
    networks = config.load_settings()["networks"]
    if not networks:
        print("Error: no hay redes de laboratorio. Use: python -m netwatch config --add-network <CIDR>")
        sys.exit(1)
    return networks


def _print_report(repo, session_id: int) -> None:
    print("\nTop 5 conversaciones:")
    convs = repo.top_conversations(session_id, 5)
    if not convs:
        print("  (ninguna)")
    else:
        print(f"  {'IP A':<16}    {'IP B':<16} {'PAQUETES':>8} {'BYTES':>8}")
    for c in convs:
        print(f"  {c['ip_a']:<16} ↔  {c['ip_b']:<16} {c['packets']:>8} {c['bytes']:>8}")
    print("\nTabla IP ↔ MAC:")
    rows = repo.ip_mac_table(session_id)
    if not rows:
        print("  (vacía)")
    else:
        print(f"  {'IP':<16} {'MAC':<18} {'PRIMERA VEZ':<12} ÚLTIMA VEZ")
    for r in rows:
        first = time.strftime("%H:%M:%S", time.localtime(r["first_seen"]))
        last = time.strftime("%H:%M:%S", time.localtime(r["last_seen"]))
        print(f"  {r['ip']:<16} {r['mac']:<18} {first:<12} {last}")
    creds = repo.credentials(session_id)
    print(f"\nCredenciales en texto plano: {len(creds)}")
    if creds:
        print(f"  {'HORA':<9} {'PROTOCOLO':<11} {'ORIGEN':<16} {'DESTINO':<22} {'USUARIO':<12} CONTRASEÑA")
    for c in creds:
        hour = time.strftime("%H:%M:%S", time.localtime(c["ts"]))
        dst = f"{c['dst_ip']}:{c['dport']}"
        print(f"  {hour:<9} {c['protocol']:<11} {c['src_ip']:<16} {dst:<22} {c['username'] or '-':<12} "
              f"{c['password_masked']}")
    alerts = repo.alerts(session_id)
    print(f"\nAlertas: {len(alerts)}")
    for a in alerts:
        hour = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
        print(f"  [{hour}] {a['severity'].upper():<8} {a['type']:<13} {a['detail']}")


def _print_summary(summary: dict) -> None:
    print(f"Total de paquetes:  {summary['total']}")
    print(f"Descartados: {summary['discarded']}")
    for reason, count in summary["discarded_by_reason"].items():
        print(f"  {reason:<40} {count}")
    print(f"Analizados: {summary['analyzed']}")
    print("Por protocolo:" + ("" if summary["protocols"] else " (ninguno)"))
    for proto, count in summary["protocols"].items():
        print(f"  {proto:<8} {count}")


VERBOSE_LIMIT = 20


def _packet_printer(enabled: bool):
    """Return an on_packet callback printing up to VERBOSE_LIMIT packets (no payload)."""
    if not enabled:
        return None
    printed = [0]

    def show(info) -> None:
        if printed[0] >= VERBOSE_LIMIT:
            return
        printed[0] += 1
        hour = time.strftime("%H:%M:%S", time.localtime(info.ts)) + f".{int(info.ts % 1 * 1000):03d}"
        src = f"{info.src_ip}:{info.sport}" if info.sport is not None else info.src_ip
        dst = f"{info.dst_ip}:{info.dport}" if info.dport is not None else info.dst_ip
        print(f"  {hour}  {info.protocol:<6} {src} → {dst}")

    return show


def cmd_analyze(args) -> None:
    from netwatch.db.repository import DB_FILE, Repository
    from netwatch.pipeline import analyze_file

    path = Path(args.file)
    if not path.is_file():
        print(f"Error: no existe el archivo {path}")
        sys.exit(1)
    networks = _require_networks()
    if args.verbose:
        print(f"Paquetes analizados (máx. {VERBOSE_LIMIT}):")
    repo = Repository()
    try:
        gateway = config.load_settings()["gateway"]
        summary = analyze_file(path, networks, _packet_printer(args.verbose), repo, gateway)
        if args.verbose:
            print()
        _print_summary(summary)
        _print_report(repo, summary["session_id"])
    finally:
        repo.close()
    print(f"\nSesión #{summary['session_id']} guardada en {DB_FILE}")


def cmd_capture(args) -> None:
    from netwatch.capture.sources import LiveSource
    from netwatch.db.repository import DB_FILE, Repository
    from netwatch.pipeline import Pipeline

    networks = _require_networks()
    repo = Repository()
    pipeline = Pipeline(networks, _packet_printer(args.verbose), repo, repo.create_session("live", args.iface),
                        config.load_settings()["gateway"])
    source = LiveSource(args.iface, pipeline.handle)
    try:
        source.start()
    except RuntimeError as exc:
        pipeline.finish()
        repo.close()
        print(f"Error: {exc}")
        sys.exit(1)
    print(f"Capturando en {args.iface} durante {args.seconds} s (Ctrl+C para detener)...")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        source.stop()
    summary = pipeline.finish()
    print()
    _print_summary(summary)
    _print_report(repo, summary["session_id"])
    repo.close()
    print(f"\nSesión #{summary['session_id']} guardada en {DB_FILE}")


def cmd_db(_args) -> None:
    from netwatch.db.repository import DB_FILE, Repository

    repo = Repository()
    print(f"Base de datos: {DB_FILE}")
    print("Filas por tabla:")
    for table, count in repo.table_counts().items():
        print(f"  {table:<14} {count}")
    repo.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="netwatch", description="NetWatch - analizador defensivo")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("interfaces", help="Listar interfaces y privilegios").set_defaults(func=cmd_interfaces)

    p_cfg = sub.add_parser("config", help="Configurar redes de laboratorio")
    p_cfg.add_argument("--add-network", metavar="CIDR")
    p_cfg.add_argument("--remove-network", metavar="CIDR")
    p_cfg.add_argument("--gateway", metavar="IP")
    p_cfg.set_defaults(func=cmd_config)

    p_an = sub.add_parser("analyze", help="Analizar un archivo .pcap")
    p_an.add_argument("file")
    p_an.add_argument("-v", "--verbose", action="store_true", help=f"Mostrar hasta {VERBOSE_LIMIT} paquetes")
    p_an.set_defaults(func=cmd_analyze)

    p_cap = sub.add_parser("capture", help="Captura en vivo (requiere privilegios)")
    p_cap.add_argument("-i", "--iface", required=True)
    p_cap.add_argument("-t", "--seconds", type=int, default=30)
    p_cap.add_argument("-v", "--verbose", action="store_true", help=f"Mostrar hasta {VERBOSE_LIMIT} paquetes")
    p_cap.set_defaults(func=cmd_capture)

    sub.add_parser("db", help="Mostrar filas por tabla en la base de datos").set_defaults(func=cmd_db)

    args = parser.parse_args()
    print(WARNING, end="\n\n")
    args.func(args)


if __name__ == "__main__":
    main()
