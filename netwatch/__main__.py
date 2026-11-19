"""CLI: python -m netwatch <command>."""
from __future__ import annotations

import argparse
import ctypes
import os
import sys
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
    from scapy.all import get_if_list

    print("Interfaces disponibles:")
    for name in get_if_list():
        print(f"  - {name}")
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


def _print_summary(summary: dict) -> None:
    print(f"Total de paquetes:  {summary['total']}")
    print(f"Descartados (fuera de las redes de laboratorio): {summary['discarded']}")
    print(f"Analizados: {summary['analyzed']}")
    print("Por protocolo:" + ("" if summary["protocols"] else " (ninguno)"))
    for proto, count in summary["protocols"].items():
        print(f"  {proto:<8} {count}")


def cmd_analyze(args) -> None:
    from netwatch.pipeline import analyze_file

    path = Path(args.file)
    if not path.is_file():
        print(f"Error: no existe el archivo {path}")
        sys.exit(1)
    _print_summary(analyze_file(path, _require_networks()))


def cmd_capture(args) -> None:
    import time

    from netwatch.capture.sources import LiveSource
    from netwatch.pipeline import Pipeline

    pipeline = Pipeline(_require_networks())
    source = LiveSource(args.iface, pipeline.handle)
    try:
        source.start()
    except RuntimeError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    print(f"Capturando en {args.iface} durante {args.seconds} s (Ctrl+C para detener)...")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        source.stop()
    _print_summary(pipeline.summary())


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
    p_an.set_defaults(func=cmd_analyze)

    p_cap = sub.add_parser("capture", help="Captura en vivo (requiere privilegios)")
    p_cap.add_argument("-i", "--iface", required=True)
    p_cap.add_argument("-t", "--seconds", type=int, default=30)
    p_cap.set_defaults(func=cmd_capture)

    args = parser.parse_args()
    print(WARNING, end="\n\n")
    args.func(args)


if __name__ == "__main__":
    main()
