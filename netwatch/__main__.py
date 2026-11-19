"""CLI: python -m netwatch <command>."""
from __future__ import annotations

import argparse
import ctypes
import os
import sys

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


def main() -> None:
    parser = argparse.ArgumentParser(prog="netwatch", description="NetWatch - analizador defensivo")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("interfaces", help="Listar interfaces y privilegios").set_defaults(func=cmd_interfaces)

    p_cfg = sub.add_parser("config", help="Configurar redes de laboratorio")
    p_cfg.add_argument("--add-network", metavar="CIDR")
    p_cfg.add_argument("--remove-network", metavar="CIDR")
    p_cfg.add_argument("--gateway", metavar="IP")
    p_cfg.set_defaults(func=cmd_config)

    args = parser.parse_args()
    print(WARNING, end="\n\n")
    args.func(args)


if __name__ == "__main__":
    main()
