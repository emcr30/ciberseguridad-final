"""Settings (lab networks, gateway, accepted warning) persisted in data/settings.json."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from netwatch.scope import validate_cidr

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"
SESSIONS_DIR = DATA_DIR / "sessions"  # one .pcap per session (export, RF13)
DEFAULTS = {"networks": [], "gateway": None, "warning_accepted": False}


def load_settings(path: Path = SETTINGS_FILE) -> dict:
    if not path.exists():
        return dict(DEFAULTS, networks=[])
    data = json.loads(path.read_text(encoding="utf-8"))
    return {**DEFAULTS, **data}


def save_settings(settings: dict, path: Path = SETTINGS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def add_network(cidr: str, path: Path = SETTINGS_FILE) -> dict:
    settings = load_settings(path)
    net = validate_cidr(cidr)
    if net not in settings["networks"]:
        settings["networks"].append(net)
    save_settings(settings, path)
    return settings


def remove_network(cidr: str, path: Path = SETTINGS_FILE) -> dict:
    settings = load_settings(path)
    net = validate_cidr(cidr)
    settings["networks"] = [n for n in settings["networks"] if n != net]
    save_settings(settings, path)
    return settings


def update_settings(networks: list[str] | None = None, gateway: str | None = None,
                    warning_accepted: bool | None = None, path: Path = SETTINGS_FILE) -> dict:
    """Replace the given fields. Raises ValueError on an invalid CIDR or gateway IP."""
    settings = load_settings(path)
    if networks is not None:
        settings["networks"] = list(dict.fromkeys(validate_cidr(n) for n in networks))
    if gateway is not None:
        settings["gateway"] = str(ipaddress.ip_address(gateway)) if gateway else None
    if warning_accepted is not None:
        settings["warning_accepted"] = bool(warning_accepted)
    save_settings(settings, path)
    return settings


def set_gateway(ip: str | None, path: Path = SETTINGS_FILE) -> dict:
    settings = load_settings(path)
    settings["gateway"] = ip
    save_settings(settings, path)
    return settings
