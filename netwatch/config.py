"""Settings (lab networks and gateway) persisted in data/settings.json."""
from __future__ import annotations

import json
from pathlib import Path

from netwatch.scope import validate_cidr

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"
DEFAULTS = {"networks": [], "gateway": None}


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


def set_gateway(ip: str | None, path: Path = SETTINGS_FILE) -> dict:
    settings = load_settings(path)
    settings["gateway"] = ip
    save_settings(settings, path)
    return settings
