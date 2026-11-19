import pytest

from netwatch import config
from netwatch.scope import in_scope, validate_cidr

LAB = ["192.168.56.0/24"]


def test_validate_cidr_normalizes():
    assert validate_cidr("192.168.56.10/24") == "192.168.56.0/24"


@pytest.mark.parametrize("bad", ["abc", "300.1.1.0/24", "192.168.1.0/40", ""])
def test_validate_cidr_rejects_invalid(bad):
    with pytest.raises(ValueError):
        validate_cidr(bad)


def test_in_scope_inside():
    assert in_scope("192.168.56.20", LAB)


def test_in_scope_outside():
    assert not in_scope("8.8.8.8", LAB)


@pytest.mark.parametrize("ip", [None, "", "not-an-ip"])
def test_in_scope_invalid_ip(ip):
    assert not in_scope(ip, LAB)


def test_in_scope_without_networks():
    assert not in_scope("192.168.56.20", [])


def test_settings_add_network(tmp_path):
    path = tmp_path / "settings.json"
    config.add_network("192.168.56.0/24", path)
    config.add_network("192.168.56.0/24", path)  # no duplicates
    assert config.load_settings(path)["networks"] == ["192.168.56.0/24"]
