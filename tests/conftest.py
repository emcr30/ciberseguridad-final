import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import gen_samples  # noqa: E402

LAB = ["192.168.56.0/24"]


@pytest.fixture(scope="session")
def samples(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("samples")
    gen_samples.build_samples(out)
    return out
