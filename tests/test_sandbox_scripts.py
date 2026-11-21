"""The baked sandbox probes must ALWAYS emit their JSON record.

An evidence probe that dies with a traceback produces no evidence, and an
empty evidence node cannot be told apart from "nothing was found". The
2026-11-18 Phase-2 real-path run found exactly that: the shipped
``enum_network.py`` called ``socket.getifaddrs()`` — an API CPython has
never had — so every real run ended with AttributeError before printing a
byte, and the POST_EXPLOIT record for that tool was always empty.

The tests load the SAME files ``containers/sandbox/Dockerfile.kali``
copies into the image (``containers/sandbox/scripts/``), never a copy, so
a script that stops emitting its record fails here.
"""

import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

SCRIPTS = (Path(__file__).resolve().parents[1]
           / "containers" / "sandbox" / "scripts")


def _load(name: str):
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"sandbox_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module, monkeypatch, target: str = "juice-shop.lab") -> dict:
    monkeypatch.setattr(sys, "argv", [f"{module.__name__}.py", target])
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert module.main() == 0
    return json.loads(buf.getvalue())


# ---- enum_network: the probe that had never produced evidence ---------------

def test_enum_network_emits_its_record(monkeypatch):
    record = _run(_load("enum_network"), monkeypatch)
    assert record["probe"] == "enum_network"
    assert record["target_context"] == "juice-shop.lab"
    assert isinstance(record["interfaces"], list)
    assert isinstance(record["established_sockets"], list)
    assert isinstance(record["resolver"], list)
    assert record["errors"] == [] or isinstance(record["errors"], list)
    assert record["hostname"] != ""


def test_enum_network_reports_a_broken_ioctl_instead_of_dying(monkeypatch):
    """The probe's old failure mode: an unexpected exception killed the
    whole record. Now the failure is data — the record always exists."""
    module = _load("enum_network")

    class BrokenFcntl:
        @staticmethod
        def ioctl(*_args, **_kwargs):
            raise OSError("SIOCGIFADDR refused")

    monkeypatch.setitem(sys.modules, "fcntl", BrokenFcntl)
    record = _run(module, monkeypatch)

    assert isinstance(record["interfaces"], list)  # never AttributeError
    assert any("SIOCGIFADDR refused" in e for e in record["errors"])


# ---- the other baked probes -------------------------------------------------

@pytest.mark.parametrize("name,probe", [
    ("enum_processes", "enum_processes"),
    ("find_secrets", "find_secrets"),
])
def test_probe_emits_its_json_record(name, probe, monkeypatch):
    record = _run(_load(name), monkeypatch)
    assert record["probe"] == probe
    assert record["target_context"] == "juice-shop.lab"
