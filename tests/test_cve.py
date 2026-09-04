"""Tests for CVE lookup (spec §3.6): validation, cache, offline behavior."""

import json
from unittest.mock import patch

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.cve import lookup_cve
from kryonsec.storage import init_db, reset_engine


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'cve.db'}"
    init_db(c)
    yield c
    reset_engine()


def test_rejects_non_cve_id(cfg):
    with pytest.raises(ValueError):
        lookup_cve(cfg, "not-a-cve")


def test_rejects_garbage(cfg):
    with pytest.raises(ValueError):
        lookup_cve(cfg, "CVE-9999")  # missing the dash-number sequence


def test_lookup_uses_cache(cfg):
    fake = {"id": "CVE-2021-44228", "cvss_score": 10.0, "severity": "CRITICAL",
            "description": "Log4Shell", "references": []}
    # first call fetches from NVD (mocked) and caches
    with patch("kryonsec.copilot.cve._from_nvd", return_value=fake):
        record = lookup_cve(cfg, "cve-2021-44228")
    assert record["cvss_score"] == 10.0

    # second call must come from cache: NVD mock now returns None
    with patch("kryonsec.copilot.cve._from_nvd", return_value=None):
        record = lookup_cve(cfg, "CVE-2021-44228")
    assert record["severity"] == "CRITICAL"


def test_unknown_cve_returns_none(cfg):
    with patch("kryonsec.copilot.cve._from_nvd", return_value=None):
        assert lookup_cve(cfg, "CVE-2030-12345") is None
