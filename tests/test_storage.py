"""Tests for storage layer (spec §10.1): schema creation, persistence."""

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.storage import (
    GeneralSession,
    GeneralUserLtm,
    SystemKnowledge,
    get_session,
    init_db,
    reset_engine,
)


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'test.db'}"
    yield c
    reset_engine()


def test_init_creates_general_tables(cfg):
    init_db(cfg, include_purple=False)
    with get_session(cfg) as s:
        row = GeneralSession(messages=[{"role": "user", "content": "hi"}], token_count=1)
        s.add(row)
        s.commit()
        assert s.query(GeneralSession).count() == 1


def test_user_ltm_unique_constraint(cfg):
    init_db(cfg)
    with get_session(cfg) as s:
        s.add(GeneralUserLtm(category="preference", key="explain_mode", value={"v": "simple"}))
        s.commit()
    with get_session(cfg) as s:
        s.add(GeneralUserLtm(category="preference", key="explain_mode", value={"v": "other"}))
        with pytest.raises(Exception):
            s.commit()


def test_system_knowledge_upsert(cfg):
    init_db(cfg)
    with get_session(cfg) as s:
        s.add(SystemKnowledge(category="cve", key="CVE-2021-44228", value={"score": 10.0}))
        s.commit()
    with get_session(cfg) as s:
        row = s.query(SystemKnowledge).filter_by(key="CVE-2021-44228").one()
        assert row.value["score"] == 10.0
