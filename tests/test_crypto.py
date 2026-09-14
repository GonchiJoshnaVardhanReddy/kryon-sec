"""Tests for the engagement secret map (C1): values must be real ciphertext.

A row written through store_secret must NOT contain the plaintext anywhere in
the stored column, and must not be decryptable with a different key.
"""

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.storage import (
    EngagementSecretMap,
    get_session,
    init_db,
    lookup_secret,
    reset_engine,
    store_secret,
)
from kryonsec.storage.crypto import decrypt_secret, encrypt_secret, secret_key_path


@pytest.fixture()
def cfg(tmp_path):
    reset_engine()
    c = KryonsecConfig(home=tmp_path / "home")
    c.database_url = f"sqlite:///{tmp_path / 'test.db'}"
    yield c
    reset_engine()


def test_encrypt_roundtrip_and_no_plaintext(cfg):
    secret = "sk-super-secret-token-123"
    token = encrypt_secret(cfg, secret)
    assert token != secret
    assert secret not in token
    assert decrypt_secret(cfg, token) == secret


def test_key_file_created_on_first_use(cfg):
    assert not secret_key_path(cfg).exists()
    encrypt_secret(cfg, "x")
    assert secret_key_path(cfg).is_file()


def test_wrong_key_cannot_decrypt(cfg):
    token = encrypt_secret(cfg, "hunter2")
    # simulate key loss/rotation: a fresh home generates a different key
    cfg.home = cfg.home.parent / "home2"
    with pytest.raises(ValueError):
        decrypt_secret(cfg, token)


def test_tampered_ciphertext_rejected(cfg):
    token = encrypt_secret(cfg, "hunter2")
    with pytest.raises(ValueError):
        decrypt_secret(cfg, token[:-4] + "AAAA")


def test_store_and_lookup_secret_roundtrip(cfg):
    init_db(cfg, include_purple=True)
    with get_session(cfg) as s:
        store_secret(s, cfg, "eng-1", "SECRET_1", "password123")
        s.commit()
    with get_session(cfg) as s:
        assert lookup_secret(s, cfg, "eng-1", "SECRET_1") == "password123"
        assert lookup_secret(s, cfg, "eng-1", "SECRET_MISSING") is None


def test_stored_row_is_not_plaintext(cfg):
    """The core C1 guarantee: read the raw column back, no decrypt call."""
    init_db(cfg, include_purple=True)
    with get_session(cfg) as s:
        store_secret(s, cfg, "eng-1", "SECRET_1", "password123")
        s.commit()
    with get_session(cfg) as s:
        row = s.query(EngagementSecretMap).filter_by(engagement_id="eng-1").one()
        assert "password123" not in row.secret_encrypted
        assert row.secret_encrypted != "password123"


def test_store_secret_replaces_existing_mapping(cfg):
    init_db(cfg, include_purple=True)
    with get_session(cfg) as s:
        store_secret(s, cfg, "eng-1", "SECRET_1", "old")
        s.commit()
    with get_session(cfg) as s:
        store_secret(s, cfg, "eng-1", "SECRET_1", "new")
        s.commit()
    with get_session(cfg) as s:
        assert s.query(EngagementSecretMap).filter_by(engagement_id="eng-1").count() == 1
        assert lookup_secret(s, cfg, "eng-1", "SECRET_1") == "new"
