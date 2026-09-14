"""Application-layer encryption for the engagement secret map (spec §6.4, C1).

Compaction replaces secrets found in tool output with placeholders before any
LLM call; the placeholder->secret mapping lives in the engagement_secret_map
table so findings can be re-hydrated locally afterwards. CLAUDE.md rule 4:
secrets never leave the machine — so the stored values must be real ciphertext,
not a column name that merely says "encrypted".

Scheme: Fernet (AES-128-CBC + HMAC-SHA256, authenticated). The key is
generated once into <home>/secret.key with 0600 permissions and never leaves
the machine. Ciphertext tokens are urlsafe-base64 ASCII, which fits the
secret_encrypted TEXT column directly.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from ..config import KryonsecConfig
from .models import EngagementSecretMap

log = logging.getLogger(__name__)


def secret_key_path(cfg: KryonsecConfig) -> Path:
    return cfg.home / "secret.key"


def _load_or_create_key(path: Path) -> bytes:
    """Load the Fernet key, generating the file on first use (0600)."""
    if path.is_file():
        key = path.read_bytes().strip()
        Fernet(key)  # raises ValueError if the file is not a valid key
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    log.info("generated new secret-map key at %s", path)
    return key


def _fernet(cfg: KryonsecConfig) -> Fernet:
    # No caching: the key file is tiny and this runs only at compaction and
    # re-hydration time, and a cached object would go stale across tests and
    # key rotations.
    return Fernet(_load_or_create_key(secret_key_path(cfg)))


def encrypt_secret(cfg: KryonsecConfig, plaintext: str) -> str:
    """Encrypt one secret; returns an ASCII-safe token for the TEXT column."""
    return _fernet(cfg).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(cfg: KryonsecConfig, token: str) -> str:
    """Decrypt one stored token; raises ValueError on wrong key or tampering."""
    try:
        return _fernet(cfg).decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "secret could not be decrypted — wrong key or tampered row"
        ) from exc


# ---- repository functions (thin layer, CLAUDE.md storage convention) -------

def store_secret(
    session: Session, cfg: KryonsecConfig, engagement_id: str, placeholder: str, secret: str
) -> EngagementSecretMap:
    """Insert or replace the mapping for (engagement_id, placeholder)."""
    row = (
        session.query(EngagementSecretMap)
        .filter_by(engagement_id=engagement_id, placeholder=placeholder)
        .one_or_none()
    )
    if row is None:
        row = EngagementSecretMap(
            engagement_id=engagement_id,
            placeholder=placeholder,
            secret_encrypted=encrypt_secret(cfg, secret),
        )
        session.add(row)
    else:
        row.secret_encrypted = encrypt_secret(cfg, secret)
    return row


def lookup_secret(
    session: Session, cfg: KryonsecConfig, engagement_id: str, placeholder: str
) -> str | None:
    """Return the plaintext secret for a placeholder, or None if absent."""
    row = (
        session.query(EngagementSecretMap)
        .filter_by(engagement_id=engagement_id, placeholder=placeholder)
        .one_or_none()
    )
    if row is None:
        return None
    return decrypt_secret(cfg, row.secret_encrypted)
