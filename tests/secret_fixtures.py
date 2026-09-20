"""Credential-shaped test fixtures, assembled at runtime.

A test that proves the secret detector fires *must* contain a string the
detector's regex matches — but a contiguous ``AKIA…``, ``ghp_…``,
``xoxb-…`` or ``-----BEGIN … PRIVATE KEY-----`` literal in the source is
indistinguishable from a live credential to anything that scans the repo:

  * GitHub push protection refuses the whole push
    (``GH013: Push cannot contain secrets``) and ``--force`` does not help,
    because it is a server-side rule.
  * Static scanners report it as a critical finding at the line it sits on.
    AWS's own documentation example key still trips them.

Joining the parts at import time means no single string in the source
matches the pattern, while the code under test still receives the
fully-formed value it is meant to detect. Put every new credential-shaped
fixture here rather than writing the literal inline.
"""

from __future__ import annotations

_AKIA = "AKIA"

# AWS's own documented example access-key id (the value the agent and
# routing tests have always used).
AWS_EXAMPLE_KEY = _AKIA + "IOSFODNN7EXAMPLE"


def aws_access_key(body: str = "ABCDEFGHIJKLMNOP") -> str:
    """A 20-character ``AKIA…`` id shape; ``body`` must be 16 × [0-9A-Z]."""
    return _AKIA + body


def github_token(body: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") -> str:
    """``ghp_`` + 36 alphanumerics, matching the github_token pattern."""
    return "ghp_" + body


def slack_token() -> str:
    """``xoxb-…``, matching the slack_token pattern."""
    return "-".join(("xoxb", "123456789012", "abcdefghijklmnop"))


def google_api_key() -> str:
    """``AIza`` + 35 url-safe characters, matching the google_api_key pattern."""
    return "AIza" + "SyD-1234567890abcdefghijklmnopqrstu"


def private_key_block() -> str:
    """A PEM private-key block. The dashes are built separately so the
    ``-----BEGIN`` header never appears contiguously in this file."""
    dashes = "-" * 5
    return (
        f"{dashes}BEGIN RSA PRIVATE KEY{dashes}\n"
        "MIIEow...\n"
        f"{dashes}END RSA PRIVATE KEY{dashes}"
    )
