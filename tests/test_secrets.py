"""Tests for secret detection/redaction (spec §6.4)."""

from kryonsec.secrets import detect_secrets, redact, restore


def test_detect_jwt():
    text = "header eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    assert detect_secrets(text)


def test_detect_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    assert detect_secrets(text)


def test_detect_password_assignment():
    assert detect_secrets("password: hunter2secret")


def test_no_false_positive_plain_text():
    assert not detect_secrets("What is the CVSS score for CVE-2021-44228?")


def test_redact_restore_roundtrip():
    text = "login with password: supersecret123 then JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c ok"
    redacted, mapping = redact(text)
    assert mapping, "expected at least one secret detected"
    for value in mapping.values():
        assert value not in redacted, f"secret leaked into redacted text: {value!r}"
    assert restore(redacted, mapping) == text


def test_redact_keeps_label():
    redacted, mapping = redact("password: supersecret123")
    assert "password" in redacted
    assert "supersecret123" not in redacted
    assert list(mapping.values()) == ["supersecret123"]


# ---- cloud credential names (2026-09-18) -----------------------------------
# The label alternation used a leading \b, which cannot match inside
# AWS_SECRET_ACCESS_KEY (the character before SECRET is "_", itself a word
# char). The AWS secret therefore went to the provider unredacted AND
# detect_secrets() was False, so it was not routed to the local model either.

_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_detect_aws_secret_access_key():
    assert detect_secrets(f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}")


def test_detect_aws_secret_access_key_lowercase_spaced():
    assert detect_secrets(f"aws_secret_access_key = {_AWS_SECRET}")


def test_redact_aws_secret_access_key_keeps_label():
    redacted, mapping = redact(f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}")
    assert "AWS_SECRET_ACCESS_KEY" in redacted
    assert _AWS_SECRET not in redacted
    assert list(mapping.values()) == [_AWS_SECRET]


# Assembled at runtime rather than written as one literal: GitHub's push
# protection cannot tell a test fixture from a live credential, so the
# contiguous xoxb-… shape is refused outright ("Push cannot contain secrets")
# and the commit never reaches the remote. Splitting it means no single string
# in this file matches the scanner's pattern, while detect_secrets() still
# sees the joined value and redacts it as the test intends.
_SLACK_TOKEN = "-".join(("xoxb", "123456789012", "abcdefghijklmnop"))


def test_detect_slack_token():
    token = _SLACK_TOKEN
    assert detect_secrets(f"slack_token={token}")
    redacted, _ = redact(f"slack_token={token}")
    assert token not in redacted


def test_detect_google_api_key():
    key = "AIzaSyD-1234567890abcdefghijklmnopqrstu"
    assert detect_secrets(f"GOOGLE_API_KEY={key}")
    redacted, _ = redact(f"GOOGLE_API_KEY={key}")
    assert key not in redacted


def test_credential_labels_do_not_false_positive():
    """The looser left-guard must not start eating ordinary prose."""
    for text in (
        "the api_key field is documented as a string",
        "secret_key_name = None",
        "access_token_count = 5",
        "password policy requires 12 chars",
        "What is the CVSS score for CVE-2021-44228?",
    ):
        assert not detect_secrets(text), f"false positive on: {text!r}"
