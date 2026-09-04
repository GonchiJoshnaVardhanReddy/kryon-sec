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
