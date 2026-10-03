"""Secret detection and redaction (spec v2.1.1 §6.4).

Used before any compaction LLM call and for report/summary sanitization.
Patterns are intentionally conservative-family: API keys, JWTs, bearer
tokens, password assignments, private key blocks, connection strings.
"""

from __future__ import annotations

import re

# Each pattern: (name, compiled regex). Order matters — first match wins a
# placeholder, and overlapping matches are claimed left-to-right.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    )),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
    )),
    ("bearer_token", re.compile(
        r"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}"
    )),
    ("aws_access_key", re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    )),
    ("github_token", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"
    )),
    ("openai_key", re.compile(
        # sk-…, sk-proj-…, sk-svcacct-… (2024+ key formats include hyphens)
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"
    )),
    ("slack_token", re.compile(
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
    )),
    ("google_api_key", re.compile(
        r"\bAIza[0-9A-Za-z_-]{35}\b"
    )),
    ("password_assignment", re.compile(
        r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"
    )),
    ("api_key_assignment", re.compile(
        # Left guard is (?<![A-Za-z0-9]) rather than \b: in the canonical
        # cloud names the character before the label is "_", itself a word
        # char, so \b never matched — AWS_SECRET_ACCESS_KEY=… sailed through
        # unredacted (and detect_secrets() returned False, so the text was
        # not even routed to the local model).
        r"(?i)(?<![A-Za-z0-9])"
        r"(api[_-]?key|secret[_-]?key|access[_-]?token"
        r"|secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\b"
        r"\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"
    )),
    ("conn_string", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s@]+@[^\s]+"
    )),
]

# Password/api-key assignment patterns have the secret in group 2 —
# redact only the value, keep the label so the summary stays readable.
_GROUPED = {"password_assignment", "api_key_assignment"}


def detect_secrets(text: str) -> bool:
    """True if any secret pattern matches."""
    return any(p.search(text) for _, p in SECRET_PATTERNS)


def find_secrets(text: str) -> list[tuple[str, str, int, int]]:
    """Return (name, secret_value, start, end) spans, longest-match priority."""
    spans: list[tuple[str, str, int, int]] = []
    taken: list[tuple[int, int]] = []

    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if name in _GROUPED and m.lastindex and m.lastindex >= 2:
                start, end = m.start(2), m.end(2)
            else:
                start, end = m.start(), m.end()
            if start == end:
                continue
            if any(start < t_end and end > t_start for t_start, t_end in taken):
                continue  # overlaps an already-claimed span
            taken.append((start, end))
            spans.append((name, text[start:end], start, end))

    spans.sort(key=lambda s: s[2])
    return spans


def redact(text: str) -> tuple[str, dict[str, str]]:
    """Replace secrets with «SECRET_n» placeholders.

    Returns (redacted_text, mapping) where mapping is
    placeholder -> original value. The mapping never leaves the machine.
    """
    spans = find_secrets(text)
    if not spans:
        return text, {}

    mapping: dict[str, str] = {}
    out: list[str] = []
    cursor = 0
    for i, (_name, value, start, end) in enumerate(spans, start=1):
        placeholder = f"«SECRET_{i}»"
        mapping[placeholder] = value
        out.append(text[cursor:start])
        out.append(placeholder)
        cursor = end
    out.append(text[cursor:])
    return "".join(out), mapping


def restore(text: str, mapping: dict[str, str]) -> str:
    """Substitute placeholders back with the real values (local, no LLM)."""
    for placeholder, value in mapping.items():
        text = text.replace(placeholder, value)
    return text


# --- the redaction declaration --------------------------------------------
#
# A prompt assembled from material that has ALREADY been through redact()
# cannot be tested for secret patterns: the patterns are gone. Without
# something else in the text, llm.secrets_safe_prompt() would see a clean
# prompt and quietly stop honouring "secrets stay local" for secrets that
# arrived as engagement data — the gate would still hold for raw text, and
# silently not hold for redacted text.
#
# So the builder that redacts leaves this declaration behind. It is computed
# from the redaction itself (redact() returns the mapping, the builder counts
# it), it is a separate signal carried alongside the text, and it encodes a
# COUNT — never a value, never a fragment, nothing restorable.
#
# It is read from the START of a line. Every line of untrusted content the
# context builder renders is prefixed with "- ", so no graph value can begin
# a line with the marker: the signal cannot be forged from engagement data,
# and a value that merely mentions the words is still just data.
REDACTION_DECLARATION = "SECRET-PATTERNS-REDACTED"

# Deliberately \d+ and not [1-9]\d*: the count only records, the check below
# decides. A declaration of zero is not a declaration.
_REDACTION_DECLARATION_RE = re.compile(
    rf"^{re.escape(REDACTION_DECLARATION)}:[ \t]*(\d+)[ \t]*$", re.MULTILINE
)


def declared_redaction_count(text: str) -> int:
    """How many redactions ``text`` declares, or 0 when it declares none.

    A count, so it is safe to log: it says that sensitive material was
    present, never what it was.
    """
    match = _REDACTION_DECLARATION_RE.search(text)
    return int(match.group(1)) if match else 0


def declares_redactions(text: str) -> bool:
    """True when ``text`` says secret-shaped values were redacted out of it.

    The converse of :func:`detect_secrets` for material that has already
    been through :func:`redact`: the patterns are gone, so the only evidence
    left that the material was sensitive is the producer's own declaration.
    """
    return declared_redaction_count(text) > 0
