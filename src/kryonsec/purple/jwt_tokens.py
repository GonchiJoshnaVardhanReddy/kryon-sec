"""The JWT token producer + offline analyzer (tool expansion Wave 2b).

``jwt_tool`` is allowlisted (``["{token}"]``) but was gated: no lane
produced its input, so every jwt_tool hypothesis got an audited skip
("no executable argv template"). This module is the producer — and the
offline analyzer:

- **Extraction** is a pure text scan for JWT-shaped strings, followed by
  a strict decode check: the first segment must decode to a JSON object
  with a string ``alg``, the second to a JSON object. A lookalike that
  does not decode is not a token.
- **Collection** reads the evidence graph's own node properties — data
  already fetched by earlier states (api observations, endpoint
  metadata, candidate findings, notes, path labels). This module sends
  NOTHING anywhere and touches no target. LLM-authored node types
  (hypotheses, plans) are deliberately NOT scanned: a token feeding a
  tool must come from observed evidence, never from prompt text.
- **Classification** is OFFLINE: base64url decode + claim reading. It
  never verifies a signature, never contacts a key server, and never
  calls a token "valid" — it reads what the token itself says (alg,
  exp/iat/nbf, kid, iss) and labels staleness against the caller's
  clock (a pinned-clock test passes both the claims and ``now``).
- **Output**: one ``jwt_token`` graph node per captured token (label is
  a short SHA-256 fingerprint; the raw token stays in the node's
  properties — engagement data that never leaves the machine), with
  provenance pointing at the evidence node it was found in, and ONE
  audited capture event carrying counts only — never token bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .handoff import utc_now_iso

if TYPE_CHECKING:  # pragma: no cover - import cycle guard only
    from .recon_passive import EngagementGraph

log = __import__("logging").getLogger(__name__)

# JWT headers are base64url of ``{"`` — every real token starts "eyJ".
# The shape mirrors the allowlist's {token} grammar (three base64url
# segments); the decode check below is what separates tokens from
# lookalikes, not the regex alone.
_JWT_SHAPE_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Evidence-node types scanned for tokens. OBSERVED evidence only —
# never hypothesis/plan/prompt text (an LLM must not be able to feed a
# tool its input by writing it into a hypothesis).
SCAN_NODE_TYPES: tuple[str, ...] = (
    "api_observation",
    "web_endpoint",
    "vuln_candidate",
    "osint_note",
    "path",
)

# A string longer than this is not scanned (bounded work; a token is
# small — anything near this size is a body dump, not a JWT).
MAX_TEXT_SCAN = 65_536

# Cap per capture pass: bounded graph growth.
MAX_TOKENS_PER_CAPTURE = 16

_MAX_TOKEN_LEN = 8_192


def _b64url_json(segment: str):
    """Decode one base64url segment to a JSON object (or None)."""
    try:
        padded = segment + "=" * (-len(segment) % 4)
        obj = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def is_jwt(candidate: str) -> bool:
    """True when the string decodes as a JWT: three segments, header is
    a JSON object with a string ``alg``, payload is a JSON object."""
    if not 0 < len(candidate) <= _MAX_TOKEN_LEN:
        return False
    parts = candidate.split(".")
    if len(parts) != 3:
        return False
    header = _b64url_json(parts[0])
    if header is None or not isinstance(header.get("alg"), str):
        return False
    return _b64url_json(parts[1]) is not None


def extract_jwt_candidates(text: str) -> list[str]:
    """All decodable JWT strings in ``text``, deduped, order kept.

    Pure: a filter over text this process already holds. Sends nothing
    anywhere."""
    if not text or len(text) > MAX_TEXT_SCAN:
        return []
    out: list[str] = []
    for match in _JWT_SHAPE_RE.findall(text):
        if is_jwt(match) and match not in out:
            out.append(match)
    return out


@dataclass
class TokenRecord:
    """One captured token and where it came from."""

    token: str
    source_node_type: str
    source_node_id: str
    fingerprint: str

    @property
    def label(self) -> str:
        return self.fingerprint


def _fingerprint(token: str) -> str:
    return "jwt:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _string_values(value, depth: int = 0):
    """Every string in a properties dict/list tree, bounded depth."""
    if depth > 4:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _string_values(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _string_values(v, depth + 1)


def _epoch_to_iso(value) -> str | None:
    """An epoch-seconds exp/iat/nbf claim (int, float, or numeric
    string) as ISO-8601 UTC — None when the claim is not epoch-shaped."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def inspect_token(token: str, now: "datetime | None" = None) -> dict:
    """OFFLINE classification of one token — what it says about itself.

    Never verifies a signature and never says "valid". Returns the
    header/payload claims a report can read (alg, kid, iss, sub, jti,
    typ), the time claims as ISO strings, and staleness notes computed
    against ``now`` (default: the real clock — a test pinning claims
    must pin ``now`` too, per the test-clock rule).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    parts = token.split(".")
    header = _b64url_json(parts[0]) or {}
    payload = _b64url_json(parts[1]) or {}

    notes: list[str] = []
    alg = header.get("alg")
    if alg == "none":
        notes.append("alg 'none' — the token itself declares no signature")
    elif isinstance(alg, str) and alg.startswith("HS"):
        notes.append(
            f"alg {alg} — symmetric; key strength cannot be assessed offline")

    out: dict = {
        "alg": alg,
        "typ": header.get("typ"),
        "kid": header.get("kid"),
        "iss": payload.get("iss"),
        "sub": payload.get("sub"),
        "jti": payload.get("jti"),
    }
    for claim in ("exp", "iat", "nbf"):
        iso = _epoch_to_iso(payload.get(claim))
        out[claim] = iso
        out[f"{claim}_present"] = iso is not None

    exp_iso = out["exp"]
    if exp_iso is None:
        notes.append("no exp claim — never expires by its own claims")
    else:
        exp_seconds = float(payload["exp"])
        age = exp_seconds - now.timestamp()
        if age < 0:
            notes.append(
                f"exp in the past — stale at {now.isoformat(timespec='seconds')}")
        else:
            notes.append(
                f"exp in the future — fresh at "
                f"{now.isoformat(timespec='seconds')}")
    nbf_iso = out["nbf"]
    if nbf_iso is not None and float(payload["nbf"]) > now.timestamp():
        notes.append("nbf in the future — not-yet-valid by its own claims")
    out["notes"] = notes
    return out


def collect_tokens_from_graph(
    graph: "EngagementGraph",
    audit,
    now: "datetime | None" = None,
    cap: int = MAX_TOKENS_PER_CAPTURE,
) -> list[TokenRecord]:
    """Capture JWTs from the evidence graph's observed-evidence nodes.

    Adds one ``jwt_token`` node per NEW token (idempotent: the
    fingerprint label dedupes against prior captures) and writes ONE
    audit event with counts only — never token bytes. Bounded: stops at
    ``cap`` new tokens; strings over :data:`MAX_TEXT_SCAN` are skipped
    and counted. A capture failure never kills the caller's state.
    """
    known = {n["label"] for n in graph.by_type("jwt_token")}
    found: list[TokenRecord] = []
    found_labels: set[str] = set()
    oversized = 0
    candidates = 0
    for node_type in SCAN_NODE_TYPES:
        for node in graph.by_type(node_type):
            texts = [node.get("label") or ""]
            texts.extend(_string_values(node.get("properties") or {}))
            for text in texts:
                if len(text) > MAX_TEXT_SCAN:
                    oversized += 1
                    continue
                for token in extract_jwt_candidates(text):
                    candidates += 1
                    fingerprint = _fingerprint(token)
                    if fingerprint in found_labels:
                        continue
                    found_labels.add(fingerprint)
                    found.append(TokenRecord(
                        token=token,
                        source_node_type=node_type,
                        source_node_id=node.get("id", ""),
                        fingerprint=fingerprint,
                    ))
    captured: list[TokenRecord] = []
    for record in found:
        if len(captured) >= cap:
            break
        if record.label in known:
            continue
        properties = {
            "token": record.token,
            "source_node_type": record.source_node_type,
            "source_node_id": record.source_node_id,
            "captured_at": utc_now_iso(),
            "classification": "observed_evidence_string",
            "verification": "not_verified",
            "untrusted": True,
            **inspect_token(record.token, now=now),
        }
        graph.add_node(
            node_type="jwt_token",
            label=record.label,
            properties=properties,
            provenance={
                "agent": "JWT_PRODUCER",
                "source_type": "tool",
                "source": record.source_node_type,
            },
        )
        captured.append(record)
    audit.write({
        "event": "jwt_tokens_captured",
        "candidates": candidates,
        "unique": len(found),
        "captured": len(captured),
        "already_known": len(found) - len(captured),
        "oversized_skipped": oversized,
    })
    return captured


def pick_captured_token(graph: "EngagementGraph") -> str | None:
    """The token for the jwt_tool lane: the FIRST captured one.

    Graph insertion order is deterministic (capture scans node types in
    a fixed order), so selection is deterministic. Selection heuristics
    (match token to asset host, freshest-iat) are deliberately NOT
    improvised here — they belong in reviewed code when a real need
    shows up.
    """
    nodes = graph.by_type("jwt_token")
    if not nodes:
        return None
    return nodes[0]["properties"].get("token") or None
