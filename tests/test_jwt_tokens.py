"""Wave 2b tests — the JWT token producer + offline analyzer.

The test-clock rule applies: staleness tests pin BOTH the token's
claims and the ``now`` passed to inspect/collect. Never a fixed now
against real utc_now_iso() stamps.
"""

import base64
import json
from datetime import datetime, timezone

import pytest

from kryonsec.purple.audit import AuditLog
from kryonsec.purple.jwt_tokens import (
    MAX_TOKENS_PER_CAPTURE,
    collect_tokens_from_graph,
    extract_jwt_candidates,
    inspect_token,
    is_jwt,
    pick_captured_token,
)
from kryonsec.purple.recon_passive import EngagementGraph

NOW = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
# epoch 1763284800 == 2026-11-16T12:00:00Z; boundaries move with NOW
STALE_EXP = 1_600_000_000        # 2020-09-13 — clearly in the past
FRESH_EXP = 1_893_456_000        # 2030-01-01 — clearly in the future


def _enc(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def _jwt(header=None, payload=None, signature="sig_" + "x" * 20) -> str:
    header = header if header is not None else {"alg": "HS256", "typ": "JWT"}
    payload = payload if payload is not None else {"sub": "1", "exp": FRESH_EXP}
    return f"{_enc(header)}.{_enc(payload)}.{signature}"


def _audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


def _events(audit):
    return [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8")
            if l.strip()]


# ---- shape + extraction ------------------------------------------------------

def test_is_jwt_accepts_a_real_token_and_rejects_lookalikes():
    assert is_jwt(_jwt())
    # three segments but garbage inside
    assert not is_jwt("eyJnotjson.eyJalsonot.sig")
    # header without an alg string
    assert not is_jwt(f"{_enc({'typ': 'JWT'})}.{_enc({'sub': '1'})}.sig")
    # two segments
    assert not is_jwt("eyJh.eyJi")
    # oversized 'token'
    assert not is_jwt(_jwt(signature="y" * 10_000))
    assert not is_jwt("")


def test_extract_jwt_candidates_filters_and_dedupes():
    token = _jwt()
    other = _jwt(payload={"sub": "2"})
    text = (f"login response: token={token}&next=/x; docs mention {other}; "
            f"lookalike eyJhbGciOi.kshape.sig is not decodable")
    assert extract_jwt_candidates(text) == [token, other]
    assert extract_jwt_candidates(f"{token} {token}") == [token]
    assert extract_jwt_candidates("") == []
    # a string over the scan bound contributes nothing (bounded work)
    assert extract_jwt_candidates(f"{token} " + "z" * 70_000) == []


def test_inspect_token_reads_claims_without_network():
    token = _jwt(payload={
        "sub": "admin", "iss": "target-corp.com", "exp": STALE_EXP,
        "iat": STALE_EXP - 100, "jti": "j-1",
    }, header={"alg": "HS256", "typ": "JWT", "kid": "k1"})
    out = inspect_token(token, now=NOW)  # claims + clock pinned together
    assert out["alg"] == "HS256"
    assert out["typ"] == "JWT"
    assert out["kid"] == "k1"
    assert out["iss"] == "target-corp.com"
    assert out["sub"] == "admin"
    assert out["jti"] == "j-1"
    assert out["exp_present"] is True and out["exp"].startswith("2020-")
    assert out["iat_present"] is True
    assert out["nbf_present"] is False
    assert any("stale" in n for n in out["notes"])


def test_inspect_token_fresh_and_never_expiring():
    fresh = inspect_token(_jwt(payload={"exp": FRESH_EXP}), now=NOW)
    assert any("fresh" in n for n in fresh["notes"])
    never = inspect_token(_jwt(payload={"sub": "1"}), now=NOW)
    assert never["exp_present"] is False
    assert any("no exp claim" in n for n in never["notes"])


def test_inspect_token_alg_none_and_nbf_future():
    none_alg = inspect_token(
        _jwt(header={"alg": "none"}), now=NOW)
    assert none_alg["alg"] == "none"
    assert any("no signature" in n for n in none_alg["notes"])
    nbf_future = inspect_token(
        _jwt(payload={"nbf": FRESH_EXP}), now=NOW)
    assert any("not-yet-valid" in n for n in nbf_future["notes"])


def test_inspect_token_rejects_non_epoch_time_claims():
    out = inspect_token(_jwt(payload={"exp": "not-a-number"}), now=NOW)
    assert out["exp_present"] is False


# ---- graph collection --------------------------------------------------------

def test_collect_captures_from_observed_evidence_nodes(tmp_path):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    token = _jwt()
    graph.add_node("api_observation", "http://target-corp.com/api", {
        "docs": f"example usage: Authorization: Bearer {token}",
        "untrusted": True,
    })
    captured = collect_tokens_from_graph(graph, audit, now=NOW)

    assert len(captured) == 1
    assert captured[0].token == token
    assert captured[0].source_node_type == "api_observation"
    nodes = graph.by_type("jwt_token")
    assert len(nodes) == 1
    node = nodes[0]
    assert node["label"].startswith("jwt:")  # fingerprint label, not the token
    assert node["properties"]["token"] == token
    assert node["properties"]["verification"] == "not_verified"
    assert node["properties"]["alg"] == "HS256"
    assert node["provenance"]["agent"] == "JWT_PRODUCER"
    # the audit event carries counts only — never token bytes
    raw = open(audit.path, encoding="utf-8").read()
    assert "jwt_tokens_captured" in _events(audit)
    assert token not in raw


def test_collect_is_idempotent_and_reports_already_known(tmp_path):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    graph.add_node("path", f"/login?token={_jwt()}", {})
    assert len(collect_tokens_from_graph(graph, audit, now=NOW)) == 1
    second = collect_tokens_from_graph(graph, audit, now=NOW)
    assert second == []
    assert len(graph.by_type("jwt_token")) == 1
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8")
              if l.strip()]
    known = [e for e in events if e["event"] == "jwt_tokens_captured"][-1]
    assert known["already_known"] == 1 and known["captured"] == 0


def test_collect_never_scans_llm_authored_nodes(tmp_path):
    """A token written into a HYPOTHESIS must not feed a tool: tokens
    come from observed evidence, never from prompt text."""
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    graph.add_node("hypothesis", "H1", {
        "title": "use this", "rationale": f"token {_jwt()}",
        "approved": True, "tools": ["jwt_tool"],
    })
    captured = collect_tokens_from_graph(graph, audit, now=NOW)
    assert captured == []
    assert graph.by_type("jwt_token") == []


def test_collect_caps_bounded_growth(tmp_path):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    tokens = [_jwt(payload={"sub": str(i)}) for i in range(MAX_TOKENS_PER_CAPTURE + 4)]
    graph.add_node("osint_note", "notes",
                   {"notes": " ".join(tokens)})
    captured = collect_tokens_from_graph(graph, audit, now=NOW)
    assert len(captured) == MAX_TOKENS_PER_CAPTURE
    assert len(graph.by_type("jwt_token")) == MAX_TOKENS_PER_CAPTURE


def test_collect_oversized_strings_are_skipped_and_counted(tmp_path):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    token = _jwt()
    graph.add_node("vuln_candidate", "v1",
                   {"finding": "z" * 70_000 + f" {token}"})
    graph.add_node("web_endpoint", "http://target-corp.com/",
                   {"title": f"page {token}"})
    captured = collect_tokens_from_graph(graph, audit, now=NOW)
    assert len(captured) == 1  # the endpoint's token; the oversized blob skipped
    events = [json.loads(l) for l in open(audit.path, encoding="utf-8")
              if l.strip()]
    event = [e for e in events if e["event"] == "jwt_tokens_captured"][-1]
    assert event["oversized_skipped"] == 1


def test_pick_captured_token_is_the_first_in_graph_order(tmp_path):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    first, second = _jwt(payload={"sub": "1"}), _jwt(payload={"sub": "2"})
    graph.add_node("path", f"/a?token={first}", {})
    graph.add_node("path", f"/b?token={second}", {})
    collect_tokens_from_graph(graph, audit, now=NOW)
    assert pick_captured_token(graph) == first


def test_pick_captured_token_none_when_empty():
    graph = EngagementGraph(engagement_id="e-j")
    assert pick_captured_token(graph) is None


def test_capture_failure_never_kills_the_caller(tmp_path):
    """A malformed node (unhashable/odd shapes) must not raise out of
    the capture pass — the state keeps running."""
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    node = graph.add_node("osint_note", "weird", {"notes": _jwt()})
    node["properties"] = None  # broken shape — tolerated, not fatal
    captured = collect_tokens_from_graph(graph, audit, now=NOW)
    assert captured == []


@pytest.mark.parametrize("bad", [
    None, 123, {"nested": {"deep": {"deeper": {"deepest": "x" * 3}}}},
])
def test_string_values_bounded_depth(tmp_path, bad):
    graph = EngagementGraph(engagement_id="e-j")
    audit = _audit(tmp_path)
    graph.add_node("osint_note", "n", {"a": bad})
    assert collect_tokens_from_graph(graph, audit, now=NOW) == []
