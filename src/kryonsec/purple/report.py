"""REPORT subagent (spec v2.1.1 §4.9).

Renders the engagement report with Jinja2, runs post-validation checks
(every finding/hypothesis appears, no duplicates), redacts secret-looking
strings, and writes report.md into the engagement directory.

Phase 6 additions: evidence normalizer (ANSI/whitespace/truncation),
hypothesis dedup, a pure-Python CVSS 3.1 base-score calculator, and the
enrichment/mapping sections in the rendered report.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import KryonsecConfig
from .audit import AuditLog
from .context import normalize_line
from .hypothesize import (
    MAX_ASSET_CHARS,
    MAX_RELATIONSHIP_CHARS,
    MAX_ROLE_CHARS,
    asset_key,
    related_asset_views,
)
# A14: whether a tool actually ran, and the one engine-derived block the
# report and the memory browser both render. `ok` on an exploit_attempt node
# is the sandbox's verdict on process creation, never on the security check,
# and a node exists for every tool EXPLOIT merely *tried* — so every claim
# below that testing happened is read from these, not from a node's
# existence.
from .views import (
    ATTEMPT_CONFIRMED,
    ATTEMPT_NOT_RUN,
    ATTEMPT_UNRECORDED,
    OUTCOMES_RUN,
    attempt_outcome,
    hypothesis_engine_view,
    verification_status,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOTES,
    VERIFICATION_NOT_RUN,
)
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)


# ---- evidence normalizer (tool expansion Phase 6) --------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def normalize_evidence(text: str, max_chars: int = 200) -> str:
    """Uniform evidence excerpt for the report: ANSI color codes stripped,
    whitespace collapsed, one truncation length. The raw tool output stays
    in the audit chain — this is only the report's view of it."""
    if not text:
        return ""
    cleaned = _ANSI_RE.sub("", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars].rstrip() + "…"
    return cleaned


# ---- CVSS 3.1 base score (tool expansion Phase 6) --------------------------
# Pure math from the CVSS v3.1 Specification, no new dependency. The vector
# comes from the HYPOTHESIZE LLM — an unparseable vector returns None, never
# a guessed score presented as a calculated one.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_SAME = {"N": 0.85, "L": 0.62, "H": 0.27}       # Scope Unchanged
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}     # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A rounding — round up to 1 decimal, with the
    intermediate value handled at 5-decimal precision (the official
    Roundup algorithm, ported)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10


def cvss_base_score(vector: str) -> float | None:
    """CVSS 3.1 base score from a vector string, e.g.
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (with or without the
    "CVSS:3.1/" prefix). None when the vector is missing or malformed."""
    if not vector:
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key.strip().upper()] = val.strip().upper()
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(m not in metrics for m in required):
        return None
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if metrics["S"] == "C" else _PR_SAME)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None  # unknown metric value — not a score we computed

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if metrics["S"] == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def cvss_severity(score: float | None) -> str:
    """Qualitative severity bucket for a base score (CVSS 3.1 §5)."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# ---- hypothesis dedup (tool expansion Phase 6; A12 equivalence) -------------
#
# A12: the merge used to key on (tool set, target asset) alone. The audit in
# docs/A12-DEDUP-AUDIT-2026-10-12.md demonstrated what that costs — a SQLi and
# a stored-XSS claim at one asset tested by one tool became one node, and the
# absorbed claim's title, rationale and A11 relationship were dropped with no
# copy anywhere. The identity is now an *equivalence*: same test AND same
# security meaning, and a merge that does happen keeps what it absorbed.

MAX_MERGED_TITLE_CHARS = 300
MAX_MERGED_RATIONALE_CHARS = 600
MAX_MERGED_ID_CHARS = 50

# Reading a hypothesis's security meaning out of its title. Keyword-based and
# deliberately small: it can only ever say "these two name different classes"
# or "one of them names nothing the table knows". It never says "these two are
# the same" — a table hit is not evidence of equivalence, only of *which*
# class a title mentions.
#
# A15/D6: "unknown" is a verdict about the title, not about the claim, so it
# can no longer be merged across. Before this, "Log4Shell in the artist
# parameter" (no table hit) merged into "SQL injection in the artist
# parameter" (a hit) — the report then presented one SQLi item where the model
# had claimed two different kinds of issue, and the class it kept was the one
# the *other* hypothesis named. Two unknowns may still merge: that is legacy
# wording with no title at all, and "we cannot read either title" is not a
# disagreement.
# ponytail: table lookup, not a classifier — add a tuple when a class shows up
# twice in real reports and the two keep colliding.
_VULN_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sqli", "sql injection", "sql-injection")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("ssrf", ("ssrf", "server-side request forgery")),
    ("lfi", ("lfi", "local file inclusion", "path traversal",
             "directory traversal", "traversal")),
    ("rce", ("rce", "remote code execution", "command injection",
             "os command")),
    ("xxe", ("xxe", "xml external entity")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("idor", ("idor", "insecure direct object")),
    ("ssti", ("ssti", "template injection")),
    ("open_redirect", ("open redirect", "open-redirect")),
    ("access_control", ("auth bypass", "authentication bypass",
                        "access control", "authorization bypass")),
    ("deserialization", ("deseriali",)),
    ("file_upload", ("file upload", "unrestricted upload")),
)
_CLASS_UNKNOWN = "unknown"


def _vuln_class(title: object) -> str:
    """Which vulnerability class a title names, or ``unknown``.

    ``unknown`` covers every way a title can fail to name exactly one class:
    it is missing, blank or not a string; it names nothing in the table; or it
    names more than one (``"SQL injection leading to RCE"`` is not evidence
    that its proposer meant the same issue as a plain RCE claim). None of
    those is a class, so none of them may be merged against one.
    """
    low = (normalize_line(title, MAX_MERGED_TITLE_CHARS) or "").lower()
    named = {name for name, needles in _VULN_CLASSES
             if any(needle in low for needle in needles)}
    return named.pop() if len(named) == 1 else _CLASS_UNKNOWN


def _claim_asset_keys(node: dict) -> frozenset[str]:
    """The :func:`asset_key` identity of every asset a hypothesis's A11 claim
    names. Same normalisation the render view uses, so what the engine calls
    "the same asset claim" and what the reader sees cannot disagree."""
    properties = node.get("properties") or {}
    if not isinstance(properties, dict):
        return frozenset()
    raw = properties.get("related_assets")
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    keys: set[str] = set()
    for entry in raw:
        if isinstance(entry, str):
            entry = {"asset": entry}
        if not isinstance(entry, dict):
            continue
        key = asset_key(entry.get("asset"))
        if key:
            keys.add(key)
    return frozenset(keys)


def _test_key(node: dict) -> tuple:
    """*Which test* this hypothesis proposes: the tool set and the asset the
    test would act on. Unchanged from Phase 6 — a model re-proposing one test
    across passes will not phrase it identically, so the proposal text cannot
    be part of the identity without disabling dedup entirely."""
    properties = node.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    return (
        tuple(sorted(str(t) for t in properties.get("tools") or [])),
        str(properties.get("target_asset", "")),
    )


def _apart_reason(left: dict, right: dict) -> str:
    """Why these two hypotheses must stay two — ``""`` when they may merge.

    The single source of truth for the merge relation: :func:`mergeable` is
    this returning nothing, and the audit chain records the reason string, so
    the graph explains its own outcome instead of just recording it. Every
    term answers a collision the A12 audit reproduced on the old key.
    """
    if _test_key(left) != _test_key(right):
        return "different tool set or target asset"
    tools, asset = _test_key(left)
    if not tools and not str(asset).strip():
        return "no tool and no asset — nothing identifies the test"
    lclass, rclass = _vuln_class(_props(left).get("title")), _vuln_class(
        _props(right).get("title"))
    if lclass != rclass:
        if _CLASS_UNKNOWN in (lclass, rclass):
            # A15/D6: one side names a class and the other names none. A merge
            # here adopts the known side's class for a claim that never named
            # it — the report would list one kind of issue where the model
            # claimed two, so the unreadable title wins nothing and loses
            # nothing by staying its own item.
            return (f"vulnerability class unclear on one side "
                    f"({lclass} vs {rclass})")
        return f"different vulnerability class ({lclass} vs {rclass})"
    lkeys, rkeys = _claim_asset_keys(left), _claim_asset_keys(right)
    if lkeys and rkeys and lkeys != rkeys:
        return "different related-asset claims"
    if bool(_props(left).get("approved")) != bool(_props(right).get("approved")):
        return "different review decisions"
    return ""


def _props(node: dict) -> dict:
    properties = node.get("properties")
    return properties if isinstance(properties, dict) else {}


def mergeable(left: dict, right: dict) -> bool:
    """Whether ``right`` is the same claim as ``left`` and may be merged in.

    An absent *asset* claim conflicts with nothing: a legacy hypothesis (no
    ``related_assets``, no ``relationship``, no ``approved``) and a
    single-asset one stay mergeable in either direction, which is what keeps
    legacy graphs behaving as they always did. A title is the one field where
    silence is not agreement — see :func:`_apart_reason`.
    """
    return not _apart_reason(left, right)


def merged_claim_record(node: dict) -> dict:
    """The absorbed hypothesis's own claim, bounded and single-lined.

    Kept on the survivor so a merge loses nothing: before A12 the victim's
    title, rationale and relationship existed nowhere in ``properties`` after
    the merge. Normalised on the way in, and again on the way out
    (:func:`merged_claim_views`), so no stored value can add a line to the
    report.
    """
    properties = _props(node)
    raw = properties.get("related_assets")
    refs: list[dict] = []
    if isinstance(raw, (list, tuple)):
        for entry in raw:
            if isinstance(entry, str):
                entry = {"asset": entry}
            if not isinstance(entry, dict):
                continue
            refs.append({
                "asset": normalize_line(entry.get("asset"), MAX_ASSET_CHARS) or "",
                "role": normalize_line(entry.get("role"), MAX_ROLE_CHARS) or "",
            })
    return {
        "id": normalize_line(node.get("label"), MAX_MERGED_ID_CHARS) or "",
        "title": normalize_line(
            properties.get("title"), MAX_MERGED_TITLE_CHARS) or "",
        "rationale": normalize_line(
            properties.get("rationale"), MAX_MERGED_RATIONALE_CHARS) or "",
        "relationship": normalize_line(
            properties.get("relationship"), MAX_RELATIONSHIP_CHARS) or "",
        "related_assets": refs,
    }


def merged_claim_views(props: dict, graph: EngagementGraph) -> list[dict]:
    """The report's view of the claims a merge folded into a hypothesis.

    Re-normalised from the stored record for the same reason
    :func:`related_asset_views` re-normalises: a value that reached the graph
    by some other route must not be able to add a line to the report.
    """
    raw = props.get("merged_claims")
    if not isinstance(raw, (list, tuple)):
        return []
    views: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        views.append({
            "id": normalize_line(entry.get("id"), MAX_MERGED_ID_CHARS) or "?",
            "title": normalize_line(
                entry.get("title"), MAX_MERGED_TITLE_CHARS) or "",
            "rationale": normalize_line(
                entry.get("rationale"), MAX_MERGED_RATIONALE_CHARS) or "",
            "relationship": normalize_line(
                entry.get("relationship"), MAX_RELATIONSHIP_CHARS) or "",
            "related_assets": related_asset_views(
                {"properties": entry}, graph),
        })
    return views


def _absorb(canonical: dict, node: dict) -> None:
    """Fold a mergeable twin into the canonical node.

    The strongest of each *evidence* field wins, as before. The absorbed
    claim's own text is kept in ``merged_claims`` (with the legacy
    ``merged_from`` label list alongside it). Nothing that carries standing
    is written here — ``approved``, ``related_assets``, ``relationship`` and
    the basis ladder are left exactly as they were, so a merge can never move
    what the engagement said about a hypothesis.
    """
    props = _props(node)
    fprops = canonical.setdefault("properties", {})
    if (props.get("confidence") or 0) > (fprops.get("confidence") or 0):
        fprops["confidence"] = props["confidence"]
    if not fprops.get("cve") and props.get("cve"):
        fprops["cve"] = props["cve"]
    if (props.get("cvss_vector") or "") and not fprops.get("cvss_vector"):
        fprops["cvss_vector"] = props["cvss_vector"]
    if "enrichment" in props and "enrichment" not in fprops:
        fprops["enrichment"] = props["enrichment"]
    fprops.setdefault("merged_from", []).append(node["label"])
    fprops.setdefault("merged_claims", []).append(merged_claim_record(node))


def hypothesis_relations(
    nodes: list[dict],
) -> tuple[dict[str, str], list[dict]]:
    """Classify hypothesis nodes in insertion order: ``(aliases, kept_apart)``.

    ``aliases`` maps a duplicate's label to the earlier node it is the same
    claim as; ``kept_apart`` records the same-test pairs that were *not*
    merged, with the reason (:func:`_apart_reason`). Pure — it reads and
    returns, it never touches the graph or the chain.

    The one place this pass is walked. :func:`dedup_hypotheses` acts on the
    result in REPORT, and the BLUE_TEAM prompt — which runs before any merge —
    describes it to the model, so the two surfaces cannot come to different
    conclusions about the same pair (A15/D3).
    """
    canonicals: list[dict] = []
    aliases: dict[str, str] = {}
    kept_apart: list[dict] = []

    for node in nodes:
        first = next((c for c in canonicals if mergeable(c, node)), None)
        if first is not None:
            aliases[node["label"]] = first["label"]
            continue
        # explainability: if an earlier hypothesis proposed the same test and
        # we chose not to merge, say why, on the chain
        for c in canonicals:
            if _test_key(c) == _test_key(node):
                kept_apart.append({
                    "kept": node["label"],
                    "apart_from": c["label"],
                    "reason": _apart_reason(c, node)[:120],
                })
        canonicals.append(node)
    return aliases, kept_apart


def dedup_hypotheses(graph: EngagementGraph, audit: AuditLog) -> int:
    """Merge hypotheses that propose the same test *and* the same claim —
    the LLM regularly re-suggests the same test twice. Two hypotheses that
    differ in vulnerability class, related-asset claim, or the operator's
    decision stay two nodes (A12: see :func:`_apart_reason`; A15: so does a
    title that names no class the table knows, when the other names one).

    The first mergeable occurrence becomes canonical; duplicates are merged
    into it rather than dropped, so the relationships the duplicate had
    already observed (``tests``, ``produced``, …) move to the canonical
    hypothesis instead of disappearing with it, and the duplicate's own claim
    is kept in ``merged_claims``. Every node that points at a merged id
    (remediation, finding, verify_attempt, exploit_attempt "H2:tool" labels)
    is remapped to the canonical one so the report joins stay correct.
    Returns the number merged.

    Deterministic: nodes are visited in insertion order and the first
    mergeable canonical wins, so the same graph always merges the same way.
    """
    nodes = list(graph.by_type("hypothesis"))
    aliases, kept_apart = hypothesis_relations(nodes)

    if aliases:
        by_label = {n["label"]: n for n in nodes}
        # insertion order, so the merge work happens in the order the graph
        # was written — same sequence as the classification above
        for label, canonical_label in aliases.items():
            canonical, node = by_label[canonical_label], by_label[label]
            _absorb(canonical, node)
            # merge_node, not remove_node: whatever the duplicate was already
            # related to follows it into the canonical hypothesis.
            graph.merge_node(node, canonical)

        for node in graph.nodes:
            ntype, label = node["node_type"], node["label"]
            if ntype in ("remediation", "finding", "verify_attempt"):
                if label in aliases:
                    node["label"] = aliases[label]
            elif ntype == "exploit_attempt" and ":" in label:
                hyp_id, rest = label.split(":", 1)
                if hyp_id in aliases:
                    node["label"] = f"{aliases[hyp_id]}:{rest}"

    if aliases:
        audit.write({
            "event": "hypotheses_merged",
            "merged": len(aliases),
            "aliases": aliases,
            "kept_apart": kept_apart[:50],
        })
    elif kept_apart:
        # same test proposed more than once, deliberately left as separate
        # nodes — worth a chain entry of its own so the outcome is explained
        audit.write({
            "event": "hypotheses_kept_apart",
            "kept_apart": kept_apart[:50],
        })
    return len(aliases)


def _normalize_enrichment(e: dict) -> dict:
    """Fixed-shape enrichment view for the template — StrictUndefined must
    never trip on a key a failed lookup did not fill."""
    return {
        "cve": e.get("cve", ""),
        "cvss_score": e.get("cvss_score"),  # from NVD; None = unknown
        "severity": e.get("severity", ""),
        "kev": e.get("kev"),  # True/False/None (unknown — lookup failed)
        "epss": e.get("epss"),
        "epss_percentile": e.get("epss_percentile"),
        "cpes": e.get("cpes") or [],
        "cwes": e.get("cwes") or [],  # Phase 8: from the NVD record
        "exploits": e.get("exploits") or [],
        "exploit_available": bool(e.get("exploit_available")),
        # Phase 8 lookups (each empty when the fetch failed or found nothing)
        "osv_aliases": e.get("osv_aliases") or [],
        "osv_severity": e.get("osv_severity", ""),
        "affected_packages": e.get("affected_packages") or [],
        "ghsa_id": e.get("ghsa_id", ""),
        "ghsa_severity": e.get("ghsa_severity", ""),
        "patched_versions": e.get("patched_versions") or [],
        "nuclei_templates": e.get("nuclei_templates") or [],
    }


def redact_secrets(text: str) -> str:
    """Replace secret-looking strings with placeholders (§4.9).

    Delegates to the shared detector (secrets.py) so the pattern list can
    never drift from the one the LLM gates use — the report is the
    artifact most likely to be shared, and a private copy here was
    already missing AWS keys, GitHub tokens and connection strings that
    detect_secrets catches. Passwords/keys keep their label; only the
    value is replaced («SECRET_n»)."""
    from ..secrets import redact

    return redact(text)[0]


def build_timeline(audit: AuditLog) -> list[dict]:
    """Phase 8: engagement timeline from the audit chain — one row per
    milestone event (engagement_created, state_enter, report_written),
    (timestamp, event, detail). The chain's hash order (not the wall
    clock) remains the ordering guarantee; ts is presentation only."""
    milestones = []
    for entry in read_audit_events(audit):
        event = entry.get("event", "")
        ts = str(entry.get("ts", ""))
        if event in ("engagement_created", "state_enter", "report_written"):
            detail = (entry.get("state") or entry.get("target")
                      or entry.get("engagement_id") or "")
            milestones.append(
                {"ts": ts, "event": event, "detail": detail})
    return milestones[:100]  # bounded


def read_audit_events(audit: AuditLog) -> list[dict]:
    """Every parseable audit entry, in chain order. Corrupt lines are
    skipped (verify() reports corruption; the report renders anyway)."""
    events: list[dict] = []
    try:
        with open(audit.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return events


# ---- Phase 1C: coverage, post-exploit honesty, limitations ------------------

MAX_COVERAGE_ITEMS = 50
#: 1.1 adds ``failed_states``: a route that reached HALT with a stage that
#: returned ``failed`` must not look like a clean sweep to a JSON reader.
REPORT_JSON_SCHEMA_VERSION = "1.1"


def coverage_summary(graph: EngagementGraph, audit: AuditLog) -> dict:
    """What the engagement actually covered — from execution and
    verification records only.

    Machine-observed activity (tool runs that really started) is read
    side by side with what the model claimed, and every bucket can be
    empty: absent from a list is **unassessed**, never "checked clean".
    """
    from .views import ATTEMPT_INCONCLUSIVE, exploit_status

    hypotheses = graph.by_type("hypothesis")
    attempts = graph.by_type("exploit_attempt")
    finding_labels = {f["label"] for f in graph.by_type("finding")}
    attempts_by_hyp: dict[str, list] = {}
    for a in attempts:
        attempts_by_hyp.setdefault(str(a["label"]).split(":", 1)[0],
                                   []).append(a)

    tested_surfaces: list[str] = []
    confirmed: list[str] = []
    tested_unconfirmed: list[str] = []
    incomplete: list[str] = []
    unassessed: list[str] = []
    unclear: list[str] = []
    blocked: list[dict] = []
    for h in hypotheses:
        label = h["label"]
        runs = attempts_by_hyp.get(label, [])
        outcomes = [attempt_outcome(a) for a in runs]
        if any(o in OUTCOMES_RUN for o in outcomes):
            asset = str((h.get("properties") or {}).get("target_asset")
                        or "").strip()
            if asset:
                tested_surfaces.append(asset)
            status = exploit_status(label, graph)
            if status == ATTEMPT_CONFIRMED and label in finding_labels:
                confirmed.append(label)
            elif status == ATTEMPT_CONFIRMED or ATTEMPT_INCONCLUSIVE in outcomes:
                # a completed check exists: at least one attempt ran to
                # its own exit (or the tool answered but its finding
                # record is missing) — neither is "did not finish"
                tested_unconfirmed.append(label)
            else:
                # every run that started was interrupted: the target was
                # touched, but no check reached a conclusion. Reporting
                # this as "tested but not confirmed" would read as a
                # clean negative the records do not support.
                incomplete.append(label)
        elif runs:
            for a in runs:
                if attempt_outcome(a) == ATTEMPT_NOT_RUN:
                    blocked.append({
                        "item": a["label"],
                        "reason": normalize_evidence(
                            a["properties"].get("error_excerpt", ""), 160),
                    })
                else:
                    unclear.append(a["label"])
        else:
            unassessed.append(label)

    verify_unresolved = [
        n["label"] for n in graph.by_type("verify_attempt")
        if verification_status(n) == VERIFICATION_INCONCLUSIVE
    ]

    events = read_audit_events(audit)
    out_of_scope = sum(
        1 for e in events
        if e.get("event") == "exploit_scope_refused"
        or (e.get("event") == "verify_skipped"
            and "scope" in str(e.get("reason", ""))))
    never_started = sum(
        1 for a in attempts if attempt_outcome(a) == ATTEMPT_NOT_RUN)

    return {
        "tested_surfaces": sorted(set(tested_surfaces))[:MAX_COVERAGE_ITEMS],
        "confirmed_findings": sorted(confirmed)[:MAX_COVERAGE_ITEMS],
        "tested_unconfirmed": sorted(tested_unconfirmed)[:MAX_COVERAGE_ITEMS],
        "started_not_finished": sorted(incomplete)[:MAX_COVERAGE_ITEMS],
        "unresolved": sorted(set(unclear + verify_unresolved))[:MAX_COVERAGE_ITEMS],
        "skipped_or_blocked": blocked[:MAX_COVERAGE_ITEMS],
        "out_of_scope_refused": out_of_scope,
        "unassessed": sorted(unassessed)[:MAX_COVERAGE_ITEMS],
        # model claims vs machine-observed activity, side by side.
        # ``items_with_run`` counts HYPOTHESES a tool really ran for;
        # ``machine_observed_runs`` counts the runs themselves. One
        # hypothesis may have several attempts, so the run count can be
        # greater — the report says both instead of "N of them" over a
        # number that could exceed the item count.
        "model_claims": len(hypotheses),
        "items_with_run": (
            len(confirmed) + len(tested_unconfirmed) + len(incomplete)),
        "machine_observed_runs": sum(
            1 for a in attempts if attempt_outcome(a) in OUTCOMES_RUN),
        "tool_runs_never_started": never_started,
    }


def post_exploit_view(graph: EngagementGraph) -> dict:
    """The report's post-exploitation view. It may claim post-exploit
    activity only when genuine authorized records exist — an APPROVED
    capability record that is ALSO independently verified, plus evidence
    nodes the phase produced. An empty parser registry means no
    capability can ever be claimed, so this is dormant by construction.
    """
    from .capability import CapabilityRecord

    records = []
    for node in graph.by_type("capability"):
        try:
            records.append(CapabilityRecord.model_validate(node["properties"]))
        except Exception:
            continue  # malformed record: the honest line is "nothing genuine"
    if not records:
        return {
            "authorized": False,
            "note": ("No post-exploitation was performed: no shell/session "
                     "capability was ever claimed (no tool in the inventory "
                     "provides independently verifiable capability evidence)."),
        }
    if not any(r.status == "approved" and r.verification == "verified"
               for r in records):
        return {
            "authorized": False,
            "note": ("A capability record exists, but it was never both "
                     "independently verified and human-approved — "
                     "post-exploitation never ran."),
        }
    evidence_nodes = graph.by_type("post_exploit_evidence")
    if not evidence_nodes:
        return {
            "authorized": False,
            "note": ("Capability evidence was verified and approved, but the "
                     "post-exploitation phase never ran."),
        }
    primary = next(
        (r for r in records
         if r.status == "approved" and r.verification == "verified"))
    evidence = []
    for n in evidence_nodes[:MAX_COVERAGE_ITEMS]:
        entry = {
            "tool": n["label"],
            "ok": bool(n["properties"].get("ok")),
            "stdout_chars": int(n["properties"].get("stdout_chars") or 0),
        }
        if "summary" in n["properties"]:
            entry["summary"] = redact_secrets(
                normalize_evidence(json.dumps(n["properties"]["summary"]),
                                   max_chars=800))
        elif "excerpt" in n["properties"]:
            entry["excerpt"] = redact_secrets(
                normalize_evidence(str(n["properties"]["excerpt"]),
                                   max_chars=400))
        evidence.append(entry)
    return {
        "authorized": True,
        "capability": primary.capability,
        "tool": primary.tool,
        "target_host": primary.target_host,
        "records": len(records),
        "evidence": evidence,
    }


def report_limitations(graph: EngagementGraph, audit: AuditLog) -> list[str]:
    """Execution and verification limitations, derived from records —
    including the egress state actually observed in the audit chain
    (never claimed resolved without the boundary events to prove it)."""
    # Phase 1E: the network-layer egress state is READ from the audit
    # chain, not asserted. Without `egress_policy_established` in this
    # engagement's chain the old default-bridge wording stays.
    established = any(
        entry.get("event") == "egress_policy_established"
        for entry in read_audit_events(audit))
    if established:
        limitations = [
            "Network egress from the execution sandbox was restricted by a "
            "host-layer allow-only firewall (DOCKER-USER chain) at the time "
            "of execution; DNS queries to the pinned resolvers could still "
            "carry exfiltration in query names — the boundary does not "
            "inspect DNS payloads.",
        ]
    else:
        limitations = [
            "Network egress from the execution sandbox is not restricted to "
            "the target scope at the network layer (default docker bridge); "
            "target scope is enforced by command-line validation only.",
        ]
    from .capability import CAPABILITY_PARSERS
    if CAPABILITY_PARSERS == {}:
        limitations.append(
            "The capability parser registry is empty: no shell/session "
            "capability can be claimed, and post-exploitation stays dormant.")
    coverage = coverage_summary(graph, audit)
    never_started = coverage["tool_runs_never_started"]
    if never_started:
        limitations.append(
            f"{never_started} exploit tool run(s) never started (sandbox or "
            "allowlist refusal): nothing was checked by them.")
    blocked_checks = sum(
        1 for n in graph.by_type("verify_attempt")
        if verification_status(n) == VERIFICATION_NOT_RUN)
    if blocked_checks:
        limitations.append(
            f"{blocked_checks} independent verification check(s) never ran; "
            "those findings are unverified, not disproven.")
    return limitations[:10]


# ---- Phase 1C: machine-readable report.json ---------------------------------

def build_report_json(
    graph: EngagementGraph,
    audit: AuditLog,
    engagement_id: str,
    completed_states: list[str] | None = None,
    halt_reason: str | None = None,
    failed_states: list[str] | None = None,
) -> str:
    """The deterministic machine-readable export, one document for the
    same graph + audit chain (no wall-clock data, sorted keys, no
    whitespace). Every free-text field is bounded and secret-redacted;
    post-exploitation content appears only from genuine authorized
    records; failures of any single section must not produce a broken
    document — a malformed section is omitted and the more general
    values stand."""
    from .views import exploit_status

    attempts = graph.by_type("exploit_attempt")
    attempt_by_label = {a["label"]: a for a in attempts}
    rows = []

    def attempt_row(a: dict) -> dict:
        props = a.get("properties") or {}
        argv = [str(x) for x in (props.get("argv") or [])]
        return {
            "id": a["id"],
            "label": a["label"],
            "tool": str(props.get("tool", "")),
            "outcome": attempt_outcome(a),
            "exit_code": props.get("exit_code"),
            "argv": [redact_secrets(a_[:120]) for a_ in argv[:64]],
            "output_excerpt": redact_secrets(
                normalize_evidence(str(props.get("output_excerpt", "")),
                                   max_chars=300)),
            "not_run_reason": redact_secrets(
                normalize_evidence(str(props.get("error_excerpt", "")),
                                   max_chars=160)),
            "retried_https": bool(props.get("retried_https")),
        }

    summary_counts = {"verified": 0, "disagreed": 0, "inconclusive": 0,
                      "not_run": 0}
    findings = []
    for h in graph.by_type("hypothesis"):
        props = h.get("properties") or {}
        view = hypothesis_engine_view(h, graph)
        status = view["verification_status"]
        summary_counts[status] = summary_counts.get(status, 0) + 1
        # provenance: stable node ids via the lineage registry
        tested_by = sorted(
            (graph.get_node(e["target_node_id"]) or {}).get("label", "")
            for e in graph.find_edges("tested_by", source=h["id"]))
        finding = next((n for n in graph.by_type("finding")
                        if n["label"] == h["label"]), None)
        verified_by = []
        if finding is not None:
            verified_by = sorted(
                (graph.get_node(e["target_node_id"]) or {}).get("label", "")
                for e in graph.find_edges("verified_by", source=finding["id"]))
        verify_reasons = [
            {
                "attempt": n["label"], "status": verification_status(n),
                "reason": (redact_secrets(normalize_evidence(
                    str((n.get("properties") or {}).get("reason", "")),
                    160))),
            }
            for n in graph.by_type("verify_attempt")
            if n["label"] == h["label"]
        ]
        score = cvss_base_score(str(props.get("cvss_vector", "")))
        if score is None:
            score = (props.get("enrichment") or {}).get("cvss_score")
        findings.append({
            "id": h["label"],
            "title": redact_secrets(normalize_line(
                props.get("title"), 300) or ""),
            "target_asset": str(props.get("target_asset", "")),
            "tools": [str(t) for t in (props.get("tools") or [])][:16],
            "approval": "approved" if props.get("approved") else "not_approved",
            "confirmed_by_tool": bool(h["label"] in
                                      {f["label"] for f
                                       in graph.by_type("finding")}),
            "cvss": {
                "vector": str(props.get("cvss_vector", "")),
                "score": score,
                "qualitative": cvss_severity(score),
            },
            "verification": {
                "status": status,
                "note": VERIFICATION_NOTES[status],
                "block_reasons": verify_reasons,
            },
            "provenance": {
                "hypothesis_id": h["id"],
                "exploit_attempts": tested_by,
                "verified_by": verified_by,
            },
        })

    verify_attempts = []
    for n in graph.by_type("verify_attempt"):
        props = n.get("properties") or {}
        verify_attempts.append({
            "id": n["id"],
            "label": n["label"],
            "status": verification_status(n),
            "method": str(props.get("method", "")),
            "verified": bool(props.get("verified")),
            "reason": redact_secrets(normalize_evidence(
                str(props.get("reason", "")), 160)),
        })

    attempts_out = [attempt_row(a) for a in attempts[:200]]
    coverage = coverage_summary(graph, audit)

    payload = {
        "schema_version": REPORT_JSON_SCHEMA_VERSION,
        "engagement_id": engagement_id,
        "target": graph.by_type("target")[0]["label"]
        if graph.by_type("target") else "",
        "summary": {
            "findings": len(findings),
            "verification_statuses": summary_counts,
            "model_claims": coverage["model_claims"],
            "machine_observed_runs": coverage["machine_observed_runs"],
            "post_exploit_authorized":
                post_exploit_view(graph)["authorized"],
        },
        "coverage": coverage,
        "findings": findings,
        "exploit_attempts": attempts_out,
        "verification_attempts": verify_attempts,
        "post_exploit": post_exploit_view(graph),
        "limitations": report_limitations(graph, audit),
        "completed_states": list(completed_states or []),
        "failed_states": list(failed_states or []),
        "halt_reason": halt_reason or "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)


def write_report_json(payload: str, path: Path) -> None:
    """Atomic write: the .tmp file is created, fully written, fsynced
    and then renamed over the destination — a crash mid-write can leave
    a .tmp behind, never a truncated report.json."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
        f.flush()
        import os as _os
        _os.fsync(f.fileno())
    tmp.replace(path)


def remediation_reference(label: object, graph: EngagementGraph) -> dict:
    """Whether a remediation's target id names something in this engagement.

    The id is free text from the model (``blue_team.Remediation.hypothesis_id``)
    and has never been a foreign key: nothing writes it, nothing resolves it,
    and the report printed a fix section for it regardless — a reader got
    "### Fix for H7" in a document where H7 appears nowhere else (A13 D5).

    Resolved against the two kinds of node the prompt actually lets the model
    name: a hypothesis, or a code-scanner finding by its tool name (the prompt
    says so — "use the scanner tool name as hypothesis_id, e.g. semgrep").

    Zero matches is a dangling reference. More than one is ambiguous: the id
    names a hypothesis *and* a scanner, and nothing in the record says which
    was meant, so claiming either would be a guess. Findings are not consulted
    — they are labelled with a hypothesis id, so counting them would make
    every ordinary reference ambiguous.
    """
    id_text = normalize_line(label, MAX_MERGED_ID_CHARS) or ""
    if not id_text:
        return {"resolved": False,
                "reference_note": "the assistant gave this fix no issue id"}
    matched = {
        node.get("node_type") for node in graph.nodes
        if node.get("label") == id_text
        and node.get("node_type") in ("hypothesis", "scanner_result")
    }
    if not matched:
        return {
            "resolved": False,
            "reference_note": (
                f"nothing in this engagement is recorded under the name "
                f"{id_text!r} — the assistant named an issue that is not in "
                "this report, so this is general advice, not a fix for "
                "something found here"
            ),
        }
    if len(matched) > 1:
        return {
            "resolved": False,
            "reference_note": (
                f"{id_text!r} names both an issue and a code scan in this "
                "engagement, and the record does not say which this fix is "
                "for"
            ),
        }
    return {"resolved": True, "reference_note": ""}


def render_report(
    graph: EngagementGraph,
    audit: AuditLog,
    engagement_id: str,
    completed_states: list[str] | None = None,
    halt_reason: str | None = None,
    failed_states: list[str] | None = None,
) -> str:
    """Render the report markdown from the engagement graph."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
    )
    template = env.get_template("report.jinja")

    target_nodes = graph.by_type("target")
    import datetime as _dt

    # map hypothesis -> its tool-run outcome (exploit_attempt nodes are
    # labeled "H1:sqlmap"). A node is written for every tool EXPLOIT *tries*,
    # so the node set says what was attempted; only its recorded outcome says
    # what actually ran (A13 D1).
    attempts = graph.by_type("exploit_attempt")
    outcomes = {a["label"]: attempt_outcome(a) for a in attempts}
    # "Tools were run" is a claim about the target, so it is true only when at
    # least one tool really ran. `attempted` is the weaker fact — something
    # was tried — and the template has its own branch for it, because a
    # sandbox that never started must read as "nothing was checked", never as
    # "we checked and found nothing".
    exploit_ran = any(o in OUTCOMES_RUN for o in outcomes.values())
    exploit_attempted = bool(attempts)
    # a finding is "verified" when VERIFY's independent probe agreed
    verified_ids = {
        n["label"] for n in graph.by_type("verify_attempt")
        if n["properties"].get("verified")
    }

    # Phase 6: enrichment + numeric CVSS score + normalized evidence per
    # hypothesis; the template renders them as the "Known risk data" rows
    #
    # A14: defaults first, the node's own properties over them. A node written
    # before a field existed (or a hand-built one) has to render — StrictUndefined
    # turns a missing key into a crash, and the report is the only deliverable.
    # Same reason the remediation rows below carry their own .get defaults.
    blank = {"title": "", "target_asset": "", "cvss_vector": "", "rationale": "",
             "tools": [], "confidence": 0.0}
    hypotheses = []
    for n in graph.by_type("hypothesis"):
        props = {**blank, **n["properties"]}
        score = cvss_base_score(props.get("cvss_vector", ""))
        if score is None:
            # NVD's own score (vector missing/unparseable) — still labeled
            # as data we looked up, not something we computed
            score = (props.get("enrichment") or {}).get("cvss_score")
        # A11: the multi-asset claim, re-derived here rather than read from
        # the node. `related_asset_views` normalises the stored text again
        # (so no graph value can add a line to the report) and decides
        # observed/not; `relationship_basis` is the engine's own verdict on
        # the claim — the model's own word is never consulted.
        #
        # A14: the whole engine-derived block comes from one function the
        # memory browser renders too (A13 D4 — two surfaces, one graph, one
        # answer), and it is merged in *after* `**props` so a model that
        # wrote `basis`/`tested`/`confirmed` into its own properties cannot
        # override what the engine recorded. `approved` is set before EXPLOIT
        # runs, so it is not evidence that a test happened and is not used
        # for any execution claim.
        hypotheses.append({
            "id": n["label"],
            **props,
            "approved": bool(props.get("approved")),
            **hypothesis_engine_view(n, graph),
            "verified": n["label"] in verified_ids,
            "cvss_score": score,
            "cvss_qual": cvss_severity(score),
            "enrichment": _normalize_enrichment(
                (props.get("enrichment") or {})),
            "relationship": normalize_line(
                props.get("relationship"), MAX_RELATIONSHIP_CHARS) or "",
            # A12: what the merge folded in, so the report can say it
            "merged_claims": merged_claim_views(props, graph),
        })

    # Phase 6: uniform evidence excerpts (ANSI/whitespace/length) on the
    # repeatable-steps section — raw output stays in the audit chain
    norm_attempts = []
    for a in attempts:
        norm_attempts.append({
            "label": a["label"],
            "properties": {
                **a["properties"],
                "output_excerpt": normalize_evidence(
                    a["properties"].get("output_excerpt", "")),
                "argv": a["properties"].get("argv", []),
                # A14: what this one attempt recorded about its own run, so
                # the per-tool lines cannot say "it checked" about a process
                # that never started. The reason a tool did not run is worth
                # showing — it is the difference between a broken sandbox and
                # a tool that is simply not installed.
                "outcome": outcomes[a["label"]],
                "not_run_reason": normalize_evidence(
                    a["properties"].get("error_excerpt", ""), max_chars=160),
            },
        })

    # Phase 8: scanner evidence rows + an SBOM summary when syft ran
    scanners = [
        {
            "label": n["label"],
            "exit_code": n["properties"].get("exit_code", "?"),
            "findings_count": n["properties"].get("findings_count"),
            "excerpt": normalize_evidence(
                n["properties"].get("excerpt", ""), max_chars=300),
        }
        for n in graph.by_type("scanner_result")
    ]
    sbom_summary = ""
    syft_nodes = [n for n in graph.by_type("scanner_result")
                  if n["label"] == "syft"]
    if syft_nodes and syft_nodes[0]["properties"].get("packages_count"):
        sbom_summary = (
            f"SBOM: {syft_nodes[0]['properties']['packages_count']} "
            "packages identified (syft)")

    return template.render(
        engagement_id=engagement_id,
        target=target_nodes[0]["label"] if target_nodes else "(none)",
        subdomains=sorted(n["label"] for n in graph.by_type("subdomain")),
        paths=sorted(n["label"] for n in graph.by_type("path"))[:50],
        hypotheses=hypotheses,
        attempts=norm_attempts,
        scanners=scanners,
        sbom_summary=sbom_summary,
        timeline=build_timeline(audit),
        # Phase 1C: coverage from actual records, honest post-exploit view,
        # derived limitations (incl. the standing egress gap)
        coverage=coverage_summary(graph, audit),
        post_exploit=post_exploit_view(graph),
        limitations=report_limitations(graph, audit),
        remediations=[
            # .get defaults: BLUE_TEAM nodes written before Phase 6 (and
            # test fixtures) lack cwe/owasp/attack/owasp_api — StrictUndefined
            # must never crash REPORT (the report is the only deliverable)
            {"hypothesis_id": n["label"], **n["properties"],
             "cwe": n["properties"].get("cwe", ""),
             "owasp": n["properties"].get("owasp", ""),
             "attack": n["properties"].get("attack", ""),
             "owasp_api": n["properties"].get("owasp_api", ""),
             **remediation_reference(n["label"], graph)}
            for n in graph.by_type("remediation")
        ],
        # the report may only claim testing happened when a tool really ran:
        # `attempted` is weaker than `ran`, and the template needs both to
        # tell "the sandbox never came up" apart from "nothing was tried"
        exploit_ran=exploit_ran,
        exploit_attempted=exploit_attempted,
        completed_states=completed_states or [],
        halt_reason=halt_reason or "",
        failed_states=failed_states or [],
        audit_head=audit.head_hash(),
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def validate_report(report: str, graph: EngagementGraph) -> list[str]:
    """§4.9 post-validation. Returns a list of problems (empty = clean)."""
    problems: list[str] = []

    # every hypothesis appears
    for h in graph.by_type("hypothesis"):
        if h["label"] not in report:
            problems.append(f"hypothesis {h['label']} missing from report")

    # every remediation's target hypothesis appears
    for r in graph.by_type("remediation"):
        if r["label"] not in report:
            problems.append(f"remediation for {r['label']} missing from report")

    # A13 D5: a remediation whose target id names nothing in this engagement
    # is a dangling reference. The report still prints it (the model did
    # propose it, and dropping advice silently is worse) but it says so, and
    # validation records it — "the label came through" was the old check, and
    # it was satisfied by a fix section for an issue that does not exist.
    for r in graph.by_type("remediation"):
        if not remediation_reference(r["label"], graph)["resolved"]:
            problems.append(
                f"remediation for {r['label']!r} refers to no hypothesis or "
                "scan in this engagement")

    # no duplicate remediation sections
    remediation_markers = report.count("### Fix for")
    if remediation_markers != len(graph.by_type("remediation")):
        problems.append(
            f"remediation count mismatch: {remediation_markers} sections, "
            f"{len(graph.by_type('remediation'))} nodes"
        )

    # Phase 6: every hypothesis that carries enrichment data must show it
    # (the CVE row) — a dropped enrichment row would hide public-risk
    # context from the reader
    for h in graph.by_type("hypothesis"):
        enrich = (h["properties"].get("enrichment") or {}).get("cve")
        if enrich and enrich not in report:
            problems.append(
                f"enrichment for {h['label']} ({enrich}) missing from report")

    # Phase 6 / A12: duplicate hypotheses (the same test *and* the same claim)
    # must have been merged — a dup would double-count risk in the report.
    # Uses the same relation dedup does, so a hypothesis deliberately kept
    # apart (different class, different asset claim, different decision) is
    # not reported as a problem.
    kept: list[dict] = []
    for h in graph.by_type("hypothesis"):
        twin = next((c for c in kept if mergeable(c, h)), None)
        if twin is not None:
            problems.append(
                f"duplicate hypothesis {h['label']} (same test and claim as "
                f"{twin['label']}) was not merged")
        kept.append(h)

    # A11: a hypothesis's multi-asset claim must survive into the report —
    # a dropped reference or relationship would hide what the assistant
    # actually claimed (and what the engine made of it). Checked against the
    # same normalised view the template renders, so a raw stored value
    # cannot make the check disagree with the page.
    for h in graph.by_type("hypothesis"):
        for view in related_asset_views(h, graph):
            if view["asset"] not in report:
                problems.append(
                    f"related asset for {h['label']} "
                    f"({view['asset']}) missing from report")
        claim = normalize_line(
            (h["properties"] or {}).get("relationship"), MAX_RELATIONSHIP_CHARS)
        if claim and claim not in report:
            problems.append(
                f"relationship claim for {h['label']} missing from report")

    # A12: a claim the merge folded in must survive into the report too — the
    # whole point of keeping it is that the reader can see what was absorbed.
    # Checked against the same normalised view the template renders.
    for h in graph.by_type("hypothesis"):
        for view in merged_claim_views(h["properties"] or {}, graph):
            if view["title"] and view["title"] not in report:
                problems.append(
                    f"merged claim {view['id']} folded into {h['label']} "
                    f"missing from report")

    # Phase 6: normalized evidence must not carry ANSI codes or runs of
    # raw whitespace — the report is plain markdown
    if _ANSI_RE.search(report):
        problems.append("ANSI escape codes found in report output")

    return problems


class ReportSubagent:
    """Runs the REPORT state: render, validate, redact, write report.md."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        engagement_id: str,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.engagement_id = engagement_id

    def run(self) -> SubagentResult:
        self.audit.write({"event": "state_enter", "state": "REPORT"})

        # completed states / halt reason live on the orchestrator; the
        # runner passes them in via set_context before running.

        # Phase 6: merge duplicate hypotheses BEFORE rendering — after
        # this point the graph is the report's final word, and the merged
        # count lands on the audit chain
        try:
            dedup_hypotheses(self.graph, self.audit)
        except Exception as e:  # never block the deliverable on dedup
            self.audit.write({
                "event": "dedup_failed",
                "reason": str(e)[:200],
            })
            log.warning("hypothesis dedup failed: %s", e)

        # the report file itself first (it may fail — REPORT must never
        # crash, it is the engagement's only deliverable)
        report_path = self.cfg.home / "engagements" / self.engagement_id / "report.md"
        try:
            report = render_report(
                self.graph, self.audit, self.engagement_id,
                completed_states=getattr(self, "completed_states", None),
                halt_reason=getattr(self, "halt_reason", None),
                failed_states=getattr(self, "failed_states", None),
            )

            problems = validate_report(report, self.graph)
            if problems:
                self.audit.write({
                    "event": "report_validation_failed",
                    "problems": problems,
                })
                # still write the report — but the audit records the gaps
                log.warning("report validation problems: %s", problems)

            report = redact_secrets(report)

            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
        except Exception as e:  # render/validate/write all guarded — a
            # broken template must never leave the engagement report-less
            self.audit.write({
                "event": "report_failed",
                "reason": str(e)[:300],
            })
            log.warning("report render failed: %s", e)
            return SubagentResult(status="failed")

        # Phase 1C: the machine-readable export, written atomically. Its
        # own failure never takes down the markdown deliverable — it is
        # audited instead and the markdown stands alone.
        json_path = report_path.parent / "report.json"
        try:
            json_payload = build_report_json(
                self.graph, self.audit, self.engagement_id,
                completed_states=getattr(self, "completed_states", None),
                halt_reason=getattr(self, "halt_reason", None),
                failed_states=getattr(self, "failed_states", None),
            )
            write_report_json(json_payload, json_path)
            self.audit.write({
                "event": "report_json_written",
                "path": str(json_path),
                "chars": len(json_payload),
            })
        except Exception as e:
            self.audit.write({
                "event": "report_json_failed",
                "reason": str(e)[:300],
            })
            log.warning("report.json failed: %s", e)

        # append report_written BEFORE reading head_hash, so the anchor
        # printed in the report matches the chain's FINAL head — a
        # verifier following the report's fingerprint instruction gets a
        # match on an untampered chain, and deleting the last line no
        # longer makes the truncated chain match the printed anchor
        self.audit.write({
            "event": "report_written",
            "path": str(report_path),
            "chars": len(report),
        })
        # patch the anchor to the now-final head hash (the fingerprint
        # line follows "The log's final fingerprint is:")
        final_head = self.audit.head_hash()
        if final_head and "The log's final fingerprint" in report:
            lines = report.splitlines()
            for i, line in enumerate(lines):
                if "The log's final fingerprint" in line:
                    # the hash sits on the next backtick-wrapped line
                    j = i + 1
                    while j < len(lines) and not lines[j].startswith("`"):
                        j += 1
                    if j < len(lines):
                        lines[j] = f"`{final_head}`"
                    break
            report = "\n".join(lines) + "\n"
            report_path.write_text(report, encoding="utf-8")
        return SubagentResult(status="ok")
