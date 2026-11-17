"""A production Mode B tool adapter: gowitness-probe (Tool Expansion
Batch 2).

Target: Kali's bundled gowitness (verified in the pinned sandbox
image: executable ``gowitness``, entrypoint-allowlisted) for authorized
screenshots of in-scope web endpoints, in the RECON_ACTIVE stage only,
through the Phase 2B.2 adapter framework — the SAME engine, sandbox,
allowlist, egress boundary, scope checks, audit chain and evidence
graph as every other tool. This module adds NO general-purpose command
interface: the executable is the fixed ``gowitness`` binary and the
argv template is fixed and Layer-2 validated.

WHY AN ADAPTER AT ALL (Batch 2 evaluation):
    - The legacy web-plan entry records ONLY a bare ``screenshot``
      graph node keyed off its own argv — no run provenance, no
      adapter_attempt record, no structured failure classification: a
      screenshot that silently failed to render is indistinguishable
      from one that was taken. The adapter runs the SAME binary with
      the SAME fixed argv shape and produces the SAME legacy-shape
      node — with the adapter_attempt run record (exit code, output
      bound, duration), structured failure classification (2B.7) and
      an audited evidence event the legacy path cannot carry.
    - The screenshot itself is the evidence: the PNG lands in the rw
      ``/evidence`` mount (the engagement folder), NOT in tool
      output. gowitness 3.x writes NO result database unless a
      ``--write-*`` flag is passed — the template passes none, so the
      read-only rootfs needs nothing special; the PNG file IS the
      record, and the graph node says where to find it.

NO NEW AGGRESSION: the template is byte-identical to the shipped
Layer-2 entry — ``scan single -u`` against the ONE scope-validated
base URL, screenshots into the FIXED ``/evidence`` mount, console
output silenced with ``-q``, the browser pinned to the image's OWN
chromium binary via ``--chrome-path`` (gowitness 3.x otherwise
downloads a browser at runtime, which the egress gate correctly
drops). No delay/scalarize/custom-flags surface exists to widen:
anything else is a conscious code change in the repo, auditable in
git, never caller input.

DUPLICATE AVOIDANCE: one probe per check. The registered
gowitness-probe adapter REPLACES the legacy ``gowitness`` web-plan
entry (deterministic either/or in ReconActiveSubagent, the same rule
as the Batch 1 katana rule): when the adapter runs, the legacy entry
is omitted from the plan — the two never both screenshot the same
base in one state.

There is NO text contract to parse: gowitness's console chatter is not
a stable interface and is never interpreted. The run's exit code and
the adapter_attempt record are the truth: a successful run records ONE
legacy-shape ``screenshot`` node (the same node type the legacy parse
produces), and a failed/refused run records NO node — a refusal must
never fabricate screenshot evidence.

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` in
adapter_whatweb.py is the combined RECON_ACTIVE registry the runner
injects. Anything not registered stays disabled.
"""

from __future__ import annotations

import logging

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "gowitness-probe"
#: the canonical id under the name recon_active's lane getter imports
#: (the same export pattern as the katana adapter module)
GOWITNESS_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "gowitness"

#: the fixed screenshot directory — the rw ``/evidence`` mount (the
#: engagement folder). A constant here makes the pin explicit and
#: testable; it is ALSO a literal in the shipped Layer-2 template.
SCREENSHOT_DIR = "/evidence"

#: the fixed argv template — EXACTLY the shipped ``gowitness`` entry in
#: allowlist.py ACTIVE_RECON_TEMPLATES, so the adapter argv and the
#: legacy plan entry are byte-identical. Lockstep is asserted by tests
#: that render the adapter argv against the SHIPPED Layer-2 template.
#: gowitness 3.2.2 (the pinned image's version) removed the v2-era
#: ``scan website`` subcommand and the ``--no-console``/``--disable-db``
#: flags — the old shape died at startup with a Usage banner (found
#: live, Phase-4 lab 2026-11-17). The v3 shape is ``scan single -u``;
#: v3 writes no result DB unless a --write-* flag is passed (none is),
#: ``-q`` silences console chatter, and ``--chrome-path`` pins the
#: image's own chromium (no runtime browser download — the gate drops
#: those). ``{url}`` is the template's only placeholder.
GOWITNESS_PROBE_TEMPLATE: tuple[str, ...] = (
    "scan", "single", "-u", "{url}",
    "--screenshot-path", SCREENSHOT_DIR,
    "--chrome-path", "/usr/bin/chromium", "-q",
)


def make_gowitness_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere. ``{url}`` is the
    template's only placeholder, filled by the framework from the
    scope-validated base.
    """
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="gowitness screenshot probe",
        purpose=(
            "Authorized screenshots of in-scope web endpoints via "
            "gowitness: one PNG per base into the evidence mount. "
            "RECON_ACTIVE only; a screenshot is a fact about the "
            "site's rendered surface, never a vulnerability claim."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=GOWITNESS_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy gowitness plan entry
        evidence_kind="screenshot_file",
    )


def production_registry():
    """The shipped Mode B adapter registry for the gowitness-probe
    adapter: EXPLICITLY contains this one vetted production adapter
    and nothing else. Unknown adapters remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_gowitness_probe_adapter())
    return registry


# ---- evidence recording -------------------------------------------------------


def find_adapter_attempt_node(graph: EngagementGraph,
                              request_id: str) -> "dict | None":
    """The ``adapter_attempt`` node this run produced (by request_id —
    stable across node hunting). None when the run never produced one
    (refusals are audit-only by the 2B.2 design)."""
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        if props.get("request_id") == request_id:
            return node
    return None


def record_gowitness_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
) -> "list[str]":
    """Map one gowitness adapter run onto the evidence graph.

    ONE legacy-shape ``screenshot`` node per successful run (the SAME
    node type the legacy gowitness parse produces, labelled by the
    screenshotted base URL), with a ``produced`` lineage edge from the
    run's ``adapter_attempt`` node and the adapter provenance the
    legacy path cannot carry. The PNG itself lives in the ``/evidence``
    mount — the node records THAT fact, never the image content. A run
    whose adapter_attempt node is missing (a refusal) records NOTHING:
    a refusal must never fabricate screenshot evidence. Duplicate
    labels (the same base already screenshotted — first-wins) are
    SKIPPED. Refusal to link is AUDITED, never silent and never fatal.

    Returns the list of created node ids.
    """
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        audit.write({
            "event": "gowitness_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
        })
        return []
    label = run_record.target[:500]
    existing = [n for n in graph.by_type("screenshot")
                if n.get("label") == label]
    if existing:
        audit.write({
            "event": "gowitness_adapter_evidence",
            "adapter": ADAPTER_ID,
            "tool": TOOL_EXECUTABLE,
            "request_id": run_record.request_id,
            "screenshot_nodes": 0,
            "duplicate_or_refused": 1,
        })
        return []
    created: list[str] = []
    try:
        node = graph.add_node(
            node_type="screenshot",
            label=label,
            properties={
                "source": TOOL_EXECUTABLE,
                "dir": SCREENSHOT_DIR,
                "adapter": ADAPTER_ID,
                "request_id": run_record.request_id,
                "untrusted": True,
                "verification": "not_verified",
            },
            provenance={
                "agent": "ADAPTER",
                "source_type": "tool",
                "tool": TOOL_EXECUTABLE,
                "adapter": ADAPTER_ID,
            },
        )
    except Exception as e:  # graph validation: audited, not fatal
        audit.write({
            "event": "gowitness_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": f"screenshot node refused: {e}"[:200],
            "label": label[:300],
        })
        return []
    created.append(node["id"])
    link(
        graph, "produced", attempt["id"], node["id"],
        provenance={
            "agent": "ADAPTER", "source_type": "tool",
            "adapter": ADAPTER_ID,
        },
        on_refuse=lambda reason, _nid=node["id"]: audit.write({
            "event": "gowitness_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "node_id": _nid,
            "reason": str(reason)[:200],
        }),
    )
    audit.write({
        "event": "gowitness_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "dir": SCREENSHOT_DIR,
        "screenshot_nodes": len(created),
        "duplicate_or_refused": 0,
    })
    return created
