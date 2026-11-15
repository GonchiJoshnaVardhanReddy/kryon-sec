"""The deterministic tool planner (Phase 2B.6).

A bounded, explainable execution-planning component for RECON_ACTIVE.
It sits BETWEEN the evidence graph and the existing adapter dispatch:
it never executes anything, never builds argv, and never widens what
can run — it only decides, from EVIDENCE, which already-vetted adapters
are worth running for which in-scope targets, in which order, within
an explicit time budget, and WHY.

THE SOURCE OF TRUTH RULE (spec of this phase, restated):
    the catalog is a VIEW over a real :class:`AdapterRegistry`. An
    adapter that is not registered does not exist here — appearing in
    the selection metadata table below gives a tool NOTHING; only
    registration makes it describable, and only the existing
    dispatch path (``prepare_adapter_run`` -> ``execute_adapter`` ->
    ``KaliSandbox.spawn``) can ever run it. This module therefore
    CANNOT disagree with the executable/argument allowlists: it reads
    the same frozen objects they enforce.

WHAT IT DECIDES (all deterministic, no LLM required):
    1. ELIGIBILITY — hard, evidence-backed constraints per
       (adapter, target base): stage gates, scheme gates (a TLS
       baseline is never forced onto plain HTTP), and the registry
       itself. Missing evidence means INELIGIBLE with a reason —
       never invented.
    2. DEDUPLICATION — a check whose (adapter, normalized target) run
       already COMPLETED successfully inside the evidence-freshness
       window is skipped as ``covered``. A run that FAILED, was
       TRUNCATED, or completed only PARTIALLY (the tls/api wrappers
       report honest ``partial``/``error`` statuses) is NEVER treated
       as coverage — the check stays eligible.
    3. PRIORITY + BUDGET — entries are ordered by an explicit
       priority table (basic service identification first, long
       vulnerability checks last) and packed into a conservative
       wall-clock budget; entries that no longer fit are DEFERRED
       with the reason on the entry (budget optimization never
       deletes a mandatory eligibility rule).
    4. EXPLANATION — every entry carries its outcome
       (selected/covered/deferred/rejected), the reason, the evidence
       references that drove it, and its estimated cost; the whole
       plan is audited as ONE event before anything executes, so the
       final report can compare planned vs actually executed.

ADVISORY SUGGESTIONS (optional, never required):
    an LLM or operator may SUGGEST priorities via
    :class:`ToolSuggestion` — but a suggestion can only reference an
    adapter that is ALREADY registered and a target base that is
    ALREADY in the plan's evidence-backed base set. It can never
    introduce an executable, an argv flag, a new target, or a
    template. Malformed, unknown, out-of-scope, duplicate or
    conflicting suggestions are recorded and dropped — a missing or
    failed LLM response changes nothing at all.

FAIL-CLOSED:
    :meth:`ToolPlanner.plan` is a pure function over validated inputs;
    if it somehow raises, the CALLER (recon_active) must treat that as
    a planner failure — audited, and the engagement falls back to the
    exact deterministic pre-2B.6 path (feature-gated), never to an
    unrestricted fallback.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# frozen schemas
# ---------------------------------------------------------------------------


class ToolSuggestion(BaseModel):
    """One ADVISORY priority suggestion. Bounded by design: two strings
    and a rationale. There is no executable field, no argv field, no
    template field, no target-invention field — a suggestion can only
    name an existing adapter and an existing in-plan base."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter_id: str = Field(min_length=3, max_length=64)
    target_asset: str = Field(min_length=1, max_length=500)
    rationale: str = Field(default="", max_length=300)


class PlanEntry(BaseModel):
    """ONE planning decision for ONE (adapter, target) pair — bounded,
    explainable, and auditable. ``status`` is the honest outcome:
    ``selected`` (will be dispatched through the existing path),
    ``covered`` (a complete prior run exists — skipped), ``deferred``
    (eligible but did not fit the budget), ``rejected`` (a hard
    constraint failed), or ``out_of_stage`` (a registered adapter
    whose stage is not this one — reported for explainability)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter_id: str
    executable: str
    target: str = Field(min_length=1, max_length=500)
    stage: str
    priority: int
    estimated_seconds: int = Field(ge=0, le=330)
    status: str = Field(
        pattern=r"^(selected|covered|deferred|rejected|out_of_stage)$")
    reason: str = Field(default="", max_length=300)
    evidence_refs: "tuple[str, ...]" = Field(default=(), max_length=6)
    suggested: bool = False

    def line(self) -> str:
        """One bounded, audit/report line for this decision."""
        return (f"{self.status:>12} {self.adapter_id} {self.target} "
                f"p{self.priority} ~{self.estimated_seconds}s "
                f"— {self.reason}"[:300])


class ExecutionPlan(BaseModel):
    """The bounded, ordered plan. Frozen once built; entries are in
    execution order. ``plan_id`` is a fresh identifier used to link
    execution outcomes back to THIS planning decision in the audit."""

    model_config = ConfigDict(frozen=True)

    plan_id: str = Field(min_length=1, max_length=64)
    version: int = Field(ge=1)
    state: str = Field(min_length=1, max_length=32)
    target: str = Field(min_length=1, max_length=300)
    entries: "tuple[PlanEntry, ...]" = Field(max_length=100)
    budget_seconds: int = Field(ge=0, le=100_000)
    planned_seconds: int = Field(ge=0)

    def selected(self) -> "list[PlanEntry]":
        return [e for e in self.entries if e.status == "selected"]

    def summary_lines(self) -> "list[str]":
        return [e.line() for e in self.entries]

    def counts(self) -> dict:
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[e.status] = counts.get(e.status, 0) + 1
        return counts


class CatalogEntry(BaseModel):
    """The selection metadata for ONE registered adapter. The adapter
    definition itself (executable, template, stage, risk, bounds) stays
    the single source of truth in the registry; this wraps it with the
    planner's view: what evidence the check needs, what it produces,
    what it costs, and how prior coverage is recognized."""

    model_config = ConfigDict(frozen=True)

    adapter: object          # the registered ModeBToolAdapter (frozen)
    priority: int
    cost_category: str = Field(
        pattern=r"^(low|medium|high)$")
    requires_evidence: "tuple[str, ...]" = Field(default=(), max_length=6)
    produces_evidence: "tuple[str, ...]" = Field(default=(), max_length=6)
    #: when set, prior coverage additionally requires a summary node of
    #: THIS type whose status property equals ``coverage_complete_value``
    #: for the same target (the honest-partial rule for wrappers whose
    #: exit code is 0 even when the run was killed early)
    coverage_node_type: str = ""
    coverage_status_field: str = ""
    coverage_complete_value: str = ""

    @property
    def adapter_id(self) -> str:
        return self.adapter.adapter_id

    @property
    def stages(self) -> "tuple[str, ...]":
        return self.adapter.stages

    @property
    def max_seconds(self) -> int:
        return self.adapter.max_seconds


class PlannerBudget(BaseModel):
    """The conservative wall-clock budget for ONE planning decision.
    Not the engagement's LLM budget (that stays in the orchestrator) —
    this bounds how much TOOL time this state may commit."""

    model_config = ConfigDict(frozen=True)

    max_total_seconds: int = Field(ge=0, le=100_000, default=1800)

    def fits(self, seconds: int, committed: int) -> bool:
        return committed + seconds <= self.max_total_seconds


# ---------------------------------------------------------------------------
# the selection metadata table — DESCRIBES, never enables
# ---------------------------------------------------------------------------

#: priority: lower runs first. The Batch 1 discovery probes plan
#: first (they run pre-discovery in practice and plan as covered
#: post-hoc), then basic service/web identification, then dependent
#: or long checks; the two long checks last.
_PRIORITY = {
    "naabu-probe": 5,        # discovery: bounded port scan (pre-plan lane)
    "dnsx-probe": 6,         # discovery: DNS resolution (pre-plan lane)
    "httpx-probe": 10,       # base evidence: statuses, titles, tech
    "whatweb-probe": 20,     # richer technology fingerprints
    "api-probe": 30,         # read-only API baseline (bounded, quick)
    "katana-probe": 35,      # pinned-depth web crawl (bounded, medium)
    "tls-probe": 40,         # ~3-5 min under real caps (measured 2B.5)
    "nuclei-probe": 50,      # vetted non-destructive template checks
}
_COST = {
    "naabu-probe": "low",
    "dnsx-probe": "low",
    "httpx-probe": "low",
    "whatweb-probe": "low",
    "api-probe": "medium",
    "katana-probe": "medium",
    "tls-probe": "high",
    "nuclei-probe": "high",
}
#: what each check consumes / produces in the evidence graph — used for
#: the explainability report and the requires-evidence reason strings.
#: The discovery probes consume nothing (naabu) or the engagement
#: target itself (dnsx): their lanes run pre-discovery, not planner-gated.
_REQUIRES = {
    "naabu-probe": (),
    "dnsx-probe": (),
    "httpx-probe": ("web_endpoint",),
    "whatweb-probe": ("web_endpoint",),
    "api-probe": ("web_endpoint",),
    "katana-probe": ("web_endpoint",),
    "tls-probe": ("https_base",),
    "nuclei-probe": ("web_endpoint",),
}
_PRODUCES = {
    "naabu-probe": (),          # feeds the shared port set; no nodes
    "dnsx-probe": ("dns_resolution",),
    "httpx-probe": ("web_endpoint",),
    "whatweb-probe": ("tech_fingerprint",),
    "api-probe": ("api_observation", "path"),
    "katana-probe": ("path",),
    "tls-probe": ("tls_observation", "vuln_candidate"),
    "nuclei-probe": ("vuln_candidate",),
}
#: the honest-partial rule: these wrappers exit 0 even when they were
#: killed at their internal bound — their run-summary node carries the
#: real status, so coverage requires status == "complete" (2B.5 shapes)
_COVERAGE_SHAPE = {
    "tls-probe": ("tls_observation", "status", "complete"),
    "api-probe": ("api_observation", "status", "complete"),
}


class ToolCapabilityCatalog:
    """The planner's view of the REGISTERED adapters — built from a
    live :class:`AdapterRegistry` and nothing else."""

    def __init__(self, registry):
        from .adapters import AdapterRegistry

        if not isinstance(registry, AdapterRegistry):
            raise TypeError(
                "catalog must be built from an AdapterRegistry — "
                "never from raw adapter objects")
        self._registry = registry
        self._entries: dict[str, CatalogEntry] = {}
        for adapter in registry.list_adapters():
            meta = _COVERAGE_SHAPE.get(adapter.adapter_id, ("", "", ""))
            self._entries[adapter.adapter_id] = CatalogEntry(
                adapter=adapter,
                priority=_PRIORITY.get(adapter.adapter_id, 99),
                cost_category=_COST.get(adapter.adapter_id, "medium"),
                requires_evidence=_REQUIRES.get(
                    adapter.adapter_id, ("web_endpoint",)),
                produces_evidence=_PRODUCES.get(
                    adapter.adapter_id, ()),
                coverage_node_type=meta[0],
                coverage_status_field=meta[1],
                coverage_complete_value=meta[2],
            )

    def entry(self, adapter_id: str) -> "CatalogEntry | None":
        return self._entries.get(adapter_id)

    def entries(self) -> "list[CatalogEntry]":
        """Catalog entries ordered by priority (stable)."""
        return sorted(self._entries.values(),
                      key=lambda e: (e.priority, e.adapter_id))

    def known_but_unregistered(self, adapter_ids) -> "list[str]":
        """Registered-nowhere ids the planner knows about — reported
        (explainability only; absence here enables NOTHING)."""
        return sorted(set(adapter_ids) - set(self._entries))

    def describe(self) -> "list[dict]":
        """A bounded, report-friendly capability description of every
        REGISTERED adapter (the Phase-2B.6 capability catalog)."""
        rows = []
        for e in self.entries():
            a = e.adapter
            rows.append({
                "adapter_id": a.adapter_id,
                "title": a.title,
                "registration_source": "AdapterRegistry (frozen)",
                "stages": list(a.stages),
                "target_kind": a.target_kind,
                "executable": a.executable,
                "argv_template": list(a.command_template),
                "network": a.network,
                "risk": a.risk,
                "evidence_kind": a.evidence_kind,
                "max_seconds": a.max_seconds,
                "approvals": list(a.approvals),
                "cost_category": e.cost_category,
                "priority": e.priority,
                "requires_evidence": list(e.requires_evidence),
                "produces_evidence": list(e.produces_evidence),
                "verification": "not_verified (hard-wired)",
            })
        return rows


# ---------------------------------------------------------------------------
# evidence helpers
# ---------------------------------------------------------------------------


def normalize_target(url: str) -> str:
    """Normalized target identity for dedupe: lowercase scheme/host,
    explicit default port kept as-is, trailing slash stripped."""
    return (url or "").strip().lower().rstrip("/")


def _host_port_of(url: str) -> str:
    """host:port out of an http(s) URL (the tls wrapper's node id)."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{host}:{port}"


def _parse_ts(value) -> "datetime | None":
    """Parse the graph's ISO-8601 created_at (e.g.
    ``2026-11-12T16:05:33Z``). Unparseable timestamps are never treated
    as fresh — the caller's staleness rule decides."""
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _prior_runs(graph, audit) -> "list[tuple[dict, object]]":
    """Prior adapter_attempt records (validated) with their node —
    malformed nodes are counted and audited, never interpreted."""
    from pydantic import ValidationError

    from .adapters import AdapterRunRecord

    out = []
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        try:
            record = AdapterRunRecord.model_validate(props)
        except ValidationError:
            audit.write({
                "event": "planner_malformed_attempt_node",
                "node_id": str(node.get("id", ""))[:64],
                "label": str(node.get("label", ""))[:120],
            })
            continue
        out.append((node, record))
    return out


def _summary_complete(graph, entry: CatalogEntry,
                      base: str) -> "tuple[bool, str]":
    """The honest-partial rule: when the adapter's coverage shape
    declares a run-summary node, prior coverage holds ONLY when that
    node exists for this target AND its status field reads as
    ``complete``. Partial/error/unparseable is NOT coverage."""
    if not entry.coverage_node_type:
        return True, ""
    host_port = _host_port_of(base)
    for node in graph.by_type(entry.coverage_node_type):
        props = node.get("properties") or {}
        if entry.coverage_node_type == "tls_observation":
            matches = str(props.get("node") or "") == host_port
        else:
            matches = normalize_target(
                str(node.get("label") or "")) == \
                normalize_target(base)
        if not matches:
            continue
        if str(props.get(entry.coverage_status_field) or "") == \
                entry.coverage_complete_value:
            return True, str(node.get("id", ""))[:64]
        return False, str(node.get("id", ""))[:64]
    return False, ""


def _coverage(graph, audit, entry: CatalogEntry, base: str,
              *, max_evidence_age_s: "int | None") -> "tuple[bool, list[str]]":
    """Conservative duplicate-work detection for ONE (adapter, base).

    Covered := a prior run of the SAME adapter for the SAME normalized
    target that actually executed, exited 0, was not truncated, and —
    for the honest-partial wrappers — left a summary node whose status
    reads ``complete``. A failed, partial, stale or inconclusive prior
    run is NEVER coverage (the check stays eligible). Coverage never
    crosses engagements: the graph IS the engagement.
    """
    norm = normalize_target(base)
    now = datetime.now(timezone.utc)
    refs: list[str] = []
    for node, record in _prior_runs(graph, audit):
        if record.adapter_id != entry.adapter_id:
            continue
        if normalize_target(record.target) != norm:
            continue
        # a run that never happened proves nothing about coverage
        if not record.executed or record.exit_code != 0 \
                or record.outcome != "attempted" or record.truncated:
            continue
        # staleness: evidence older than the window is re-eligible
        if max_evidence_age_s is not None:
            ts = _parse_ts(node.get("created_at"))
            if ts is None or (now - ts).total_seconds() > \
                    max_evidence_age_s:
                continue
        ok, ref = _summary_complete(graph, entry, base)
        if not ok:
            continue     # partial/incomplete — honest, stays eligible
        refs.append(str(node.get("id", ""))[:64])
        if len(refs) >= 2:
            break
    return bool(refs), refs


# ---------------------------------------------------------------------------
# the planner
# ---------------------------------------------------------------------------


class ToolPlanner:
    """The bounded planner. Holds a catalog (from a real registry), a
    budget and a suggestion list; :meth:`plan` turns evidence into a
    frozen :class:`ExecutionPlan`. It NEVER executes and NEVER builds
    argv — dispatch stays in the existing adapter path."""

    def __init__(self, catalog: ToolCapabilityCatalog,
                 *, budget: "PlannerBudget | None" = None,
                 suggestions: "tuple[ToolSuggestion, ...] | None" = None,
                 max_evidence_age_s: "int | None" = 3600,
                 plan_version: int = 1):
        self.catalog = catalog
        self.budget = budget or PlannerBudget()
        self.max_evidence_age_s = max_evidence_age_s
        self.plan_version = max(1, int(plan_version))
        self.suggestion_rejections: list[str] = []
        self._suggestions = self._validate_suggestions(
            suggestions or ())

    # -- advisory suggestions (validated, priority-only) -----------------

    def _validate_suggestions(
            self, suggestions: "tuple[ToolSuggestion, ...]",
    ) -> "dict[tuple[str, str], ToolSuggestion]":
        """Deterministic validation: a suggestion is usable only when
        its adapter is REGISTERED. Target membership in the base set is
        checked at plan time (that is when the evidence exists). Every
        rejection is recorded — never raised, never policy-weakening.
        Conflicts (two suggestions for the same pair) keep the FIRST."""
        accepted: dict[tuple[str, str], ToolSuggestion] = {}
        for i, s in enumerate(suggestions):
            try:
                if self.catalog.entry(s.adapter_id) is None:
                    raise ValueError(
                        f"adapter {s.adapter_id!r} is not registered — "
                        "suggestions cannot enable unregistered tools")
                key = (s.adapter_id, normalize_target(s.target_asset))
                if key in accepted:
                    raise ValueError(
                        "conflicting duplicate suggestion for the same "
                        "adapter/target — first one kept")
                accepted[key] = s
            except ValueError as e:
                self.suggestion_rejections.append(
                    f"suggestion[{i}]: {e}"[:300])
        return accepted

    # -- eligibility ------------------------------------------------------

    def _eligibility(self, entry: CatalogEntry, state: str,
                     base: str) -> "tuple[str, str]":
        """Hard eligibility constraints. Returns (ok, reason)."""
        if state not in entry.stages:
            return False, (f"adapter stage is {list(entry.stages)}, "
                           f"not {state}")
        # scheme gate: a TLS baseline is never forced onto plain HTTP
        if entry.adapter_id == "tls-probe" and \
                not base.lower().startswith("https://"):
            return False, "plain-http base — TLS checks never forced"
        return True, "eligible"

    # -- the plan ---------------------------------------------------------

    def plan(self, *, state: str, target: str,
             bases: "list[str]", graph, audit,
             domain_targets: "list[str] | None" = None) -> ExecutionPlan:
        """Build the bounded, ordered plan for ONE state.

        ``bases`` are the stage's in-scope, scope-validated base URLs
        (already derived from observed open ports — the planner never
        discovers targets). ``domain_targets`` (Tool Expansion Batch
        1) are the scope-validated DOMAIN-kind targets (the
        engagement target itself) for the registered domain-kind
        adapters (naabu-probe / dnsx-probe). The pairing is strict,
        never cross-kind: a URL-kind adapter is only ever paired with
        ``bases`` and a domain-kind adapter only with
        ``domain_targets`` — preparing an adapter against the wrong
        target kind would be refused by prepare_adapter_run, so the
        plan must never produce such a pair. Adapters of other target
        kinds (hostport/term/assetless) get no entries here yet.

        Every registered adapter x matching target pair gets an
        explicit decision entry; the plan is FROZEN and returned.
        """
        domain_targets = list(domain_targets or ())
        entries: list[PlanEntry] = []
        committed = 0
        matched_suggestions: set[tuple[str, str]] = set()
        unregistered = self.catalog.known_but_unregistered(
            _PRIORITY)
        if unregistered:
            audit.write({
                "event": "planning_unregistered_adapters",
                "adapters": unregistered,
                "note": "described nowhere, executable nowhere",
            })
        for entry in self.catalog.entries():
            # the stage gate is per REGISTERED ADAPTER, before any
            # target pairing: an adapter whose stage is not this one
            # gets ONE explicit ``out_of_stage`` entry (explainability)
            # — never silently absent, never paired to invented targets
            if state not in entry.stages:
                anchor = bases[0][:500] if bases else (
                    domain_targets[0][:500] if domain_targets
                    else target[:500])
                entries.append(PlanEntry(
                    adapter_id=entry.adapter_id,
                    executable=entry.adapter.executable,
                    target=anchor, stage=state,
                    priority=entry.priority,
                    estimated_seconds=entry.max_seconds,
                    status="out_of_stage",
                    reason=(f"adapter stage is {list(entry.stages)}, "
                            f"not {state}")[:300]))
                continue
            kind = entry.adapter.target_kind
            if kind == "url":
                entry_targets: "list[str]" = bases
            elif kind == "domain":
                entry_targets = domain_targets
            else:
                # hostport/term/assetless adapters are not plannable
                # against either target list yet — zero entries, no
                # invented pairing
                entry_targets = []
            for base in entry_targets:
                norm = normalize_target(base)
                suggestion = self._suggestions.get(
                    (entry.adapter_id, norm))
                if suggestion is not None:
                    # membership held: the suggestion's target IS an
                    # evidence-backed, in-scope base of this plan
                    matched_suggestions.add((entry.adapter_id, norm))
                refs: list[str] = []
                ok, reason = self._eligibility(entry, state, base)
                if not ok:
                    if reason.startswith("adapter stage"):
                        status = "out_of_stage"
                    else:
                        status = "rejected"
                    entries.append(PlanEntry(
                        adapter_id=entry.adapter_id,
                        executable=entry.adapter.executable,
                        target=base[:500], stage=state,
                        priority=entry.priority,
                        estimated_seconds=entry.max_seconds,
                        status=status, reason=reason[:300],
                        suggested=suggestion is not None))
                    continue
                covered, crefs = _coverage(
                    graph, audit, entry, base,
                    max_evidence_age_s=self.max_evidence_age_s)
                if covered:
                    entries.append(PlanEntry(
                        adapter_id=entry.adapter_id,
                        executable=entry.adapter.executable,
                        target=base[:500], stage=state,
                        priority=entry.priority,
                        estimated_seconds=0,
                        status="covered",
                        reason=("complete prior run within the "
                                "evidence-freshness window — "
                                "duplicate work avoided"),
                        evidence_refs=tuple(crefs[:2]),
                        suggested=suggestion is not None))
                    continue
                # budget: eligible, uncovered — does it fit? (priority
                # order means basic checks claim budget before long
                # checks; a deferred entry is audited, never dropped
                # silently, and never overrides an eligibility rule)
                if not self.budget.fits(entry.max_seconds, committed):
                    entries.append(PlanEntry(
                        adapter_id=entry.adapter_id,
                        executable=entry.adapter.executable,
                        target=base[:500], stage=state,
                        priority=entry.priority,
                        estimated_seconds=entry.max_seconds,
                        status="deferred",
                        reason=(
                            f"budget: needs ~{entry.max_seconds}s, "
                            f"{self.budget.max_total_seconds - committed}s "
                            f"remain of {self.budget.max_total_seconds}s"
                        )[:300],
                        suggested=suggestion is not None))
                    continue
                committed += entry.max_seconds
                reason = "evidence-backed eligible check"
                if suggestion is not None:
                    reason += f"; suggested: {suggestion.rationale}"[:200]
                entries.append(PlanEntry(
                    adapter_id=entry.adapter_id,
                    executable=entry.adapter.executable,
                    target=base[:500], stage=state,
                    priority=entry.priority,
                    estimated_seconds=entry.max_seconds,
                    status="selected", reason=reason[:300],
                    evidence_refs=(f"base:{norm}"[:300],),
                    suggested=suggestion is not None))
        # a suggestion whose target never appeared in the plan's
        # evidence-backed base set is RECORDED, never silently dropped
        for (adapter_id, norm), s in self._suggestions.items():
            if (adapter_id, norm) not in matched_suggestions:
                self.suggestion_rejections.append(
                    f"suggestion target {s.target_asset[:120]!r} is "
                    f"not in the plan's evidence-backed base set "
                    f"(adapter {adapter_id})"[:300])
        plan = ExecutionPlan(
            plan_id=str(uuid.uuid4())[:8],
            version=self.plan_version,
            state=state,
            target=str(target)[:300],
            entries=tuple(entries),
            budget_seconds=self.budget.max_total_seconds,
            planned_seconds=committed,
        )
        audit.write({
            "event": "planning_decided",
            "plan_id": plan.plan_id,
            "plan_version": plan.version,
            "state": state,
            "target": str(target)[:300],
            "budget_seconds": plan.budget_seconds,
            "planned_seconds": plan.planned_seconds,
            "counts": plan.counts(),
            "entries": plan.summary_lines()[:100],
            "suggestion_rejections": self.suggestion_rejections[:20],
        })
        return plan
