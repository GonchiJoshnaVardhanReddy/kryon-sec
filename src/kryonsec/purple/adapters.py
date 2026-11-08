"""Vetted Mode B tool adapters (Phase 2B.2).

The typed contract, registry and execution path for the NEXT vetted
security tools — Strix-inspired discovery, executed through the EXISTING
engine. This is deliberately NOT a parallel execution engine:

- argv is built from a FIXED command template on the registered adapter
  (the Phase-2A-era ``allowlist`` template grammar, never from LLM text);
- execution is only ever ``KaliSandbox.spawn`` (or a compatible sandbox
  object in tests): Docker + gVisor runsc, non-root, read-only rootfs,
  resource caps, isolation and egress invariants re-checked inside spawn
  itself. There is no host fallback anywhere in this module;
- every refusal runs through the existing audit chain; every run maps to
  an ``adapter_attempt`` graph node with the SAME lifecycle as
  ``exploit_attempt`` nodes (hypothesis --tested_by--> attempt);
- output is UNTRUSTED DATA, and the record's verification status is
  HARD-WIDED to ``not_verified``: only the VERIFY subagent (independent
  tool, same Phase-1C rule) can ever upgrade a finding. A successful
  exit code or a scanner's success message verifies nothing.

THE CONTRACT (Phase 2B.2 decision)
    adapter_id      unique id; unknown ids raise / refuse (never run)
    title/purpose   what this is FOR (honest text, shown at Gate 2)
    category        one fixed category (registry search key)
    stages          which authorized workflow states it may run in
    executable      the sandbox executable: a bare program name in the
                    image or a baked /opt/kryonsec/ script — never an
                    LLM-chosen path
    command_template FIXED argv template (allowlist grammar)
    target_kind     url | hostport | domain | term | assetless
    max_seconds     per-run bound (<= the sandbox's own 330s ceiling)
    output_bound_chars  output record bound (the sandbox bounds first)
    approvals       gates REQUIRED before execution (registration rule
                    makes impact and stage consistent)
    network         none | target_scope  (third_party is Zone A's path;
                    Zone B adapters cannot claim it here)
    risk            inert | informational | active | impactful
    evidence_kind   text_excerpt | screenshot_file | json_report

REGISTRATION IS EXPLICIT. The shipped registry starts EMPTY; unknown
adapters are refused. This phase ships no offensive adapter and exposes
no new execution to the LLM — Additions come one vetted adapter at a
time (Phase 2B.3+).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, \
    field_validator, model_validator

from ..secrets import redact
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .capability import host_in_scope
from .exploit import compose_url
from .lineage import link
from .orchestrator import STATES
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

#: the workflow states an adapter may claim (the deterministic loop)
ADAPTER_STAGES: tuple[str, ...] = tuple(STATES)

#: the fixed categories (search keys, never free text)
ADAPTER_CATEGORIES: tuple[str, ...] = (
    "recon", "web_recon", "exploit", "verify", "post_exploit",
    "blue_team", "utility",
)

#: the ONLY human gates an adapter may name
ADAPTER_GATES: tuple[str, ...] = ("hypothesis_gate", "post_exploit_gate")

#: network claims an ADAPTER may make (third-party data is Zone A's
#: path — RECON_PASSIVE/zonea — not a sandbox adapter's to claim)
ADAPTER_NETWORKS: tuple[str, ...] = ("none", "target_scope")

#: risk classification
ADAPTER_RISKS: tuple[str, ...] = (
    "inert", "informational", "active", "impactful",
)

#: evidence shapes an adapter may declare
ADAPTER_EVIDENCE: tuple[str, ...] = (
    "text_excerpt", "screenshot_file", "json_report",
)

#: the required-baked script location (same convention as allowlist.py)
_SCRIPT_PATH = re.compile(r"^/opt/kryonsec/[A-Za-z0-9._-]+\.py\Z")

#: target placeholders a template may use, per target_kind
_TARGET_PLACEHOLDER: dict[str, str] = {
    "url": "{url}",
    "hostport": "{hostport}",
    "domain": "{target}",
    "term": "{term}",
}

_TARGET_VARIABLES: dict[str, str] = {
    "url": "url",
    "hostport": "hostport",
    "domain": "target",
    "term": "term",
}


class AdapterError(Exception):
    """Base: registration, preparation or availability refusal."""


class DuplicateAdapterError(AdapterError):
    pass


class AdapterNotRegistered(AdapterError):
    """Unknown adapter ids are REFUSED, never defaulted to enabled."""


class AdapterScopeRefused(AdapterError):
    """A prepared target (or composed URL) is outside engagement scope."""


class ModeBToolAdapter(BaseModel):
    """The typed, frozen definition of one vetted Mode B tool.

    Instances are hand-written constants inside the repo — an LLM can
    call an adapter through the registry, but the REGISTRY decides what
    exists. Unknown adapters are refused with :class:`AdapterError`.
    """

    model_config = ConfigDict(frozen=True)

    adapter_id: str = Field(min_length=3, max_length=64,
                            pattern=r"^[a-z][a-z0-9_-]+$")
    title: str = Field(min_length=3, max_length=80)
    purpose: str = Field(min_length=3, max_length=300)
    category: str
    stages: tuple[str, ...]
    executable: str
    command_template: tuple[str, ...] = Field(min_length=1)
    target_kind: Literal["url", "hostport", "domain", "term",
                         "assetless"] = "url"
    max_seconds: int = Field(ge=10, le=330, default=120)
    output_bound_chars: int = Field(ge=256, le=1_000_000,
                                    default=20_000)
    approvals: tuple[str, ...] = ()
    network: Literal["none", "target_scope"] = "none"
    risk: Literal["inert", "informational", "active", "impactful"] = "inert"
    evidence_kind: Literal["text_excerpt", "screenshot_file",
                           "json_report"] = "text_excerpt"

    @field_validator("category", "stages", "approvals", "network",
                     "risk", "evidence_kind", mode="before")
    @classmethod
    def _in_fixed_sets(cls, value, info):
        name = info.field_name
        if name == "category":
            if value not in ADAPTER_CATEGORIES:
                raise ValueError(
                    f"category {value!r} is not one of "
                    f"{list(ADAPTER_CATEGORIES)}")
        elif name == "stages":
            stages = tuple(value or ())
            if not stages:
                raise ValueError("stages must name at least one state")
            bad = [s for s in stages
                   if s not in ADAPTER_STAGES or s == "INIT"]
            if bad:
                raise ValueError(
                    f"stages must be workflow states, got {bad}")
        elif name == "approvals":
            gates = tuple(value or ())
            bad = [g for g in gates if g not in ADAPTER_GATES]
            if bad:
                raise ValueError(
                    f"approvals must be gates in {list(ADAPTER_GATES)}, "
                    f"got {bad}")
        elif name == "network":
            if value not in ADAPTER_NETWORKS:
                raise ValueError(
                    f"network {value!r} must be one of "
                    f"{list(ADAPTER_NETWORKS)} — third-party data is "
                    "Zone A's path, never a Zone B adapter's claim")
        elif name == "risk":
            if value not in ADAPTER_RISKS:
                raise ValueError(
                    f"risk {value!r} must be one of {list(ADAPTER_RISKS)}")
        elif name == "evidence_kind":
            if value not in ADAPTER_EVIDENCE:
                raise ValueError(
                    f"evidence_kind {value!r} must be one of "
                    f"{list(ADAPTER_EVIDENCE)}")
        return value

    @field_validator("executable")
    @classmethod
    def _executable_is_fixed(cls, value: str) -> str:
        from .allowlist import is_program_name

        ok = is_program_name(value) or _SCRIPT_PATH.match(value)
        if not ok:
            raise ValueError(
                f"executable {value!r} must be a bare program name or a "
                "baked /opt/kryonsec/ script path — never a caller- or "
                "LLM-chosen executable path")
        return value

    @model_validator(mode="after")
    def _consistency_rules(self) -> "ModeBToolAdapter":
        # the template must compile in the ALLOWLIST grammar (Layer 2
        # reuse) and carry the target placeholder its target_kind needs
        placeholder = _TARGET_PLACEHOLDER.get(self.target_kind)
        joined = " ".join(self.command_template)

        def _has(name: str) -> bool:
            return any(f"{{{name}}}" in arg
                       for arg in self.command_template)

        if placeholder and not any(placeholder in arg
                                   for arg in self.command_template):
            raise ValueError(
                f"command_template must carry {placeholder} for "
                f"target_kind={self.target_kind!r}")
        if self.target_kind == "assetless":
            bad = [v for v in ("url", "urlfuzz", "target", "hostport",
                               "term") if _has(v)]
            if bad:
                raise ValueError(
                    f"assetless adapter's template must not contain "
                    f"target placeholders: {bad}")
        try:
            ToolAllowlist(self.templates_map())
        except ValueError as e:
            raise ValueError(f"command_template does not compile: {e}")
        # stage/gate consistency (mirror the engine: EXPLOIT runs behind
        # Gate 2, POST_EXPLOIT behind Gate 3)
        if "EXPLOIT" in self.stages and \
                "hypothesis_gate" not in self.approvals:
            raise ValueError(
                f"{self.adapter_id}: EXPLOIT stage requires the "
                "hypothesis_gate approval")
        if "POST_EXPLOIT" in self.stages and \
                "post_exploit_gate" not in self.approvals:
            raise ValueError(
                f"{self.adapter_id}: POST_EXPLOIT stage requires the "
                "post_exploit_gate approval")
        # risk/gate consistency: impact requires a human, a human flow
        # requires a real touch, and an egress-less run cannot be active
        if "post_exploit_gate" in self.approvals and \
                self.risk != "impactful":
            raise ValueError(
                f"{self.adapter_id}: post_exploit_gate is reserved for "
                "impactful tools")
        if not self.approvals and self.risk == "impactful":
            raise ValueError(
                f"{self.adapter_id}: an impactful tool cannot run "
                "without a required approval gate")
        if self.network == "target_scope" and \
                self.risk not in ("active", "impactful"):
            raise ValueError(
                f"{self.adapter_id}: a target-touching tool must "
                "classify active or impactful")
        if self.network == "none" and \
                self.risk not in ("inert", "informational"):
            raise ValueError(
                f"{self.adapter_id}: a no-network tool cannot be "
                "active or impactful (target touch implies network)")
        return self

    # -- helpers ------------------------------------------------------------

    def templates_map(self) -> dict[str, list[str]]:
        """The allowlist-style mapping this adapter validates against."""
        return {self.executable: list(self.command_template)}

    def tool_name(self) -> str:
        """The name used in audit events and graph records."""
        return self.adapter_id


# ---- the registry (explicit registration; unknown = disabled) ------------


class PreparedAdapterRun(BaseModel):
    """A validated execution request — and ONLY a request.

    Preparation is scope-checked, template-rendered and Layer-2-valid.
    It does NOT imply authorization to execute: :func:`execute_adapter`
    still demands the sandbox, the egress boundary and the required
    approval gates.
    """

    model_config = ConfigDict(frozen=True)

    adapter_id: str
    request_id: str = Field(min_length=8, max_length=64)
    argv: list[str]
    target: str
    target_kind: str
    tool: str
    max_seconds: int
    network: str
    approvals: tuple[str, ...]


class AdapterRegistry:
    """The explicit registry: nothing exists until it is registered.

    Empty by default. ``prepare``/``execute``/``search`` against an id
    that was never registered is a refusal, not a fallback.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, ModeBToolAdapter] = {}
        self._allowlists: dict[str, ToolAllowlist] = {}

    # -- registration -------------------------------------------------------

    def register(self, adapter: ModeBToolAdapter) -> None:
        """Register one vetted adapter. Duplicate ids are refused —
        an adapter identity must be stable, not silently re-pointed."""
        if not isinstance(adapter, ModeBToolAdapter):
            raise AdapterError("register() takes a ModeBToolAdapter")
        if adapter.adapter_id in self._adapters:
            raise DuplicateAdapterError(
                f"adapter {adapter.adapter_id!r} already registered "
                "— duplicate identities are refused")
        self._adapters[adapter.adapter_id] = adapter
        self._allowlists[adapter.adapter_id] = ToolAllowlist(
            adapter.templates_map())
        log.info("adapter registered: %s (%s)", adapter.adapter_id,
                 adapter.category)

    def adapter_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    # -- lookup; unknown ids REFUSE -----------------------------------------

    def get(self, adapter_id: str) -> ModeBToolAdapter:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise AdapterNotRegistered(
                f"adapter {adapter_id!r} is not registered — unknown "
                "adapters are refused, never defaulted to enabled")
        return adapter

    def _allowlist(self, adapter_id: str) -> ToolAllowlist:
        self.get(adapter_id)          # unknown -> AdapterNotRegistered
        return self._allowlists[adapter_id]

    # -- discovery (read-only; grants NO execution) ---------------------------

    def list_adapters(self) -> tuple[ModeBToolAdapter, ...]:
        return tuple(self._adapters[a] for a in self.adapter_ids())

    def search(self, category: str | None = None,
               stage: str | None = None,
               query: str | None = None) -> tuple[ModeBToolAdapter, ...]:
        if category is not None and category not in ADAPTER_CATEGORIES:
            raise AdapterError(f"unknown category {category!r}")
        if stage is not None and stage not in ADAPTER_STAGES:
            raise AdapterError(f"unknown stage {stage!r}")
        found = []
        needle = (query or "").casefold()
        for adapter in self.list_adapters():
            if category and adapter.category != category:
                continue
            if stage and stage not in adapter.stages:
                continue
            if needle and needle not in (
                    f"{adapter.title} {adapter.purpose} "
                    f"{adapter.adapter_id}").casefold():
                continue
            found.append(adapter)
        return tuple(found)

    def describe(self, adapter_id: str) -> str:
        """Honest requirements as JSON — including the fixed argv
        template, so an operator (or the LLM at describe time) sees
        EXACTLY what may run. Discovery never authorizes execution."""
        adapter = self.get(adapter_id)
        return json.dumps({
            "adapter_id": adapter.adapter_id,
            "title": adapter.title,
            "purpose": adapter.purpose,
            "category": adapter.category,
            "stages": list(adapter.stages),
            "risk": adapter.risk,
            "network": adapter.network,
            "approvals": list(adapter.approvals),
            "executable": adapter.executable,
            "command_template": list(adapter.command_template),
            "target_kinds": adapter.target_kind,
            "evidence_kind": adapter.evidence_kind,
            "max_seconds": adapter.max_seconds,
            "output_bound_chars": adapter.output_bound_chars,
            "note": "registration is NOT authorization: execution "
                    "additionally requires the sandbox boundary, egress "
                    "policy (target-touching tools) and the named "
                    "approval gates",
        }, indent=1)

    # -- availability in the CURRENT sandbox ---------------------------------

    def check_available(self, adapter_id: str,
                        sandbox: Any) -> "tuple[bool, list[str]]":
        """Can this adapter run against THIS sandbox right now? A
        ready-planning API only — availability still grants nothing."""
        ok = True
        reasons: list[str] = []
        adapter = self.get(adapter_id)
        if sandbox is None or not callable(getattr(sandbox, "spawn", None)):
            return False, ["no sandbox provided or no spawn() — "
                           "host fallback is never a substitute"]
        if not getattr(sandbox, "image", ""):
            return False, ["sandbox has no pinned image"]
        if adapter.network == "target_scope" and \
                getattr(sandbox, "egress_policy", None) is None:
            ok = False
            reasons.append(
                "sandbox has no egress policy — a target-touching "
                "adapter (network=target_scope) is refused without the "
                "engagement egress boundary (Phase 1E)")
        limit = getattr(sandbox, "timeout_s", None)
        if limit is not None and adapter.max_seconds > limit:
            reasons.append(
                f"sandbox timeout {limit}s is below the adapter bound "
                f"{adapter.max_seconds}s — spawn would be capped at "
                f"{limit}s")
        return ok, reasons


# ---- preparation: scope + template rendering + Layer-2 validation -------

_VAR_SEGMENT = re.compile(r"\{([^{}]+)\}")


def _remaining_is_alternation(arg: str) -> bool:
    """After substituting variables, every remaining {…} segment must be
    a template ALTERNATION (a literal choice like {1|2}); anything else
    is an unfilled placeholder and the render must refuse."""
    for m in _VAR_SEGMENT.finditer(arg):
        if "|" in m.group(1):
            continue
        return False
    return True


def _fill_template(template: tuple[str, ...],
                   variables: dict[str, str]) -> "list[str]":
    args = []
    for arg in template:
        for name, value in variables.items():
            arg = arg.replace(f"{{{name}}}", value)
        if not _remaining_is_alternation(arg):
            raise AdapterError(
                f"template argument {arg!r} still carries an unfilled "
                "placeholder — preparation is all-or-nothing")
        args.append(arg)
    return args


def prepare_adapter_run(
    registry: AdapterRegistry,
    adapter_id: str,
    *,
    target: str = "",
    target_asset: str = "",
    subdomains: "list[str] | None" = None,
    scheme: str = "http",
    params: "dict[str, str] | None" = None,
    request_id: str | None = None,
) -> PreparedAdapterRun:
    """Build a validated execution request for a REGISTERED adapter.

    Scope is enforced exactly like the engine: the composed URL (or
    hostport host) must be the engagement target or an in-scope
    subdomain — the caller cannot aim an adapter at an arbitrary host.
    The rendered argv is re-checked against the adapter's Layer-2
    allowlist before the request exists.
    """
    adapter = registry.get(adapter_id)
    if request_id is None:
        request_id = uuid.uuid4().hex
    if len(request_id) < 8:
        raise AdapterError("request_id is too short to correlate audits")
    params = dict(params or {})
    variables: dict[str, str] = {}
    used_target = ""

    if adapter.target_kind == "url":
        url = compose_url(target, target_asset, subdomains, scheme=scheme)
        # compose_url returns None for an OUT-OF-SCOPE absolute asset —
        # the same rule ExploitSubagent's tools run under
        if not url:
            raise AdapterScopeRefused(
                f"adapter {adapter_id}: asset {target_asset!r} resolves "
                f"outside engagement scope (target {target!r})")
        variables["url"] = url
        used_target = url
    elif adapter.target_kind == "domain":
        if not target.strip():
            raise AdapterError("domain adapters need the engagement target")
        variables["target"] = target
        used_target = target
    elif adapter.target_kind == "hostport":
        hostport = (params.pop("hostport", "") or "").strip()
        host, _, port = hostport.rpartition(":")
        if not host or not port.isdigit():
            raise AdapterError(
                "hostport adapters need params['hostport'] as host:port")
        h = host.lower().rstrip(".")
        if not (host_in_scope(h, target)
                or any(h == s.lower().rstrip(".")
                       for s in (subdomains or []))):
            raise AdapterScopeRefused(
                f"adapter {adapter_id}: host {h!r} is outside engagement "
                f"scope (target {target!r})")
        variables["hostport"] = f"{h}:{port}"
        used_target = f"{h}:{port}"
    elif adapter.target_kind == "term":
        variables["term"] = params.pop("term", "")
        if not variables["term"].strip():
            raise AdapterError("term adapters need params['term']")

    # every remaining placeholder must be satisfied by an explicit param
    for arg in adapter.command_template:
        for m in _VAR_SEGMENT.finditer(arg):
            name = m.group(1)
            if name in variables or "|" in name:
                continue
            if name not in params:
                raise AdapterError(
                    f"adapter {adapter_id}: template placeholder "
                    f"{{{name}}} has no value (params={sorted(params)})")
            variables[name] = params.pop(name)
    if params:
        raise AdapterError(
            f"adapter {adapter_id}: unexpected params {sorted(params)}")

    args = _fill_template(adapter.command_template, variables)

    # Layer 2, adapter scope: the RENDERED argv must match the template
    allowlist = registry._allowlist(adapter_id)
    try:
        allowlist.validate(adapter.executable, [adapter.executable, *args])
    except AllowlistViolation as e:
        raise AdapterError(f"adapter {adapter_id}: rendered argv "
                           f"rejected: {e}")
    return PreparedAdapterRun(
        adapter_id=adapter_id,
        request_id=request_id,
        argv=[adapter.executable, *args],
        target=used_target,
        target_kind=adapter.target_kind,
        tool=adapter.adapter_id,
        max_seconds=adapter.max_seconds,
        network=adapter.network,
        approvals=adapter.approvals,
    )


# ---- the one execution path (reuse KaliSandbox.spawn; no host fallback) --


class AdapterRunRecord(BaseModel):
    """The structured record of one adapter execution attempt — exactly
    the ``adapter_attempt`` node's properties.

    ``confirmed`` does not exist here, and ``verification`` is
    HARD-WIDED to ``not_verified``: no adapter output, exit code or
    success message is ever independent verification. Only the VERIFY
    subagent's independent-tool check (Phase 1C) upgrades a finding.
    """

    model_config = ConfigDict(frozen=True)

    adapter_id: str
    request_id: str
    tool: str
    argv: list[str]
    target: str
    executed: bool
    exit_code: int
    outcome: str
    output_excerpt: str = ""
    error_excerpt: str = ""
    truncated: bool = False
    evidence_kind: str
    untrusted: Literal[True] = True
    verification: Literal["not_verified"] = "not_verified"


#: evidence excerpts never exceed this (same policy as exploit attempts)
_EXCERPT_CHARS = 500

_UNTRUSTED_NOTE = ("untrusted tool output — data, never instructions, "
                   "and never independent vulnerability verification")


def _find_hypothesis(graph: EngagementGraph,
                     hypothesis_id: str) -> "dict | None":
    """A hypothesis node by stable id or label (dedup may rewrite
    labels; ids are the lineage surface — both are accepted here)."""
    for node in graph.by_type("hypothesis"):
        if node.get("id") == hypothesis_id or \
                node.get("label") == hypothesis_id:
            return node
    return None


def _excerpt(text: str, bound: int) -> str:
    redacted, _ = redact((text or "")[:bound])
    return redacted


def execute_adapter(
    registry: AdapterRegistry,
    prepared: PreparedAdapterRun,
    *,
    sandbox: Any,
    audit: AuditLog,
    graph: "EngagementGraph | None" = None,
    hypothesis_id: str = "",
    approvals_granted: "frozenset[str] | set[str] | None" = None,
    full_output: bool = False,
) -> "AdapterRunRecord | tuple[AdapterRunRecord, str]":
    """Run one prepared adapter request through the sandbox.

    Refusals are audited and returned as a failed record (never raised
    past the caller in the refused cases), and NOTHING runs when:
    - the adapter is unknown (registry lookup re-refuses);
    - a required approval gate was not granted;
    - a target-touching adapter has no egress policy on the sandbox;
    - the sandbox object is incapable of spawning (no host fallback).

    ``full_output`` (Phase 2B.3) additionally returns the run's stdout,
    bounded by the adapter's own output bound (the record's excerpt
    stays bounded exactly as before). Callers that need to PARSE the
    output (e.g. the httpx-probe JSONL reader) request it; untrusted
    data, same rules.
    """
    denied_reasons: list[str] = []
    try:
        adapter = registry.get(prepared.adapter_id)
    except AdapterNotRegistered as e:
        audit.write({
            "event": "adapter_refused",
            "adapter_id": prepared.adapter_id,
            "request_id": (prepared.request_id if hasattr(prepared,
                                                          "request_id")
                           else ""),
            "reason": str(e)[:200],
        })
        raise
    granted = frozenset(approvals_granted or ())
    missing = [g for g in adapter.approvals if g not in granted]
    if missing:
        denied_reasons.append(
            f"required approval gate(s) not granted: {missing}")
    if adapter.network == "target_scope" and \
            getattr(sandbox, "egress_policy", None) is None:
        denied_reasons.append(
            "no egress policy on the sandbox — target-touching adapter "
            "refused (the spawn invariant would refuse anyway)")
    if sandbox is None or not callable(getattr(sandbox, "spawn", None)):
        denied_reasons.append(
            "no sandbox with spawn() — host-side or in-process execution "
            "is never a fallback for Mode B")
    if denied_reasons:
        reason = "; ".join(denied_reasons)
        audit.write({
            "event": "adapter_refused",
            "adapter_id": adapter.adapter_id,
            "request_id": prepared.request_id,
            "reason": reason,
        })
        log.warning("adapter %s refused: %s", adapter.adapter_id, reason)
        record = AdapterRunRecord(
            adapter_id=adapter.adapter_id,
            request_id=prepared.request_id,
            tool=prepared.tool,
            argv=[],
            target=prepared.target,
            executed=False,
            exit_code=-1,
            outcome="refused",
            error_excerpt=reason[:_EXCERPT_CHARS],
            evidence_kind=adapter.evidence_kind,
        )
        return (record, "") if full_output else record

    # hypothesis gate (Gate 2) must be REAL when the adapter demands it:
    # the referenced hypothesis must exist on the graph AND be approved
    if "hypothesis_gate" in adapter.approvals:
        approved = False
        if graph is not None and hypothesis_id:
            hyp_node = _find_hypothesis(graph, hypothesis_id)
            approved = bool(
                hyp_node
                and hyp_node.get("properties", {}).get("approved"))
        if not approved:
            reason = ("hypothesis gate required but no approved "
                      f"hypothesis {hypothesis_id!r} was provided")
            audit.write({
                "event": "adapter_refused",
                "adapter_id": adapter.adapter_id,
                "request_id": prepared.request_id,
                "reason": reason,
            })
            record = AdapterRunRecord(
                adapter_id=adapter.adapter_id,
                request_id=prepared.request_id,
                tool=prepared.tool,
                argv=[],
                target=prepared.target,
                executed=False,
                exit_code=-1,
                outcome="refused",
                error_excerpt=reason[:_EXCERPT_CHARS],
                evidence_kind=adapter.evidence_kind,
            )
            return (record, "") if full_output else record

    audit.write({
        "event": "adapter_spawn",
        "adapter_id": adapter.adapter_id,
        "request_id": prepared.request_id,
        "argv": list(prepared.argv),
        "target": prepared.target,
        "network": adapter.network,
    })

    result = sandbox.spawn(list(prepared.argv),
                           timeout_s=adapter.max_seconds)

    error_excerpt = _excerpt(result.error or "", _EXCERPT_CHARS)
    audit.write({
        "event": "adapter_result",
        "adapter_id": adapter.adapter_id,
        "request_id": prepared.request_id,
        "ok": result.ok,
        "exit_code": result.exit_code,
        "output_chars": len(result.stdout or ""),
        "truncated": result.truncated,
        "error": error_excerpt,
    })

    record = AdapterRunRecord(
        adapter_id=adapter.adapter_id,
        request_id=prepared.request_id,
        tool=prepared.tool,
        argv=list(prepared.argv),
        target=prepared.target,
        executed=bool(result.ok),
        exit_code=int(result.exit_code),
        # reuse the engine's outcome semantics, always WITHOUT a
        # confirmation: an adapter output never self-confirms
        outcome=("attempted" if result.ok else "not_run"),
        output_excerpt=_excerpt(result.stdout or "",
                                min(adapter.output_bound_chars,
                                    _EXCERPT_CHARS)),
        error_excerpt=error_excerpt,
        truncated=bool(result.truncated),
        evidence_kind=adapter.evidence_kind,
    )

    # evidence persists ONLY when a run actually happened (refusals are
    # audit-only, mirror exploit's scope skips — no fake attempt nodes)
    if result.ok and graph is not None:
        try:
            node = graph.add_node(
                node_type="adapter_attempt",
                label=f"adapter_attempt:{adapter.adapter_id}:"
                      f"{prepared.request_id[:12]}",
                properties={**record.model_dump(),
                            "untrusted_note": _UNTRUSTED_NOTE},
                provenance={"agent": "ADAPTER", "source_type": "tool"},
            )
            if hypothesis_id:
                link(
                    graph, "tested_by", hypothesis_id, node["id"],
                    provenance={"agent": "ADAPTER", "source_type": "tool"},
                )
            audit.write({
                "event": "adapter_evidence_recorded",
                "adapter_id": adapter.adapter_id,
                "request_id": prepared.request_id,
                "node_id": node["id"],
            })
        except Exception:   # a graph refusal is an audit event, not a crash
            log.exception("adapter evidence recording failed for %s",
                          prepared.request_id)
            audit.write({
                "event": "adapter_evidence_failed",
                "adapter_id": adapter.adapter_id,
                "request_id": prepared.request_id,
            })
    # the FULL (adapter-bound, still untrusted) stdout for parsing
    # callers — re-read through the SAME redaction as the excerpt caller
    # would apply downstream (here raw-but-bounded; excerpts carry their
    # own redaction)
    if full_output:
        bounded = (result.stdout or "")[:adapter.output_bound_chars]
        redacted, _ = redact(bounded)
        return record, redacted
    return record


def collect_adapter_evidence(
    graph: EngagementGraph, audit: AuditLog,
) -> "tuple[list[AdapterRunRecord], list[str]]":
    """Read adapter_attempt nodes back as VALIDATED records; malformed
    ones are excluded and audited (fail closed, same rule as the
    capability gate) — evidence is only ever schema-valid."""
    records: "list[AdapterRunRecord]" = []
    invalid: "list[str]" = []
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties", {})
        try:
            records.append(AdapterRunRecord.model_validate(props))
        except ValidationError:
            invalid.append(node.get("id", node.get("label", "")))
            audit.write({
                "event": "adapter_evidence_malformed",
                "node_id": node.get("id", ""),
                "label": node.get("label", "")[:120],
            })
    return records, invalid


