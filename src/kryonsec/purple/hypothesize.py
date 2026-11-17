"""HYPOTHESIZE subagent (spec v2.1.1 §4.2).

The LLM proposes vulnerability hypotheses as structured Pydantic data.
The orchestrator stays deterministic: this subagent only produces data
(no state transitions, no tool calls — spec rule: pure LLM state).

Structured output strategy: Instructor when the package is installed,
otherwise a JSON-mode prompt validated with Pydantic + one retry.
"""

from __future__ import annotations

import json
import logging
from typing import Callable

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..config import KryonsecConfig
from .audit import AuditLog
from .context import ContextBudget, build_investigation_context
from .orchestrator import BudgetTracker, SubagentResult
from .recon_passive import EngagementGraph
# A14: the engine-derived views moved to their own module — the report, the
# blue-team prompt, human review, the memory browser and this subagent all
# render the same answers from it. Re-exported here because every caller has
# always imported them from this module (A11 put them here).
from .views import (  # noqa: F401
    _ASSET_NODE_TYPES,
    _claim_text,
    ASSET_NODE_TYPES,
    ATTEMPT_CONFIRMED,
    ATTEMPT_INCONCLUSIVE,
    ATTEMPT_NONE,
    ATTEMPT_NOTES,
    ATTEMPT_NOT_RUN,
    ATTEMPT_UNRECORDED,
    BASIS_NOTES,
    BASIS_PROPOSED,
    BASIS_SUPPORTED,
    BASIS_TESTED,
    BASIS_VALIDATED,
    MAX_ASSET_CHARS,
    MAX_RELATIONSHIP_CHARS,
    MAX_ROLE_CHARS,
    OUTCOMES_RUN,
    asset_key,
    attempt_names,
    attempt_outcome,
    claim_text,
    exploit_status,
    observed_assets,
    primary_asset_observed,
    related_asset_views,
    relationship_basis,
)

log = logging.getLogger(__name__)

# Bumped whenever the prompt or the node contract changes, so a hypothesis
# node can be read back against the shape that produced it. v2 is the
# provenance-aware contract (A1): nodes are "proposed", never "observed".
# v3 adds the structured multi-asset claim (A11); a v2 node has neither
# field and reads exactly as it did.
PROMPT_VERSION = "hypothesize-v3"


# --- the multi-asset claim and its standing (A11) ---------------------------
#
# The claim caps, the standing ladder and the engine-derived views live in
# ``views`` — they are what the *engagement* can say about a claim, not part
# of the subagent that produced it, and the memory browser has to render the
# same answers without holding a reference to a subagent (A14). Re-exported
# at the top of this module.
#
# What stays here is this subagent's own contract, and one rule about it:
# every cap is applied by *sanitising*, not by rejecting. A model that writes
# something useful in a badly-shaped way should still be proposing it — a
# ValidationError fails the whole state (the JSON path retries once, then
# HYPOTHESIZE dies), and a formatting excess is not worth an engagement.
# Sanitising also means the stored value is bounded whatever the model did,
# which is what "untrusted" has to mean in practice. The *standing* of the
# claim is never a field at all: see ``views``.
MAX_RELATED_ASSETS = 4


class AssetReference(BaseModel):
    """One further asset a hypothesis says it needs, and the part it plays.

    A claim about the target's surface, never an observation: nothing here
    says the asset exists, belongs to the engagement, or is reachable from
    the hypothesis's own asset. The engine decides that
    (:func:`related_asset_views`), not this.
    """

    # ``["/a", "/b"]`` is read as two references that give no role — a model
    # that names assets without roles is unambiguous about what it means.
    @model_validator(mode="before")
    @classmethod
    def _from_shorthand(cls, value):
        if isinstance(value, str):
            return {"asset": value}
        return value

    asset: str = Field(
        default="", description="The referenced asset, e.g. /admin/list.asp"
    )
    role: str = Field(
        default="", description="What this asset does in the relationship, "
        "e.g. 'carries the input the other acts on'"
    )

    @field_validator("asset", "role", mode="before")
    @classmethod
    def _bounded(cls, value, info):
        limit = MAX_ASSET_CHARS if info.field_name == "asset" else MAX_ROLE_CHARS
        return _claim_text(value, limit)


class Hypothesis(BaseModel):
    """One vulnerability hypothesis proposed by the LLM."""

    # id format is rigid where it MATTERS: ids join labels like
    # "H1:sqlmap", so a ':' in an id would silently corrupt the
    # tested/confirmed/verify joins (split(":")). Everything else is
    # deliberately loose so ids LLMs naturally emit ('1', 'H1',
    # 'sqli-showthread-id') all pass — the tight ^H…$ pattern was a
    # v1.1.1 regression that zeroed whole hypothesis sets.
    id: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$",
        description="Short stable id, e.g. H1 (letters/digits/-/_ only, no colon)",
    )
    title: str = Field(description="One-line hypothesis, plain language")
    target_asset: str = Field(
        description="Which asset it applies to — full path WITH query string "
        "when one exists (e.g. /ListProducts.asp?artist=1)"
    )
    rationale: str = Field(description="Why recon suggests this (evidence-based)")
    cvss_vector: str = Field(
        default="",
        description="CVSS 3.1 vector string guess, e.g. AV:N/AC:L/...",
    )
    cve: str = Field(
        default="",
        description="CVE id when the hypothesis names a specific known "
        "vulnerability (e.g. CVE-2021-44228), else empty",
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Tools from the allowlist that could test this",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    # A11 — the structured multi-asset claim. Optional: a legacy hypothesis
    # (or a single-asset one) has neither, and both default to empty. Extra
    # keys in the model's reply are ignored (pydantic's default), which is
    # what keeps a model from inventing, say, a `validated: true` field.
    related_assets: list[AssetReference] = Field(
        default_factory=list,
        description="Further assets this depends on, each with its role",
    )
    relationship: str = Field(
        default="",
        description="The proposed relationship between the assets — a claim, "
        "never something observed or tested",
    )

    @field_validator("relationship", mode="before")
    @classmethod
    def _bounded_relationship(cls, value):
        return _claim_text(value, MAX_RELATIONSHIP_CHARS)

    @field_validator("related_assets", mode="before")
    @classmethod
    def _bounded_references(cls, value):
        """At most :data:`MAX_RELATED_ASSETS` references that name an asset.

        The list is the model's, so it is bounded and filtered rather than
        trusted: an entry that names no asset (or is not an asset reference
        at all) is dropped instead of failing the state. The drop happens
        *before* the cap, so a model that pads the list with junk cannot
        push a real reference past the limit and out of the claim. Trimming
        here means no later reader has to re-check the bound.
        """
        if not isinstance(value, (list, tuple)):
            return []
        kept: list = []
        for entry in value:
            if isinstance(entry, str):
                entry = {"asset": entry}
            elif isinstance(entry, AssetReference):
                entry = entry.model_dump()
            elif not isinstance(entry, dict):
                continue
            if not _claim_text(entry.get("asset"), MAX_ASSET_CHARS):
                continue  # names nothing: no claim, and no slot taken
            kept.append(entry)
            if len(kept) == MAX_RELATED_ASSETS:
                break
        return kept


class HypothesisSet(BaseModel):
    """Structured LLM response for HYPOTHESIZE."""

    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=10)

    @property
    def has_unique_ids(self) -> bool:
        ids = [h.id for h in self.hypotheses]
        return len(ids) == len(set(ids))


def render_hypothesize_prompt(
    graph: EngagementGraph,
    budget: ContextBudget | None = None,
) -> str:
    """Render the Jinja2 prompt with the investigation context (A4).

    The evidence the model sees is the A2/A3 context block: one allowlisted,
    redacted, single-line, token-fitted rendering of the graph. This used to
    flatten subdomains, paths, notes and services here, each with its own
    hardcoded slice and no way to report what had been left out.

    The graph is read, never written: everything the block contains is a
    snapshot taken by :func:`build_investigation_context`.

    ``budget`` is the caller's :class:`ContextBudget`; None uses the
    default, which is what the HYPOTHESIZE state runs with.
    """
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    from .allowlist import exploit_tool_names

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
    )
    template = env.get_template("hypothesize.jinja")

    target_nodes = graph.by_type("target")
    target = target_nodes[0]["label"] if target_nodes else ""
    context = build_investigation_context(graph, budget)

    return template.render(
        target=target,
        # the rendered block, not the object: the template may not reach
        # back into the graph through it
        context=context.text,
        # L8: the tool list is generated from the allowlist module — a
        # hardcoded copy here silently drifted whenever a tool was added.
        # A10: the *names* only. One EXPLOIT_TEMPLATES key is a script
        # inside the sandbox image, allowlisted so enrichment can spawn it;
        # advertising it here invited a `tools` value the execution engine
        # could only skip.
        tools=exploit_tool_names(),  # order-stable dict keys
    )


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of an LLM reply (handles fences)."""
    text = text.strip()
    if text.startswith("```"):
        # strip a code fence: ```json ... ```
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found in LLM reply")
    return json.loads(text[start : end + 1])


def propose_hypotheses_with_model(
    cfg: KryonsecConfig,
    prompt: str,
) -> tuple[HypothesisSet, str | None]:
    """Ask the LLM for hypotheses, structured. Raises on failure.

    Tries Instructor (strict schema) when available; otherwise a JSON
    prompt + Pydantic validation with one repair retry.

    Returns the set and the model that served it, or None when that is
    not genuinely knowable. The Instructor path calls the provider
    directly with an explicit model and no fallback configured, so a
    returned result means that model answered. The JSON path goes through
    `llm.chat`, which rewrites the model for provider isolation, the
    secrets gate and same-provider fallback without reporting the
    substitution — so it returns None rather than naming a configured
    model that may not be the one that ran.
    """
    from ..llm import LlmUnavailable, llm_disabled

    if llm_disabled():
        raise LlmUnavailable("LLM disabled by KRYONSEC_DISABLE_LLM")

    system = (
        "You are the hypothesis engine of a purple-team engagement. "
        "You propose vulnerability hypotheses from recon data. "
        "You NEVER claim to have tested anything. Output JSON only."
    )
    model = cfg.general_search_model
    if model.startswith("gpt") and not cfg.openai_api_key:
        model = cfg.local_model
    # engagement data (subdomains, Wayback paths with query strings) never
    # goes to a third-party LLM unredacted — spec §6.4 / CLAUDE.md rule 4.
    # secrets_safe_prompt never raises: a false-positive secret pattern in
    # recon data (e.g. '/login?password=forgot') must not kill the whole
    # HYPOTHESIZE state — it routes local, or redacts when no local model
    # is up (v1.1.1 regression: SecretsMustStayLocal crashed the state
    # and the engagement ended with zero hypotheses).
    from ..llm import secrets_safe_prompt

    model, prompt = secrets_safe_prompt(cfg, model, prompt)

    try:
        import instructor  # optional strict path

        from litellm import completion

        client = instructor.from_litellm(completion)
        result = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            response_model=HypothesisSet,
            temperature=0.0,
            timeout=60,
        )
        return result, model
    except ImportError:
        pass  # fall through to the JSON path
    except ValidationError:
        raise
    except Exception as e:  # provider error on the instructor path
        log.warning("instructor call failed (%s); trying JSON path", e)

    from ..llm import chat

    json_prompt = (
        f"{prompt}\n\n"
        "Respond with ONLY a JSON object of this exact shape:\n"
        '{"hypotheses": [{"id": "H1", "title": "...", "target_asset": "...", '
        '"rationale": "...", "cvss_vector": "...", "cve": "...", '
        '"tools": ["..."], "confidence": 0.0-1.0, '
        '"related_assets": [{"asset": "/other.asp?id=1", '
        '"role": "what this asset does in the relationship"}], '
        '"relationship": "how the assets are proposed to work together"}]}\n'
        "Maximum 10 hypotheses. No other text."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json_prompt},
    ]

    text = chat(cfg, messages, model=model)
    try:
        return HypothesisSet.model_validate(_extract_json(text)), None
    except (ValueError, ValidationError):
        # one repair retry with the parse error spelled out
        retry = messages + [
            {"role": "assistant", "content": text[:2000]},
            {
                "role": "user",
                "content": "That was not valid JSON for the schema. "
                "Output ONLY the corrected JSON object now.",
            },
        ]
        text = chat(cfg, retry, model=model)
        return HypothesisSet.model_validate(_extract_json(text)), None


def propose_hypotheses(cfg: KryonsecConfig, prompt: str) -> HypothesisSet:
    """The hypothesis set alone — the long-standing public signature."""
    return propose_hypotheses_with_model(cfg, prompt)[0]


class HypothesizeSubagent:
    """Runs the HYPOTHESIZE state. LLM proposes; nothing is executed."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        llm_fn: Callable[[str], HypothesisSet] | None = None,
        budget: BudgetTracker | None = None,
        sandbox: object | None = None,
        adapter_registry=None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        # injectable for tests; default does the real LLM call
        self.llm_fn = llm_fn or self._default_llm
        # the model that served the last proposal, when the provider was
        # explicit about it. None means "not knowable" — an injected
        # llm_fn, or the JSON path where llm.chat substitutes silently —
        # and is written to no node rather than guessed at.
        self._model_used: str | None = None
        # engagement budget (spec §4.3): LLM states accrue their usage so
        # the orchestrator's budget guard can actually trip on tokens
        self.budget = budget
        # sandbox for ExploitDB (searchsploit) enrichment; None = skipped
        # cleanly with an audited notice (HYPOTHESIZE runs on any OS)
        self.sandbox = sandbox
        # Phase 2B.4: the vetted tool adapters for enrichment (when
        # registered, searchsploit-term replaces the legacy table
        # lookup). None = legacy behavior, unchanged.
        self.adapter_registry = adapter_registry

    def _default_llm(self, prompt: str) -> HypothesisSet:
        result, model = propose_hypotheses_with_model(self.cfg, prompt)
        self._model_used = model
        return result

    def _audit_usage(self, records: list[dict]) -> None:
        """Audit the REAL usage of this state's LLM calls (chain-visible).

        One llm_usage event per captured record. Token counts are always
        provider-reported; cost_usd appears only when the provider's cost
        map could price the model — absent means unknown, never invented.
        """
        for r in records:
            event = {
                "event": "llm_usage",
                "state": "HYPOTHESIZE",
                "model": r.get("model"),
                "routed_model": r.get("routed_model"),
                "prompt_tokens": r.get("prompt_tokens"),
                "completion_tokens": r.get("completion_tokens"),
                "total_tokens": r.get("total_tokens"),
            }
            if r.get("cost_usd") is not None:
                event["cost_usd"] = r.get("cost_usd")
            self.audit.write(event)

    def _record_budget(
        self, prompt: str, result: HypothesisSet | None,
        usage_records: list[dict] | None = None,
    ) -> None:
        """Accrue the engagement budget (spec §4.3).

        REAL provider-reported usage (estimate=False) when the provider
        told us the token counts; the local token count stays the fallback
        and is visible as an estimate. A failed state accrues only what
        its attempts actually reported — a completed-but-invalid reply is
        still real spend.
        """
        records = list(usage_records or [])
        self._audit_usage(records)
        if self.budget is None:
            return
        real = [r for r in records if r.get("total_tokens") is not None]
        if real:
            self.budget.record_usage(
                sum(int(r["total_tokens"]) for r in real),
                sum(
                    float(r["cost_usd"]) for r in records
                    if r.get("cost_usd") is not None),
                estimate=False,
            )
            return
        if result is None:  # failed state and nothing real to report
            return
        from ..llm import count_tokens

        self.budget.record_usage(
            count_tokens(prompt) + count_tokens(result.model_dump_json()))

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "HYPOTHESIZE",
            "findings_nodes": len(self.graph.nodes),
        })

        # last run's model must not be attributed to this run's nodes
        self._model_used = None

        # Drain the REAL provider usage appended during this state's LLM
        # call(s). The orchestrator is sequential, so nothing else makes
        # LLM calls between here and the call — the delta belongs to this
        # state.
        from ..llm import usage_log

        usage_start = len(usage_log())
        prompt: str | None = None
        hypothesis_set: HypothesisSet | None = None
        try:
            prompt = render_hypothesize_prompt(self.graph)
            hypothesis_set = self.llm_fn(prompt)
        except Exception as e:
            # A dead LLM fails the state; it must never halt the engagement
            # silently — the audit records exactly why. Attempts that DID
            # complete before the failure are still real spend: audit and
            # accrue them.
            self._record_budget(prompt, None, usage_log()[usage_start:])
            self.audit.write({
                "event": "hypothesize_failed",
                "error": str(e)[:200],
            })
            log.warning("HYPOTHESIZE failed: %s", e)
            return SubagentResult(status="failed")

        self._record_budget(
            prompt, hypothesis_set, usage_log()[usage_start:])

        for h in hypothesis_set.hypotheses:
            # A hypothesis is what a model guessed, not something the
            # engagement observed: the status and provenance say so, so a
            # reader can never mistake it for recon. `model` is written
            # only when the provider actually told us which one answered.
            provenance = {
                "source_type": "model",
                "source": "HYPOTHESIZE",
                "agent": "HYPOTHESIZE",
                "prompt_version": PROMPT_VERSION,
            }
            if self._model_used:
                provenance["model"] = self._model_used
            properties = {
                "title": h.title,
                "target_asset": h.target_asset,
                "rationale": h.rationale,
                "cvss_vector": h.cvss_vector,
                "cve": h.cve,
                "tools": h.tools,
                "confidence": h.confidence,
            }
            # A11: the claim is written only when the model actually made
            # one, so a single-asset hypothesis's node is byte-identical to
            # what every earlier phase wrote. The model's text arrives here
            # already bounded and single-lined (see _claim_text) — this is a
            # claim, and the node's status/provenance say whose.
            if h.related_assets:
                properties["related_assets"] = [
                    ref.model_dump() for ref in h.related_assets]
            if h.relationship:
                properties["relationship"] = h.relationship
            node = self.graph.add_node(
                node_type="hypothesis",
                label=h.id,
                properties=properties,
                provenance=provenance,
                status="proposed",
            )
            self.audit.write({
                "event": "hypothesis_proposed",
                "hypothesis_id": h.id,
                "target_asset": h.target_asset,
                "tools": h.tools,
                "confidence": h.confidence,
                # how many further assets the model claimed, so the chain
                # records that a multi-asset claim was made at all
                "related_assets": len(h.related_assets),
                "node_size": node["size_bytes"],
            })
        # duplicate ids would corrupt the finding->hypothesis joins
        # (EXPLOIT labels, VERIFY lookups, the report's tested/confirmed
        # sets) — dedupe deterministically instead of trusting the LLM
        if not hypothesis_set.has_unique_ids:
            self.audit.write({
                "event": "hypothesize_duplicate_ids",
                "note": "LLM returned duplicate hypothesis ids — deduped",
            })
            seen: set[str] = set()
            deduped = []
            for n in self.graph.by_type("hypothesis"):
                if n["label"] in seen:
                    self.graph.remove_node(n)
                else:
                    seen.add(n["label"])
                    deduped.append(n)
            log.warning("hypothesize: duplicate ids deduped (%d kept)", len(deduped))

        # ---- enrichment (tool expansion Phase 3) ---------------------------
        # Public-risk context (NVD/CPE, KEV, EPSS, ExploitDB) for hypotheses
        # that name a CVE. All third-party fetches, target never contacted.
        # Enrichment can never fail the state — the worst case is an audited
        # skip, exactly like a flaky passive source.
        try:
            from .enrichment import enrich_hypotheses

            enrich_hypotheses(
                self.cfg, self.graph, self.audit, sandbox=self.sandbox,
                adapter_registry=self.adapter_registry)
        except Exception as e:
            self.audit.write({
                "event": "enrichment_failed",
                "error": str(e)[:200],
            })
            log.warning("hypothesis enrichment failed: %s", e)

        self.audit.write({
            "event": "hypothesize_done",
            "count": len(hypothesis_set.hypotheses),
        })
        return SubagentResult(status="ok")
