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

from pydantic import BaseModel, Field, ValidationError

from ..config import KryonsecConfig
from .audit import AuditLog
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)


class Hypothesis(BaseModel):
    """One vulnerability hypothesis proposed by the LLM."""

    id: str = Field(description="Short stable id, e.g. H1")
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
    tools: list[str] = Field(
        default_factory=list,
        description="Tools from the allowlist that could test this",
    )
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class HypothesisSet(BaseModel):
    """Structured LLM response for HYPOTHESIZE."""

    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=10)


def render_hypothesize_prompt(graph: EngagementGraph) -> str:
    """Render the Jinja2 prompt with the current passive-recon findings."""
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
    )
    template = env.get_template("hypothesize.jinja")

    subdomains = sorted(n["label"] for n in graph.by_type("subdomain"))
    paths = sorted(n["label"] for n in graph.by_type("path"))
    target_nodes = graph.by_type("target")
    target = target_nodes[0]["label"] if target_nodes else ""

    return template.render(
        target=target,
        subdomains=subdomains[:50],
        paths=paths[:50],
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


def propose_hypotheses(
    cfg: KryonsecConfig,
    prompt: str,
) -> HypothesisSet:
    """Ask the LLM for hypotheses, structured. Raises on failure.

    Tries Instructor (strict schema) when available; otherwise a JSON
    prompt + Pydantic validation with one repair retry.
    """
    system = (
        "You are the hypothesis engine of a purple-team engagement. "
        "You propose vulnerability hypotheses from recon data. "
        "You NEVER claim to have tested anything. Output JSON only."
    )
    model = cfg.general_search_model
    if model.startswith("gpt") and not cfg.openai_api_key:
        model = cfg.local_model

    try:
        import instructor  # optional strict path

        from litellm import completion

        client = instructor.from_litellm(completion)
        return client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            response_model=HypothesisSet,
            temperature=0.0,
            timeout=60,
        )
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
        '"rationale": "...", "cvss_vector": "...", "tools": ["..."], '
        '"confidence": 0.0-1.0}]}\n'
        "Maximum 10 hypotheses. No other text."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json_prompt},
    ]

    text = chat(cfg, messages, model=model)
    try:
        return HypothesisSet.model_validate(_extract_json(text))
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
        return HypothesisSet.model_validate(_extract_json(text))


class HypothesizeSubagent:
    """Runs the HYPOTHESIZE state. LLM proposes; nothing is executed."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        llm_fn: Callable[[str], HypothesisSet] | None = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        # injectable for tests; default does the real LLM call
        self.llm_fn = llm_fn or self._default_llm

    def _default_llm(self, prompt: str) -> HypothesisSet:
        return propose_hypotheses(self.cfg, prompt)

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "HYPOTHESIZE",
            "findings_nodes": len(self.graph.nodes),
        })

        try:
            prompt = render_hypothesize_prompt(self.graph)
            hypothesis_set = self.llm_fn(prompt)
        except Exception as e:
            # A dead LLM fails the state; it must never halt the engagement
            # silently — the audit records exactly why.
            self.audit.write({
                "event": "hypothesize_failed",
                "error": str(e)[:200],
            })
            log.warning("HYPOTHESIZE failed: %s", e)
            return SubagentResult(status="failed")

        for h in hypothesis_set.hypotheses:
            node = self.graph.add_node(
                node_type="hypothesis",
                label=h.id,
                properties={
                    "title": h.title,
                    "target_asset": h.target_asset,
                    "rationale": h.rationale,
                    "cvss_vector": h.cvss_vector,
                    "tools": h.tools,
                    "confidence": h.confidence,
                },
            )
            self.audit.write({
                "event": "hypothesis_proposed",
                "hypothesis_id": h.id,
                "target_asset": h.target_asset,
                "tools": h.tools,
                "confidence": h.confidence,
                "node_size": node["size_bytes"],
            })

        self.audit.write({
            "event": "hypothesize_done",
            "count": len(hypothesis_set.hypotheses),
        })
        return SubagentResult(status="ok")
