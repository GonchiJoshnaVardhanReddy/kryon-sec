"""BLUE_TEAM subagent (spec v2.1.1 §4.2).

The LLM generates defensive recommendations — fixes and detection
rules — for each hypothesis/finding. Pure LLM: no tools, no state
transitions. Same structured-output strategy as HYPOTHESIZE (Instructor
when available, JSON+validation fallback).
"""

from __future__ import annotations

import logging
from typing import Callable

from pydantic import BaseModel, Field, ValidationError

from ..config import KryonsecConfig
from .audit import AuditLog
from .hypothesize import _extract_json
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)


class Remediation(BaseModel):
    """One defensive recommendation mapped to a hypothesis/finding."""

    hypothesis_id: str = Field(description="Which hypothesis this remediates, e.g. H1")
    title: str = Field(description="One-line fix title")
    fix: str = Field(description="How to fix it (concrete steps)")
    detection: str = Field(
        default="",
        description="Detection rule/log signature for defenders (optional)",
    )
    severity: str = Field(default="medium", description="low | medium | high | critical")


class RemediationSet(BaseModel):
    remediations: list[Remediation] = Field(default_factory=list, max_length=20)


def render_blue_team_prompt(graph: EngagementGraph) -> str:
    """Render the Jinja2 prompt with hypotheses + approval decisions."""
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        autoescape=False,
    )
    template = env.get_template("blue_team.jinja")

    hypotheses = [
        {
            "id": n["label"],
            **{k: v for k, v in n["properties"].items()},
        }
        for n in graph.by_type("hypothesis")
    ]
    findings = [
        {"label": n["label"], **n["properties"]}
        for n in graph.by_type("finding")
    ]
    target_nodes = graph.by_type("target")
    target = target_nodes[0]["label"] if target_nodes else ""

    return template.render(target=target, hypotheses=hypotheses, findings=findings)


def generate_remediations(cfg: KryonsecConfig, prompt: str) -> RemediationSet:
    """Ask the LLM for remediations. Raises on failure.

    Instructor when available; JSON prompt + validation otherwise,
    with one repair retry (same shape as HYPOTHESIZE).
    """
    system = (
        "You are the blue-team engine of a purple-team engagement. "
        "You write defensive recommendations: concrete fixes and detection "
        "signatures. Output JSON only."
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
            response_model=RemediationSet,
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
        '{"remediations": [{"hypothesis_id": "H1", "title": "...", '
        '"fix": "...", "detection": "...", "severity": "medium"}]}\n'
        "No other text."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json_prompt},
    ]

    text = chat(cfg, messages, model=model)
    try:
        return RemediationSet.model_validate(_extract_json(text))
    except (ValueError, ValidationError):
        retry = messages + [
            {"role": "assistant", "content": text[:2000]},
            {
                "role": "user",
                "content": "That was not valid JSON for the schema. "
                "Output ONLY the corrected JSON object now.",
            },
        ]
        text = chat(cfg, retry, model=model)
        return RemediationSet.model_validate(_extract_json(text))


class BlueTeamSubagent:
    """Runs the BLUE_TEAM state. LLM proposes remediations; nothing executes."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        llm_fn: Callable[[str], RemediationSet] | None = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.llm_fn = llm_fn or self._default_llm

    def _default_llm(self, prompt: str) -> RemediationSet:
        return generate_remediations(self.cfg, prompt)

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "BLUE_TEAM",
            "hypotheses": len(self.graph.by_type("hypothesis")),
        })

        try:
            prompt = render_blue_team_prompt(self.graph)
            remediation_set = self.llm_fn(prompt)
        except Exception as e:
            self.audit.write({
                "event": "blue_team_failed",
                "error": str(e)[:200],
            })
            log.warning("BLUE_TEAM failed: %s", e)
            return SubagentResult(status="failed")

        for r in remediation_set.remediations:
            node = self.graph.add_node(
                node_type="remediation",
                label=r.hypothesis_id,
                properties={
                    "title": r.title,
                    "fix": r.fix,
                    "detection": r.detection,
                    "severity": r.severity,
                },
            )
            self.audit.write({
                "event": "remediation_proposed",
                "hypothesis_id": r.hypothesis_id,
                "severity": r.severity,
                "node_size": node["size_bytes"],
            })

        self.audit.write({
            "event": "blue_team_done",
            "count": len(remediation_set.remediations),
        })
        return SubagentResult(status="ok")
