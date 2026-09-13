"""BLUE_TEAM subagent (spec v2.1.1 §4.2).

The LLM generates defensive recommendations — fixes and detection
rules — for each hypothesis/finding. Pure LLM: no tools, no state
transitions. Same structured-output strategy as HYPOTHESIZE (Instructor
when available, JSON+validation fallback).
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Literal

from pydantic import BaseModel, Field, ValidationError

from ..config import KryonsecConfig
from .audit import AuditLog
from .hypothesize import _extract_json
from .orchestrator import BudgetTracker, SubagentResult
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

# ---- blue-team static analyzers (tool expansion Phase 5) --------------------
# Fixed plan, no LLM input. Runs against the read-only /code mount of a
# user-provided folder (--code). hadolint is conditional on a Dockerfile.
# kube-bench is deliberately NOT here: it audits a live node's kubelet
# config, not a code folder — inside this sandbox it would test the
# sandbox itself (recorded in docs/TOOL-EXPANSION-2026-09-13.md).
BLUE_TEAM_SCAN_PLAN: list[tuple[str, list[str]]] = [
    ("semgrep", ["semgrep", "--config=auto", "/code"]),
    ("bandit", ["bandit", "-r", "/code"]),
    ("gitleaks", ["gitleaks", "detect", "--source", "/code"]),
    ("trivy", ["trivy", "fs", "--scanners", "vuln", "/code"]),
    ("checkov", ["checkov", "-d", "/code"]),
]
HADOLINT_PLAN_ENTRY = ("hadolint", ["hadolint", "/code/Dockerfile"])

# bounded evidence: scanner output can be enormous
MAX_SCANNER_EXCERPT = 2000

# Best-effort findings counters per tool. bandit/gitleaks EXIT 1 when
# they find something — that is findings, not failure.
_FINDING_COUNT_RES: dict[str, list[re.Pattern[str]]] = {
    "semgrep": [re.compile(r"(\d+) findings?\b")],
    "bandit": [re.compile(r"\bIssue:\s*\[")],
    "gitleaks": [re.compile(r"\bFinding:\s")],
    "trivy": [re.compile(r"Total:\s*(\d+)")],
    "checkov": [re.compile(r"Failed checks:\s*(\d+)")],
    "hadolint": [re.compile(r"^/code/Dockerfile:", re.MULTILINE)],
}


def _count_findings(tool: str, stdout: str) -> int | None:
    """Approximate the findings count from scanner text output. None when
    the output shape is unknown — never a guess presented as a count."""
    import json as _json

    # trivy/checkov often print JSON when configured — try that first
    try:
        data = _json.loads(stdout)
        if isinstance(data, dict):
            if tool == "trivy" and isinstance(data.get("Results"), list):
                return sum(len(r.get("Vulnerabilities") or [])
                           for r in data["Results"])
            if tool == "checkov" and isinstance(data.get("failed_checks"), list):
                return len(data["failed_checks"])
    except (ValueError, TypeError):
        pass
    for pattern in _FINDING_COUNT_RES.get(tool, []):
        matches = pattern.findall(stdout)
        if matches:
            # "N findings" styles report a number; occurrence styles count
            return int(matches[-1]) if matches[-1].isdigit() else len(matches)
    return None


def run_code_scanners(
    graph: EngagementGraph,
    sandbox,
    audit: AuditLog,
    allowlist=None,
    has_dockerfile: bool = False,
) -> int:
    """Pre-LLM tool phase: static analyzers over the /code mount.

    Every spawn is allowlist-validated and audited (state BLUE_TEAM);
    results become `scanner_result` graph nodes that the Jinja prompt
    renders as scanner evidence. A failing scanner is an audited skip —
    the LLM phase runs regardless. Returns the number of scanners that
    actually ran."""
    from .allowlist import ToolAllowlist

    allow = allowlist or ToolAllowlist()
    plan = list(BLUE_TEAM_SCAN_PLAN)
    if has_dockerfile:
        plan.append(HADOLINT_PLAN_ENTRY)

    ran = 0
    for tool, argv in plan:
        try:
            allow.validate(argv[0], argv)
            allow.check_blocklist(argv)
        except Exception as e:
            audit.write({
                "event": "scanner_rejected_by_allowlist",
                "tool": tool,
                "reason": str(e)[:200],
            })
            log.warning("blue_team: %s rejected by allowlist: %s", tool, e)
            continue
        audit.write({
            "event": "tool_spawn",
            "state": "BLUE_TEAM",
            "tool": tool,
            "argv": argv,
        })
        result = sandbox.spawn(argv)
        audit.write({
            "event": "tool_result",
            "state": "BLUE_TEAM",
            "tool": tool,
            "ok": result.ok,
            "exit_code": result.exit_code,
            "output_chars": len(result.stdout),
        })
        if not result.ok:
            continue  # spawn failed — audited, next scanner
        ran += 1
        properties: dict = {
            "tool": tool,
            "exit_code": result.exit_code,
            "stdout_chars": len(result.stdout),
            "excerpt": result.stdout[:MAX_SCANNER_EXCERPT],
        }
        count = _count_findings(tool, result.stdout)
        if count is not None:
            properties["findings_count"] = count
        graph.add_node(
            node_type="scanner_result", label=tool, properties=properties,
        )
    audit.write({
        "event": "scanners_done",
        "ran": ran,
        "planned": len(plan),
        "dockerfile": has_dockerfile,
    })
    return ran


class Remediation(BaseModel):
    """One defensive recommendation mapped to a hypothesis/finding."""

    hypothesis_id: str = Field(description="Which hypothesis this remediates, e.g. H1")
    title: str = Field(description="One-line fix title")
    fix: str = Field(description="How to fix it (concrete steps)")
    detection: str = Field(
        default="",
        description="Detection rule/log signature for defenders (optional)",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="low | medium | high | critical",
    )
    # Phase 5: LLM-suggested mappings — displayed in the report as
    # suggestions, never treated as verified fact
    cwe: str = Field(
        default="",
        description="CWE id if the issue maps cleanly, e.g. CWE-89 (suggested)",
    )
    owasp: str = Field(
        default="",
        description="OWASP category if applicable, e.g. A03:2021-Injection (suggested)",
    )
    attack: str = Field(
        default="",
        description="MITRE ATT&CK technique id if applicable, e.g. T1190 (suggested)",
    )


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
    # scanner evidence (Phase 5): normalized so StrictUndefined never trips
    scanners = [
        {
            "label": n["label"],
            "exit_code": n["properties"].get("exit_code", "?"),
            "findings_count": n["properties"].get("findings_count"),
            "excerpt": n["properties"].get("excerpt", ""),
        }
        for n in graph.by_type("scanner_result")
    ]
    target_nodes = graph.by_type("target")
    target = target_nodes[0]["label"] if target_nodes else ""

    return template.render(
        target=target, hypotheses=hypotheses, findings=findings,
        scanners=scanners,
    )


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
    # engagement data (exploit excerpts, findings) never goes to a
    # third-party LLM unredacted — spec §6.4 / CLAUDE.md rule 4. The
    # instructor path below calls the provider directly and would bypass
    # chat()'s gate, so gate here (same as HYPOTHESIZE): route local,
    # or redact when no local model is up.
    from ..llm import secrets_safe_prompt

    model, prompt = secrets_safe_prompt(cfg, model, prompt)

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
        '"fix": "...", "detection": "...", "severity": "medium", '
        '"cwe": "...", "owasp": "...", "attack": "..."}]}\n'
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
        budget: BudgetTracker | None = None,
        sandbox=None,
        code_folder: str | None = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.llm_fn = llm_fn or self._default_llm
        # engagement budget (spec §4.3): LLM states accrue their usage so
        # the orchestrator's budget guard can actually trip on tokens
        self.budget = budget
        # Phase 5: sandbox with the read-only /code mount + the host code
        # folder (for the Dockerfile check). Either missing => pure LLM.
        self.sandbox = sandbox
        self.code_folder = code_folder

    def _default_llm(self, prompt: str) -> RemediationSet:
        return generate_remediations(self.cfg, prompt)

    def _record_budget(self, prompt: str, result: RemediationSet) -> None:
        if self.budget is None:
            return
        from ..llm import count_tokens

        self.budget.record_usage(
            count_tokens(prompt) + count_tokens(result.model_dump_json()))

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "BLUE_TEAM",
            "hypotheses": len(self.graph.by_type("hypothesis")),
            "code_scan": bool(self.sandbox is not None and self.code_folder),
        })

        # ---- pre-LLM tool phase (Phase 5): static analyzers over /code ----
        # A scanner failure is an audited skip — the LLM phase runs
        # regardless, exactly like a flaky passive source.
        if self.sandbox is not None and self.code_folder:
            try:
                from pathlib import Path

                has_dockerfile = Path(self.code_folder, "Dockerfile").is_file()
                run_code_scanners(
                    self.graph, self.sandbox, self.audit,
                    has_dockerfile=has_dockerfile,
                )
            except Exception as e:
                self.audit.write({
                    "event": "scanners_failed",
                    "error": str(e)[:200],
                })
                log.warning("blue-team scanners failed: %s", e)

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

        self._record_budget(prompt, remediation_set)

        for r in remediation_set.remediations:
            node = self.graph.add_node(
                node_type="remediation",
                label=r.hypothesis_id,
                properties={
                    "title": r.title,
                    "fix": r.fix,
                    "detection": r.detection,
                    "severity": r.severity,
                    "cwe": r.cwe,
                    "owasp": r.owasp,
                    "attack": r.attack,
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
