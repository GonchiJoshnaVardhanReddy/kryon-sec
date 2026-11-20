"""Read-only questions about a Purple Team engagement.

While an engagement runs (or after it finishes), the operator can ask
"what is the Recon agent doing?" or "why did Nmap fail?". Answering a
question must never start an engagement, run a tool, mutate the workflow,
or write to the audit chain: this module only READS the presentation
snapshot the workspace controller already reduced from real audit events.

Two answer paths, both derived only from the snapshot:

* the local Ollama model, prompted with the snapshot and forbidden from
  inventing results (plain completion — no tools are ever attached, so an
  answer cannot trigger execution);
* a deterministic summary built from the same snapshot, used whenever the
  local model is unavailable or refuses — the operator always gets a real,
  bounded answer, never a made-up one.

Privacy: engagement data never leaves this machine. The snapshot contains
the target, stages, findings and tool activity, so it is sent only to a
local ``ollama/`` model at a loopback endpoint. There is no hosted fallback
and no provider routing. If that path is unavailable or misconfigured, the
deterministic summary is returned without any remote request. Redaction is
defence in depth, never a licence to export engagement data.
"""

from __future__ import annotations

from typing import Any

from ..secrets import redact

# Fallback vocabulary, used when purple.ui's tables cannot be imported.
# The real tables are imported lazily so this module stays importable in a
# bare environment (the full ones only add words, never behaviour).
_MIN_STATE_ACTION: dict[str, str] = {
    "RECON_PASSIVE": "Collecting external intelligence",
    "RECON_ACTIVE": "Mapping reachable services",
    "HYPOTHESIZE": "Generating vulnerability hypotheses",
    "HUMAN_REVIEW": "Waiting for operator approval",
    "EXPLOIT": "Testing approved hypotheses",
    "POST_EXPLOIT": "Enumerating approved access",
    "VERIFY": "Independently confirming findings",
    "BLUE_TEAM": "Generating remediation guidance",
    "REPORT": "Compiling evidence and report",
}

QUESTION_SYSTEM_PROMPT = (
    "You answer the operator's questions about ONE Kryonsec Purple Team "
    "engagement. You are given a snapshot of that engagement only.\n"
    "Rules:\n"
    "- Use ONLY facts present in the snapshot. Never invent tool results, "
    "findings, CVEs, hostnames, or timings.\n"
    "- If the snapshot does not contain the answer, say exactly that.\n"
    "- Answer in simple English, 6 sentences or fewer.\n"
    "- You cannot run anything, change anything, or approve anything: you "
    "only explain what the snapshot records."
)


def _state_action(state: str) -> str:
    if not state:
        return "waiting to start"
    try:
        from ..purple.ui import STATE_ACTION as _full

        table = _full
    except Exception:  # pragma: no cover - import is guaranteed in product
        table = _MIN_STATE_ACTION
    return table.get(state, state.replace("_", " ").lower())


def _fmt_counts(counts: dict[str, Any]) -> str:
    parts = []
    assets = int(counts.get("subdomains", 0) or 0) + int(counts.get("endpoints", 0) or 0)
    if assets:
        parts.append(f"assets discovered {assets}")
    for key, label in (
        ("hypotheses", "hypotheses"),
        ("findings", "findings"),
        ("evidence", "evidence pieces"),
        ("errors", "tool errors"),
    ):
        value = int(counts.get(key, 0) or 0)
        if value:
            parts.append(f"{label} {value}")
    return ", ".join(parts) or "nothing recorded yet"


def engagement_context_text(snapshot: dict[str, Any]) -> str:
    """A compact, redacted text rendering of one engagement snapshot."""
    lines = [
        f"TARGET: {snapshot.get('target') or 'unknown'}",
        f"ENGAGEMENT ID: {snapshot.get('engagement_id') or 'unknown'}",
    ]
    state = snapshot.get("current_state") or ""
    if state:
        lines.append(f"CURRENT STAGE: {state} ({_state_action(state)})")
    else:
        lines.append("CURRENT STAGE: not started yet")
    completed = [str(s) for s in (snapshot.get("completed_states") or [])]
    if completed:
        lines.append("STAGES COMPLETED: " + ", ".join(completed))
    failed = [str(s) for s in (snapshot.get("failed_states") or [])]
    if failed:
        lines.append("STAGES THAT FAILED: " + ", ".join(failed))
    sandbox = snapshot.get("sandbox_status") or "unknown"
    lines.append(f"SANDBOX: {sandbox}")
    detail = snapshot.get("sandbox_detail")
    if detail:
        lines.append(f"SANDBOX DETAIL: {detail}")
    lines.append(f"RECORD COUNTS: {_fmt_counts(snapshot.get('counts') or {})}")

    findings = snapshot.get("findings") or []
    if findings:
        lines.append("FINDINGS (label, standing, severity):")
        for label, standing, severity in findings:
            lines.append(f"- {label} [{standing}, severity {severity}]")
    else:
        lines.append("FINDINGS: none recorded yet")

    tools = snapshot.get("tools") or []
    if tools:
        lines.append("RECENT TOOL ACTIVITY (most recent last):")
        for row in tools[-10:]:
            duration = row.get("duration")
            timing = f" in {duration:.1f}s" if isinstance(duration, (int, float)) else ""
            lines.append(
                f"- {row.get('name')} — {row.get('status')}{timing}"
                + (f" ({row.get('detail')})" if row.get("detail") else "")
            )
    else:
        lines.append("TOOL ACTIVITY: none recorded yet")

    notices = snapshot.get("notices") or []
    if notices:
        lines.append("RECENT NOTICES AND ERRORS:")
        for notice in notices[-6:]:
            lines.append(f"- {notice}")

    outcome = snapshot.get("outcome")
    if outcome:
        lines.append(f"ENGAGEMENT OUTCOME: {outcome}")
        halt = snapshot.get("halt_reason")
        if halt:
            lines.append(f"HALT REASON: {halt}")
    report = snapshot.get("report_path")
    if report:
        lines.append(f"REPORT PATH: {report}")
    return "\n".join(lines)


def engagement_plain_summary(snapshot: dict[str, Any]) -> str:
    """The deterministic answer, used when no model can answer.

    Every sentence is derived from the snapshot alone; nothing is invented.
    """
    parts: list[str] = []
    target = snapshot.get("target") or "the target"
    state = snapshot.get("current_state") or ""
    outcome = snapshot.get("outcome")
    if outcome:
        parts.append(f"The engagement on {target} has finished: {outcome}.")
        halt = snapshot.get("halt_reason")
        if halt:
            parts.append(f"It stopped early — reason: {halt}.")
    elif state:
        parts.append(
            f"The engagement on {target} is currently in the {state} stage "
            f"({_state_action(state)})."
        )
    else:
        parts.append(f"The engagement on {target} has not started its first stage yet.")

    completed = [str(s) for s in (snapshot.get("completed_states") or [])]
    if completed:
        parts.append("Stages completed so far: " + ", ".join(completed) + ".")

    failed = [str(s) for s in (snapshot.get("failed_states") or [])]
    if failed:
        parts.append(
            "Stages that did not finish: " + ", ".join(failed) + "."
        )

    counts = snapshot.get("counts") or {}
    findings = int(counts.get("findings", 0) or 0)
    verified = sum(
        1 for row in (snapshot.get("findings") or []) if row[1] == "verified"
    )
    if findings:
        parts.append(
            f"{findings} finding(s) recorded, {verified} of them verified."
        )
        top = (snapshot.get("findings") or [])[-3:]
        for label, standing, severity in top:
            parts.append(f"- {label} [{standing}, severity {severity}]")
    else:
        parts.append("No findings recorded yet.")

    errors = int(counts.get("errors", 0) or 0)
    tools = snapshot.get("tools") or []
    failures = [row for row in tools if row.get("status") == "failed"]
    if failures:
        last = failures[-1]
        parts.append(
            f"{errors} tool error(s) so far. The latest failed tool was "
            f"{last.get('name')} — {last.get('detail') or 'reason not recorded'}."
        )
    elif tools:
        running = [row for row in tools if row.get("status") == "running"]
        if running:
            names = ", ".join(str(row.get("name")) for row in running[-3:])
            parts.append(f"Tool(s) running right now: {names}.")
        else:
            last = tools[-1]
            parts.append(
                f"The most recent tool was {last.get('name')} ({last.get('status')})."
            )

    notices = [str(n) for n in (snapshot.get("notices") or [])]
    if notices:
        parts.append("Latest notice: " + notices[-1])

    if errors == 0 and not failures and not tools:
        parts.append("No tools have run yet.")
    summary = " ".join(parts)
    return summary[:4000]


def answer_question(cfg: Any, snapshot: dict[str, Any], question: str) -> str:
    """Answer one operator question. Runs on a worker thread.

    The model call is a plain completion with NO tools attached, so an
    answer cannot execute anything. It goes only to the local Ollama model
    at a loopback endpoint — never to a hosted provider. Any local failure
    (unavailable, invalid model, non-loopback endpoint, refused, timeout)
    falls back to the deterministic summary, and the fallback is labelled
    honestly.
    """
    from ..llm import LlmUnavailable, chat_local

    context = engagement_context_text(snapshot)
    question_text = redact(str(question or ""))[0][:2000]
    fallback_note = ""
    try:
        reply = chat_local(
            cfg,
            [
                {"role": "system", "content": QUESTION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"ENGAGEMENT SNAPSHOT:\n{context}\n\n"
                        f"OPERATOR QUESTION: {question_text}"
                    ),
                },
            ],
        )
        text = redact(str(reply or ""))[0].strip()
        if text:
            return text[:4000]
        fallback_note = "The local assistant returned an empty answer."
    except LlmUnavailable as exc:
        fallback_note = (
            "The local assistant is unavailable "
            f"({redact(str(exc))[0]})."
        )
    except Exception as exc:  # presentation must never break the engagement
        fallback_note = f"The local assistant could not be reached ({type(exc).__name__})."
    summary = engagement_plain_summary(snapshot)
    return f"(local summary — {fallback_note})\n{summary}"


__all__ = [
    "QUESTION_SYSTEM_PROMPT",
    "answer_question",
    "engagement_context_text",
    "engagement_plain_summary",
]
