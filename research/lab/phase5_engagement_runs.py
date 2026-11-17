"""IEEE-research Phase 5 — full engagements through the REAL product path
(APPROVED scope only).

Operator-approved 2026-11-16 (research/lab/README.md): target
juice-shop.lab = 10.213.43.10, HTTP port 80 only.

This harness runs the REAL product path — the same function the
`kryonsec purple` command uses, not a re-implementation:

    cli._run_purple(cfg, "juice-shop.lab", engagement_id,
                    output=False,
                    human_reviewer=<auto-approver>,
                    post_exploit_approver=<always-False>)

which is: load_config -> start_engagement (10-state orchestrator,
BudgetTracker, EgressGate, KaliSandbox gVisor) -> ... -> REPORT, with the
graph persisted to PostgreSQL and every decision appended to the
SHA256-chained audit chain.

Run modes
  full      LLM ON (openai gpt-6-astra per config.toml). Gate 2
            approvals are AUTOMATION-INJECTED (non-human): every
            hypothesis the engine proposes is approved. Gate 3
            (post-exploitation) ALWAYS refuses — the engagement never
            goes past a shell, by design.
  llm-off   KRYONSEC_DISABLE_LLM=1 (the product's own disable gate):
            zero LLM calls. Recon runs for real; HYPOTHESIZE and
            BLUE_TEAM fail audited; zero hypotheses => no EXPLOIT.

Honesty rules baked into every manifest
  - approval_provenance: "automation-injected (non-human)" — the Gate-2
    decisions were NOT made by a person.
  - infrastructure success is NOT detection performance: this manifest
    records what the engagement DID. Scoring against the 118-challenge
    ground truth is Phase 6, never this file.
  - LLM tokens are provider-reported (REAL) via llm_usage audit events;
    cost is summed ONLY over calls the provider's cost map could price,
    and the count of unpriced calls is reported — never a guessed price.
  - between runs the lab is reset (lab-down.sh + lab-up.sh) and the
    plumbing is re-proven (plumbing_check.py: every check REAL) before
    the next engagement starts.

Usage (WSL, user dev):
  cd /mnt/d/project/kryon-sec/research/lab
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase5_engagement_runs.py [full|llm-off|both]
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phase4_tool_runs import DNS_CONTAINER, LAB_DIR, TARGET  # noqa: E402
from phase4_tool_runs import pin_template_hosts  # noqa: E402

from kryonsec.cli import _run_purple  # noqa: E402
from kryonsec.config import load_config  # noqa: E402
from kryonsec.llm import clear_usage_log  # noqa: E402
from kryonsec.purple.audit import AuditLog  # noqa: E402
from kryonsec.purple.graph_store import load_graph  # noqa: E402
from kryonsec.storage import get_purple_session, init_purple_db  # noqa: E402

AUTO_APPROVAL_LABEL = "automation-injected (non-human)"
BASELINE_APPROVAL_LABEL = (
    "none needed (zero hypotheses — LLM disabled)")


# ---- the ui stub _run_purple drives ----------------------------------------


class QuietUI:
    """The ui surface cli._run_purple expects, as a plain-print stub.

    PurpleUI owns a rich live panel built for a terminal; a background
    lab run has none. This stub answers the same method calls and prints
    one plain line per state so a background log still shows progress.
    It only receives; it can influence nothing (same contract as the
    audit observers: presentation only).
    """

    def __init__(self) -> None:
        self.graph = None
        self.audit = None
        self.orchestrator = None
        self.started_at = 0.0
        self.notices: list[str] = []
        self.states: list[str] = []
        self.outcome: str | None = None
        self.halt_reason: str | None = None
        self.report_path: str | None = None

    # notices come from the product AND from PurpleLogHandler (log >=WARNING)
    def on_notice(self, message: str) -> None:
        text = str(message)
        self.notices.append(text)
        print(f"    notice: {text[:200]}", flush=True)

    def on_log(self, record) -> None:  # PurpleLogHandler calls this
        self.on_notice(record.getMessage())

    def on_state(self, state: str) -> None:
        self.states.append(state)
        print(f"    state: {state}", flush=True)

    def on_state_complete(self, state: str) -> None:
        pass

    def on_audit(self, event: dict) -> None:
        name = event.get("event", "?")
        if name in ("tool_spawn", "adapter_spawn", "exploit_plan",
                    "finding_confirmed", "finding_verified",
                    "llm_usage", "engagement_finished"):
            print(f"    audit: {name} "
                  f"{json.dumps(event, default=str)[:200]}", flush=True)

    def start(self) -> None:
        pass

    def finish(self, outcome: str, halt_reason=None, report_path=None) -> None:
        self.outcome = outcome
        self.halt_reason = halt_reason
        self.report_path = report_path
        print(f"    finish: {outcome} halt={halt_reason} "
              f"report={report_path}", flush=True)

    def stop(self) -> None:
        pass


# ---- the injected reviewers (Gate 2 / Gate 3) -------------------------------


def auto_approver(hypotheses: list[dict]) -> set[str]:
    """AUTOMATION-INJECTED (non-human): approve every proposed hypothesis.

    Same single-argument contract the injectable reviewer slot expects;
    the manifest labels the run with it so no one can mistake these
    Gate-2 decisions for a person's.
    """
    return {h["label"] for h in hypotheses}


def deny_post_exploit(reason: str) -> bool:
    """Gate 3: ALWAYS refused — these runs never approve
    post-exploitation, whatever the reason."""
    return False


def pin_template_hosts_with_retry(cfg, attempts: int = 4,
                                  pause_s: float = 15.0) -> dict:
    """Pin the template hosts, retrying on the KNOWN rotation flake.

    The pin's rotation guard compares two host-side resolutions seconds
    apart (the policy build's and the pin's own). GitHub's GeoDNS hands
    out rotating edge IPs, so a rotation landing between the two calls
    fails the subset check — the fail-closed mechanism working exactly
    as designed (found live 2026-11-17: github.com answered
    4.186.157.192 where the policy had pinned 4.187.247.160). Each retry
    re-resolves everything fresh; a steady DNS window passes. Never a
    faked pin: every attempt either verifies or refuses.
    """
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            pin_template_hosts(cfg)
            return {"ok": True, "attempts": attempt}
        except (SystemExit, Exception) as e:
            # SystemExit: the rotation guard's fail-closed refusal.
            # Exception: transient host-resolution failures (seen live
            # 2026-11-17: "Temporary failure in name resolution" right
            # after a lab reset). Both are retryable; the pin is never
            # faked — every attempt either verifies or refuses.
            last_error = f"{type(e).__name__}: {e}"
            print(f"  pin attempt {attempt}/{attempts} refused: {last_error}",
                  flush=True)
            if attempt < attempts:
                time.sleep(pause_s)
    return {"ok": False, "attempts": attempts, "last_error": last_error}


# ---- lab infrastructure ------------------------------------------------------


def reset_lab() -> None:
    """lab-down.sh + lab-up.sh: container recreation is the reset (the
    targets keep no volumes)."""
    print("lab reset: lab-down.sh + lab-up.sh ...", flush=True)
    for script in ("lab-down.sh", "lab-up.sh"):
        subprocess.run(["bash", script], cwd=LAB_DIR, check=True,
                       timeout=600)


def dns_started_at() -> str | None:
    r = subprocess.run(
        ["docker", "inspect", DNS_CONTAINER,
         "--format", "{{.State.StartedAt}}"],
        capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else None


def plumbing_check() -> dict:
    """plumbing_check.py must pass with ZERO non-REAL checks before an
    engagement starts. The condition is count-agnostic on purpose: the
    lab's check list grew from 9 to 10 between phases and must not need
    a harness edit to keep working — 'all REAL' is the invariant."""
    print("plumbing check ...", flush=True)
    r = subprocess.run(
        [sys.executable, "plumbing_check.py"], cwd=LAB_DIR,
        capture_output=True, text=True, timeout=1200)
    summary = None
    all_real = False
    total = 0
    results_path = LAB_DIR / "plumbing-results.json"
    if results_path.is_file():
        try:
            data = json.loads(results_path.read_text(encoding="utf-8"))
            checks = data.get("checks") or []
            total = len(checks)
            summary = data.get("summary")
            all_real = total > 0 and all(
                c.get("result") == "REAL" for c in checks)
        except Exception:
            summary = None
    return {
        "ok": r.returncode == 0 and all_real,
        "summary": summary,
        "all_real": all_real,
        "total_checks": total,
        "exit_code": r.returncode,
        "stdout_tail": (r.stdout or "")[-600:],
        "stderr_tail": (r.stderr or "")[-400:],
    }


# ---- measurement -------------------------------------------------------------


def read_audit(path: Path) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    events.append({"event": "UNPARSEABLE_LINE"})
    return events


def tool_name(event: dict) -> str:
    named = event.get("tool") or event.get("adapter")
    if named:
        return str(named)
    argv = event.get("argv") or []
    if argv:
        return Path(str(argv[0])).name
    return "?"


def graph_dump(cfg, engagement_id: str) -> dict:
    """The persisted graph, read back from PostgreSQL storage."""
    try:
        init_purple_db(cfg)
        with get_purple_session(cfg) as session:
            graph = load_graph(session, engagement_id)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:300]}
    nodes = [
        {
            "id": n.get("id"),
            "node_type": n.get("node_type"),
            "label": n.get("label"),
            "canonical_key": n.get("canonical_key"),
            "status": n.get("status"),
            "properties": dict(n.get("properties") or {}),
            "provenance": dict(n.get("provenance") or {}),
        }
        for n in graph.nodes
    ]
    edges = [
        {k: e.get(k) for k in ("source", "target", "relation", "kind")
         if k in e}
        for e in graph.edges
    ]
    return {"nodes": nodes, "edges": edges}


def summarize(mode: str, engagement_id: str, cfg, wall_s: float,
              audit_events: list[dict], chain_ok: bool, chain_error: str,
              head_hash: str, plumbing: dict, dns_before: str | None,
              dns_after: str | None) -> dict:
    def ev(name: str) -> list[dict]:
        return [e for e in audit_events if e.get("event") == name]

    states = [e.get("state") for e in ev("state_enter")]
    reviewed = ev("hypothesis_reviewed")
    approved_ids = [e.get("hypothesis_id") for e in reviewed
                    if e.get("approved")]
    rejected_ids = [e.get("hypothesis_id") for e in reviewed
                    if not e.get("approved")]
    llm_events = ev("llm_usage")
    tokens = sum(int(e.get("total_tokens") or 0) for e in llm_events)
    priced = [float(e["cost_usd"]) for e in llm_events
              if e.get("cost_usd") is not None]
    spawns = ev("tool_spawn")
    results = ev("tool_result")
    finished = ev("engagement_finished")

    by_adapter = Counter()
    for e in spawns:
        by_adapter[tool_name(e)] += 1

    outcome = finished[-1].get("outcome") if finished else "UNKNOWN"
    manifest = {
        "mode": mode,
        "target": TARGET,
        "engagement_id": engagement_id,
        "approval_provenance": (
            AUTO_APPROVAL_LABEL if mode == "full"
            else BASELINE_APPROVAL_LABEL),
        "gate3_post_exploit": "always refused (no post-exploitation)",
        "outcome": outcome,
        "states_entered": states,
        "wall_s": round(wall_s, 1),
        "llm": {
            "provider": cfg.provider,
            "chat_model": cfg.general_chat_model,
            "disable_gate": (
                "KRYONSEC_DISABLE_LLM=1" if mode == "llm-off"
                else "not set"),
            "calls_audited": len(llm_events),
            "total_tokens_provider_reported": tokens,
            "token_source": (
                "REAL (provider-reported usage objects)" if llm_events
                else "none (zero LLM calls)"),
            "cost_known_usd": round(sum(priced), 6),
            "cost_unpriced_calls": len(llm_events) - len(priced),
            "cost_note": (
                "cost summed ONLY over calls the provider's cost map "
                "could price; unpriced calls are unknown, never guessed"),
        },
        "hypotheses": {
            "proposed": len(ev("hypothesis_proposed")),
            "approved": len(approved_ids),
            "approved_ids": approved_ids,
            "rejected": len(rejected_ids),
        },
        "tools": {
            "spawns": len(spawns),
            "results": len(results),
            "by_tool": dict(by_adapter),
            "tool_failures": len(
                [e for e in results if e.get("exit_code") not in (0, None)]),
        },
        "findings": {
            "confirmed": len(ev("finding_confirmed")),
            "verified": len(ev("finding_verified")),
            "verification_failed": len(ev("finding_verification_failed")),
        },
        "report_written": bool(ev("report_written")),
        "audit_chain": {
            "events": len(audit_events),
            "head_hash": head_hash,
            "verified": chain_ok,
            "error": chain_error,
        },
        "lab": {
            "reset_before_run": True,
            "plumbing": plumbing,
            "dns_started_at_before": dns_before,
            "dns_started_at_after": dns_after,
            "dns_recreated_mid_run": (
                None if (dns_before is None or dns_after is None)
                else dns_before != dns_after),
        },
        "honest_note": (
            "infrastructure success is NOT detection performance; "
            "missed/false-positive scoring happens in Phase 6 against "
            "ground-truth/juice-shop-v20.4.0-challenges.yml (118 "
            "challenges), never from this manifest"),
    }
    return manifest


# ---- one run ------------------------------------------------------------------


def run_mode(mode: str, cfg, stamp: str, outdir: Path) -> dict:
    run_dir = outdir / f"run-{mode}"
    run_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = f"lab-p5-{mode}-{stamp}"

    print(f"\n===== Phase 5 run: {mode} ({engagement_id}) =====", flush=True)

    # 1. fresh target state (container recreation IS the reset)
    reset_lab()

    # 2. the reset recreates the DNS container clean — re-pin the
    #    template hosts (fail-closed + self-verifying) and note both
    #    StartedAt values so a mid-run recreate is visible in the manifest
    dns_before = dns_started_at()
    pin = pin_template_hosts_with_retry(cfg)
    if not pin["ok"]:
        print("template-host pin FAILED after retries — recording and "
              "stopping this run (fail-closed on rotation, never faked)",
              flush=True)
        return {
            "mode": mode, "engagement_id": engagement_id,
            "label": "FAILED", "stage": "template_host_pin",
            "detail": pin,
        }

    # 3. plumbing must be 9/9 REAL before any engagement
    plumbing = plumbing_check()
    shutil.copy(LAB_DIR / "plumbing-results.json",
                run_dir / "plumbing-results.json")
    if not plumbing["ok"]:
        print(f"plumbing NOT green ({plumbing['summary']}) — recording and "
              "stopping this run", flush=True)
        return {
            "mode": mode, "engagement_id": engagement_id,
            "label": "FAILED", "stage": "plumbing_check",
            "detail": plumbing,
        }

    # 4. the engagement itself — the REAL product path
    if mode == "llm-off":
        os.environ["KRYONSEC_DISABLE_LLM"] = "1"
    else:
        os.environ.pop("KRYONSEC_DISABLE_LLM", None)
    clear_usage_log()

    ui = QuietUI()
    started = time.monotonic()
    try:
        _run_purple(
            cfg, TARGET, engagement_id,
            output=False, ui=ui,
            human_reviewer=auto_approver,
            post_exploit_approver=deny_post_exploit,
        )
        wall_s = time.monotonic() - started
    finally:
        # never let one mode's gate leak into the next
        os.environ.pop("KRYONSEC_DISABLE_LLM", None)

    # 5. measure — everything from the audit chain + persisted graph
    audit_path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    if not audit_path.is_file():
        return {
            "mode": mode, "engagement_id": engagement_id,
            "label": "FAILED", "stage": "no_audit",
            "detail": f"{audit_path} does not exist after the run",
        }
    shutil.copy(audit_path, run_dir / "audit.jsonl")
    report_src = cfg.home / "engagements" / engagement_id / "report.md"
    if report_src.is_file():
        shutil.copy(report_src, run_dir / "report.md")

    audit_events = read_audit(run_dir / "audit.jsonl")
    chain = AuditLog(run_dir / "audit.jsonl")
    chain_ok, chain_error = chain.verify()
    head_hash = chain.head_hash()
    dns_after = dns_started_at()

    manifest = summarize(
        mode, engagement_id, cfg, wall_s, audit_events, chain_ok,
        chain_error, head_hash, plumbing, dns_before, dns_after)
    manifest["lab"]["template_host_pin"] = pin

    dump = graph_dump(cfg, engagement_id)
    if "error" not in dump:
        with open(run_dir / "graph.json", "w", encoding="utf-8") as fh:
            json.dump(dump, fh, indent=2)
        by_type = Counter(n.get("node_type") for n in dump["nodes"])
        manifest["graph"] = {
            "nodes": len(dump["nodes"]), "edges": len(dump["edges"]),
            "by_type": dict(by_type),
        }
    else:
        manifest["graph"] = {"error": dump["error"]}

    with open(run_dir / "phase5-run-manifest.json", "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    print(f"===== {mode} done: outcome={manifest['outcome']} "
          f"wall={manifest['wall_s']}s "
          f"llm_calls={manifest['llm']['calls_audited']} "
          f"tokens={manifest['llm']['total_tokens_provider_reported']} "
          f"hypotheses={manifest['hypotheses']['proposed']} "
          f"(approved {manifest['hypotheses']['approved']}) "
          f"tools={manifest['tools']['spawns']} "
          f"findings confirmed/verified="
          f"{manifest['findings']['confirmed']}/"
          f"{manifest['findings']['verified']} "
          f"chain_verified={manifest['audit_chain']['verified']} "
          f"=====", flush=True)
    return manifest


def main() -> int:
    requested = sys.argv[1:] or ["both"]
    modes: list[str] = []
    for arg in requested:
        if arg == "both":
            modes += ["full", "llm-off"]
        elif arg in ("full", "llm-off"):
            modes.append(arg)
        else:
            raise SystemExit(f"unknown mode: {arg} (use full|llm-off|both)")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = LAB_DIR / "results" / stamp
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"Phase 5 sequence {stamp} -> {outdir}", flush=True)

    cfg = load_config()  # KRYONSEC_HOME carries the approved lab scope
    manifests = []
    for i, mode in enumerate(modes):
        try:
            manifests.append(run_mode(mode, cfg, stamp, outdir))
        except Exception as e:
            # a harness/infrastructure failure is RECORDED, never a lost
            # run record (same rule the Phase-4 harness lives by)
            manifests.append({
                "mode": mode, "label": "FAILED", "stage": "harness",
                "detail": f"{type(e).__name__}: {e}"[:400],
            })
            print(f"harness FAILED for {mode}: {type(e).__name__}: {e}",
                  flush=True)

    summary = {
        "when": stamp, "target": TARGET,
        "modes_requested": modes,
        "runs": manifests,
        "approval_note": (
            "full runs are automation-injected (non-human) approvals; "
            "Gate 3 always refused"),
        "honest_note": (
            "infrastructure success is NOT detection performance; "
            "scoring is Phase 6 against the recorded ground truth"),
    }
    out = outdir / "phase5-engagement-runs.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    failed = [m for m in manifests if m.get("label") == "FAILED"]
    bad_chain = [
        m for m in manifests
        if isinstance(m, dict) and not m.get("audit_chain", {}).get(
            "verified", True)]
    print(f"results written: {out}", flush=True)
    print(f"summary: runs={len(manifests)} harness_failures={len(failed)} "
          f"chain_breaks={len(bad_chain)}", flush=True)
    return 1 if (failed or bad_chain) else 0


if __name__ == "__main__":
    raise SystemExit(main())
