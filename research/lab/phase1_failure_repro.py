"""IEEE-research Phase 1 - reproduce the 6 failed tool runs (APPROVED scope).

Operator-approved lab scope (research/lab/README.md): target
juice-shop.lab = 10.213.43.10, HTTP 80 only. This script re-runs the
EXACT argv list from the failed ToolRunner spawns of engagement
lab-p5-full-20261117T110737Z through the REAL execution path:

    load_config -> build_policy -> EgressGate establish/verify
    -> KaliSandbox (runsc, egress policy) -> sandbox.spawn

and records for each: exit code, duration, stdout chars, and (for
nuclei) a sampled memory trace of the container + the host OOM log
state, so the exit-137 root cause is EVIDENCE, not assumption.

Usage (WSL):
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase1_failure_repro.py [name ...]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")

from kryonsec.config import load_config  # noqa: E402
from kryonsec.purple.audit import AuditLog  # noqa: E402
from kryonsec.purple.egress import (  # noqa: E402
    EgressGate,
    build_policy,
    release_active,
)
from kryonsec.purple.sandbox import KaliSandbox  # noqa: E402

TARGET = "juice-shop.lab"

# The exact failed argv list from the real engagement audit
# (lab-p5-full-20261117T110737Z/audit.jsonl), named for re-runs.
FAILED_ARGVS: dict[str, list[str]] = {
    "subfinder": ["subfinder", "-d", TARGET, "-passive", "-silent"],
    "amass": ["amass", "enum", "-passive", "-d", TARGET],
    "assetfinder": ["assetfinder", "-silent", TARGET],
    "curl-ftp": ["curl", "-sS", "--max-time", "30", f"http://{TARGET}/ftp"],
    "wget-ftp": ["wget", "-q", "-O", "-", "--timeout=30", f"http://{TARGET}/ftp"],
    "nuclei-full-tree": [
        "nuclei", "-u", f"http://{TARGET}/metrics", "-t",
        "/opt/nuclei-templates", "-rate-limit", "50", "-timeout", "30",
    ],
}


def sample_stats(name_rx: str, out: list, stop: threading.Event) -> None:
    """Sample docker stats for containers matching name_rx until stopped."""
    while not stop.is_set():
        try:
            p = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.Name}} {{.MemUsage}} {{.PIDs}}", name_rx],
                capture_output=True, text=True, timeout=20)
            for line in p.stdout.splitlines():
                out.append((time.time(), line.strip()))
        except Exception as e:  # sampling must never kill the run
            out.append((time.time(), f"sampler-error: {e}"))
        stop.wait(2.0)


def kernel_oom_evidence() -> str:
    """One-line OOM state from the WSL kernel ring (best effort)."""
    try:
        p = subprocess.run(["dmesg"], capture_output=True, text=True,
                           timeout=15)
        hits = [ln for ln in p.stdout.splitlines()
                if "oom" in ln.lower() or "killed process" in ln.lower()]
        return " | ".join(hits[-5:]) if hits else "no oom lines in dmesg"
    except Exception as e:
        return f"dmesg unavailable: {e}"


def main() -> int:
    requested = [a for a in sys.argv[1:] if not a.startswith("-")]
    names = list(requested) if requested else list(FAILED_ARGVS)
    unknown = set(names) - set(FAILED_ARGVS)
    if unknown:
        raise SystemExit(f"unknown runs: {sorted(unknown)}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path("/mnt/d/project/kryon-sec/research/lab/results") / f"{stamp}-p1repro"
    (outdir / "audit").mkdir(parents=True, exist_ok=True)

    cfg = load_config()
    results = []
    for name in names:
        argv = FAILED_ARGVS[name]
        engagement_id = f"lab-p1-{name}"
        entry = {"run": name, "argv": argv}
        print(f"=== {name}: {argv} ===", flush=True)
        policy = build_policy(cfg, engagement_id, TARGET)
        gate = EgressGate()
        ok, reason = gate.establish(policy)
        if not ok:
            entry["error"] = f"establish failed: {reason}"
            results.append(entry)
            continue
        try:
            audit = AuditLog(outdir / "audit" / f"{name}.jsonl")
            sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)
            audit.write({"event": "tool_spawn", "run": name, "argv": argv})
            started = time.monotonic()
            stats: list = []
            stop = threading.Event()
            if name == "nuclei-full-tree":
                sampler = threading.Thread(
                    target=sample_stats,
                    args=("kryonsec-", stats, stop), daemon=True)
                sampler.start()
            res = sb.spawn(argv)
            duration = round(time.monotonic() - started, 2)
            stop.set()
            audit.write({"event": "tool_result", "run": name,
                         "exit_code": res.exit_code, "ok": res.ok,
                         "output_chars": len(res.stdout or ""),
                         "truncated": res.truncated,
                         "error": (res.error or "")[:300]})
            entry.update({
                "exit_code": res.exit_code,
                "ok": res.ok,
                "duration_s": duration,
                "stdout_chars": len(res.stdout or ""),
                "error_excerpt": (res.error or "")[:300],
                "stdout_tail": (res.stdout or "")[-800:],
            })
            if name == "nuclei-full-tree":
                entry["mem_samples"] = [line for _, line in stats[-12:]]
                entry["kernel_oom"] = kernel_oom_evidence()
        finally:
            gate.release(policy)
            release_active(engagement_id)
        results.append(entry)
        print(f"  exit={entry.get('exit_code')} ok={entry.get('ok')} "
              f"duration={entry.get('duration_s')}s "
              f"chars={entry.get('stdout_chars')}", flush=True)
        if name == "nuclei-full-tree":
            for line in entry.get("mem_samples", []):
                print(f"    mem: {line}", flush=True)
            print(f"    kernel: {entry.get('kernel_oom')}", flush=True)

    (outdir / "phase1-repro.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"results -> {outdir / 'phase1-repro.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
