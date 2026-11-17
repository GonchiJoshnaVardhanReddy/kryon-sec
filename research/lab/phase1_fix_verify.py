"""IEEE-research Phase 1 - verify the FIXED argvs through the real path.

Same real path as phase1_failure_repro.py (build_policy -> EgressGate ->
KaliSandbox -> sandbox.spawn), but with the FIXED argv lists from
build_argv — proving the Phase-1 fixes execute, not just validate:

  wget-ftp-fixed   bounded retries (-t 3 --waitretry=2): the /ftp
                   truncated response must cost seconds, not 266s
  nuclei-manifest  the reviewed, hash-pinned manifest templates with the
                   probe's proven safety flags + -mt 2m: must COMPLETE
                   inside the 300s cap (no exit 137)

Usage (WSL):
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase1_fix_verify.py [name ...]
"""

from __future__ import annotations

import json
import sys
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
from kryonsec.purple.exploit import build_argv  # noqa: E402
from kryonsec.purple.sandbox import KaliSandbox  # noqa: E402

TARGET = "juice-shop.lab"


def main() -> int:
    requested = [a for a in sys.argv[1:] if not a.startswith("-")]
    runs = requested or ["wget-ftp-fixed", "nuclei-manifest"]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path("/mnt/d/project/kryon-sec/research/lab/results") / \
        f"{stamp}-p1verify"
    (outdir / "audit").mkdir(parents=True, exist_ok=True)

    cfg = load_config()
    results = []
    for name in runs:
        if name == "wget-ftp-fixed":
            argv = build_argv("wget", TARGET, "/ftp")
        elif name == "nuclei-manifest":
            argv = build_argv("nuclei", TARGET, "/metrics")
        else:
            raise SystemExit(f"unknown run: {name}")
        entry = {"run": name, "argv_len": len(argv)}
        print(f"=== {name} ({len(argv)} args) ===", flush=True)
        engagement_id = f"lab-p1v-{name}"
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
            audit.write({"event": "tool_spawn", "run": name,
                         "argv": argv})
            started = time.monotonic()
            res = sb.spawn(argv)
            duration = round(time.monotonic() - started, 2)
            audit.write({"event": "tool_result", "run": name,
                         "exit_code": res.exit_code, "ok": res.ok,
                         "output_chars": len(res.stdout or "")})
            tail = (res.stdout or "")[-600:]
            entry.update({
                "exit_code": res.exit_code,
                "ok": res.ok,
                "duration_s": duration,
                "stdout_chars": len(res.stdout or ""),
                "stdout_tail": tail,
            })
        finally:
            gate.release(policy)
            release_active(engagement_id)
        results.append(entry)
        print(f"  exit={entry.get('exit_code')} ok={entry.get('ok')} "
              f"duration={entry.get('duration_s')}s "
              f"chars={entry.get('stdout_chars')}", flush=True)

    (outdir / "phase1-verify.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"results -> {outdir / 'phase1-verify.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
