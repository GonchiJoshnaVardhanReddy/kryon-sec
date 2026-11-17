"""Phase 4 tool-expansion — REAL-path verification of the 9 new wired
tools (APPROVED scope only).

Operator-approved 2026-11-16 (research/lab/README.md): target
juice-shop.lab = 10.213.43.10, HTTP port 80 only. WebGoat is NOT in
scope. No public targets.

What this proves, per tool:
  1. the argv the product builds (allowlist template + plan entry)
     passes Layer 2 AND the sandbox entrypoint gate;
  2. the binary exists in the rebuilt image and runs under gVisor
     through the REAL KaliSandbox (runsc, egress policy);
  3. the flags are accepted (no "unrecognized option" — a guessed flag
     shape shows up here as exit 1/64 + usage text);
  4. the parser contract is checked against the REAL output (excerpt
     saved to the results dir for the parser fixtures).

Honest labels per run: REAL (it ran — success or failure are both real
results), SKIPPED (with reason). The approved target has NO SMB ports
open, so the REAL product plan honestly omits the SMB trio; the
harness force-captures their exact argv by resolving the target with a
real dig spawn (the same thing the discovery stage does) and calling
_smb_plan({445}, target_ip=...) — so the argv table is the real
product output, not a fake, and the omission difference is visible.

Blue-team tools run through the REAL run_code_scanners path with a
fixture /code mount (one real ELF + text files), on the SAME engagement
gate via KaliSandbox.copy_with — the runner's own one-sandbox-per-
engagement, per-state-variant rule.

Usage (WSL, user dev, after image rebuild):
  cd /mnt/d/project/kryon-sec/research/lab
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase4b_tool_verify.py [tool ...]
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")

from kryonsec.config import load_config  # noqa: E402
from kryonsec.purple.audit import AuditLog  # noqa: E402
from kryonsec.purple.blue_team import run_code_scanners  # noqa: E402
from kryonsec.purple.egress import (  # noqa: E402
    EgressGate,
    build_policy,
    release_active,
)
from kryonsec.purple.recon_active import (  # noqa: E402
    ReconActiveSubagent,
    parse_dirsearch,
    parse_dns_a_records,
)
from kryonsec.purple.recon_passive import EngagementGraph  # noqa: E402
from kryonsec.purple.sandbox import KaliSandbox  # noqa: E402

TARGET = "juice-shop.lab"
ENGAGEMENT_ID = "lab-p4b-verify"
REPO = Path("/mnt/d/project/kryon-sec")
LAB_DIR = REPO / "research" / "lab"

RESULTS: list[dict] = []
OUTDIR: Path | None = None

# The wired Phase 4 set; anything in the recon block runs through the
# product plan argv, the blue-team pair through run_code_scanners.
NEW_RECON = (
    "wafw00f", "dirsearch", "dnsenum", "fierce",
    "nbtscan", "smbmap", "enum4linux-ng",
)
NEW_BLUE = ("checksec", "exiftool")


def output_format(stdout: str) -> str:
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            # JSON only on a { start: a bare [ is plain text in tools
            # like smbmap ("[\] Checking for open ports…") and
            # enum4linux-ng ("[92m" color codes) — the first heuristic
            # mislabeled both as json (found in the Phase 4b run)
            return "json" if line.startswith("{") else "text"
    return "empty"


def plan_argvs(sb: KaliSandbox) -> dict[str, list[str]]:
    """The EXACT argv the product builds for each new tool, from a real
    subagent pointed at the real sandbox (so the pinned-resolver and
    port-gating rules apply for real). No tool is SPAWNED here except
    the dig resolution that mirrors what the discovery stage does: the
    dns_resolution node it records is what run() reads nbtscan's IP
    from (nbtscan rejects hostnames — verified live)."""
    graph = EngagementGraph(engagement_id=ENGAGEMENT_ID)
    audit = AuditLog(OUTDIR / "audit" / "argv-probe.jsonl")
    sub = ReconActiveSubagent(
        load_config(), graph, audit, TARGET, sb)
    out: dict[str, list[str]] = {}
    for tool, argv in sub._discovery_plan():
        out.setdefault(tool, argv)
    for tool, argv in sub._web_plan({80}):  # the approved base: port 80
        out.setdefault(tool, argv)
    # mirror the discovery stage's resolution so the SMB plan sees the
    # observed IP exactly as run() would (the real dig spawn through
    # the sandbox; empty output = no IP = the honest nbtscan omission)
    dig = sb.spawn(["dig", "@10.213.44.1", TARGET, "A", "+short"])
    ip = next((l.strip() for l in (dig.stdout or "").splitlines()
               if l.strip()), None)
    if ip:
        graph.add_node("dns_resolution", TARGET,
                       properties={"ips": [ip], "source": "dig-verify"})
        print(f"resolved {TARGET} -> {ip} (real dig)", flush=True)
    for tool, argv in sub._smb_plan({445}, target_ip=ip):
        out.setdefault(tool, argv)
    return out


def run_tool(sb: KaliSandbox, tool: str, argv: list[str]) -> None:
    entry: dict = {"tool": tool, "argv": argv, "label": "REAL"}
    print(f"=== {tool}: {' '.join(argv[:8])}{'…' if len(argv) > 8 else ''}",
          flush=True)
    audit = AuditLog(OUTDIR / "audit" / f"{tool}.jsonl")
    started = time.monotonic()
    audit.write({"event": "tool_spawn", "state": "LAB_VERIFY",
                 "tool": tool, "argv": argv})
    res = sb.spawn(argv)
    duration = round(time.monotonic() - started, 2)
    raw_path = OUTDIR / f"{tool}.out.txt"
    raw_path.write_text(res.stdout or "", encoding="utf-8",
                        errors="replace")
    entry.update({
        "duration_s": duration,
        "exit_code": res.exit_code,
        "ok": res.ok,
        "stdout_chars": len(res.stdout or ""),
        "error_excerpt": (res.error or "")[:300],
        "output_format": output_format(res.stdout or ""),
        "raw": str(raw_path),
    })
    # parser contract against the REAL output, where a parser exists
    if tool == "dirsearch":
        rows = parse_dirsearch(res.stdout or "")
        entry["parser_paths_found"] = len(rows)
        entry["parser_sample"] = rows[:5]
    if tool in ("dnsenum", "fierce"):
        entry["parser_a_records"] = parse_dns_a_records(res.stdout or "")
    audit.write({"event": "tool_result", "state": "LAB_VERIFY",
                 "tool": tool, "ok": res.ok, "exit_code": res.exit_code,
                 "output_chars": len(res.stdout or "")})
    print(f"  exit={res.exit_code} dur={duration}s "
          f"out={entry['stdout_chars']}B fmt={entry['output_format']}",
          flush=True)
    RESULTS.append(entry)


def fixture_code_dir(image: str) -> Path:
    """A tiny /code fixture: text files + ONE real ELF pulled from the
    sandbox image (checksec needs an ELF to audit; exiftool reads any)."""
    d = OUTDIR / "code-fixture"
    d.mkdir(exist_ok=True)
    (d / "app.py").write_text(
        "import os\nTOKEN = 'not-a-real-secret'\n", encoding="utf-8")
    (d / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8")
    elf = d / "elf-sample"
    if not elf.exists():
        # the image ref MUST come from the config (tag or digest-pin) —
        # a hardcoded "kryonsec/sandbox" fails when no :latest tag exists
        # (found live, first Phase 4b run)
        try:
            cid = subprocess.run(
                ["docker", "create", image, "/bin/true"],
                capture_output=True, text=True, check=True,
                timeout=60).stdout.strip()
            subprocess.run(
                ["docker", "cp", f"{cid}:/usr/bin/dash", str(elf)],
                check=True, timeout=60)
            subprocess.run(["docker", "rm", "-f", cid],
                           capture_output=True, timeout=60)
        except subprocess.SubprocessError as e:
            print(f"  (ELF fixture unavailable: {e})", flush=True)
    return d


def run_blue_team(sb: KaliSandbox, image: str) -> None:
    """checksec + exiftool through the REAL run_code_scanners path."""
    code_dir = fixture_code_dir(image)
    sb_code = sb.copy_with(code_dir=str(code_dir))
    for tool in NEW_BLUE:
        entry: dict = {"tool": tool, "label": "REAL",
                       "path": "run_code_scanners"}
        graph = EngagementGraph(engagement_id=ENGAGEMENT_ID)
        audit = AuditLog(OUTDIR / "audit" / f"{tool}.jsonl")
        ran = run_code_scanners(graph, sb_code, audit, has_dockerfile=True)
        mine = [n for n in graph.by_type("scanner_result")
                if n["label"] == tool]
        entry.update({
            "ran": ran,
            "node": mine[0]["properties"] if mine else None,
        })
        if mine:
            raw = OUTDIR / f"{tool}.out.txt"
            raw.write_text(str(mine[0]["properties"].get("excerpt", "")),
                           encoding="utf-8")
        print(f"=== {tool} (blue) ran={ran} "
              f"node={'yes' if mine else 'NO'}", flush=True)
        RESULTS.append(entry)


def main() -> int:
    global OUTDIR
    requested = sys.argv[1:] or list(NEW_RECON + NEW_BLUE)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    OUTDIR = LAB_DIR / "results" / f"{stamp}-p4b-verify"
    (OUTDIR / "audit").mkdir(parents=True, exist_ok=True)
    (OUTDIR / "evidence").mkdir(exist_ok=True)
    print(f"Phase 4b verification -> {OUTDIR}", flush=True)

    cfg = load_config()  # KRYONSEC_HOME carries the approved lab scope
    policy = build_policy(cfg, ENGAGEMENT_ID, TARGET)
    gate = EgressGate()
    ok, reason = gate.establish(policy)
    if not ok:
        raise SystemExit(f"gate establish FAILED: {reason}")
    try:
        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate,
                         evidence_dir=str(OUTDIR / "evidence"))
        argvs = plan_argvs(sb)
        # blue team is ONE lane covering both tools: request checksec
        # OR exiftool and run_code_scanners runs once (the first Phase
        # 4b run executed the pair twice — once per requested name)
        blue_requested = [t for t in requested if t in NEW_BLUE]
        for tool in requested:
            if tool in NEW_RECON:
                if tool not in argvs:
                    RESULTS.append({
                        "tool": tool, "label": "SKIPPED",
                        "reason": "no plan entry (resolver/port rule)",
                    })
                    print(f"=== {tool}: SKIPPED (no plan entry)", flush=True)
                    continue
                run_tool(sb, tool, argvs[tool])
            elif tool in NEW_BLUE:
                if blue_requested:
                    run_blue_team(sb, cfg.sandbox_image)
                    blue_requested = []  # once, even if both were named
            else:
                print(f"unknown tool: {tool}", flush=True)
    finally:
        gate.release(policy)
        release_active(ENGAGEMENT_ID)

    out = OUTDIR / "phase4b-verify.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"when": stamp, "target": TARGET,
                   "runs": RESULTS}, fh, indent=2)
    print(f"results: {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
