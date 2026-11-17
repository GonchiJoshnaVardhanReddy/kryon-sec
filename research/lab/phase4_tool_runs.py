"""IEEE-research Phase 4 — per-tool REAL-path experiments (APPROVED scope).

Operator-approved 2026-11-16 (research/lab/README.md): target
juice-shop.lab = 10.213.43.10, HTTP 80 only. This script runs each
vetted tool ONCE against that target through Kryonsec's REAL execution
path — exactly what a live engagement runs:

    load_config -> build_policy -> EgressGate establish/verify
    -> KaliSandbox (runsc, egress policy) -> production adapter registry
    -> prepare_adapter_run (Layer-2 + scope) -> execute_adapter
    -> gate.release + release_active

NOTHING here is a detection measurement yet: Phase 4 records whether
each tool RUNS through the real path (redacted argv, duration, exit
status, output shape, failures). Detection claims come only from
Phases 5-6 scored against ground truth.

Honest labels written into the results file:
  REAL     — the run happened through the real path (tool success OR
             tool failure — a failed tool run is still a REAL result)
  SKIPPED  — planned but not run, with the reason (e.g. no TLS)

Excluded by design (NOT RUN, never silently): brute-force/DoS-shaped
work (masscan absent from the product; no wordlist smashing beyond the
product's own bounded templates), WebGoat (10.213.43.11 — scope NOT
approved), and anything outside the pinned /32.

Usage (WSL, user dev):
  cd /mnt/d/project/kryon-sec/research/lab
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python phase4_tool_runs.py [tool ...]
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")

from kryonsec.config import load_config  # noqa: E402
from kryonsec.purple.adapter_whatweb import recon_active_registry  # noqa: E402
from kryonsec.purple.adapters import (  # noqa: E402
    AdapterError,
    execute_adapter,
    prepare_adapter_run,
)
from kryonsec.purple.audit import AuditLog  # noqa: E402
from kryonsec.purple.egress import (  # noqa: E402
    EgressGate,
    build_policy,
    release_active,
)
from kryonsec.purple.recon_active import RECON_PORTS  # noqa: E402
from kryonsec.purple.sandbox import KaliSandbox  # noqa: E402

TARGET = "juice-shop.lab"
LAB_RESOLVER = "10.213.44.1"
DNS_CONTAINER = "kryonsec-lab-dns"
TEMPLATE_HOSTS = (
    "github.com", "codeload.github.com", "raw.githubusercontent.com")

REPO = Path("/mnt/d/project/kryon-sec")
LAB_DIR = REPO / "research" / "lab"

# the product's own deterministic discovery port list (pinned in source)
PORTS = RECON_PORTS
RATE = "100"  # gentle: connect-scan rate ceiling, well under any DoS shape

# tool -> (adapter_id | None for direct template spawn, params, note)
RUNS: dict[str, tuple[str | None, dict, str]] = {
    "naabu": ("naabu-probe", {"ports": PORTS, "rate": RATE},
              "product discovery port list, rate 100"),
    "nmap": ("nmap-probe", {"ports": PORTS, "rate": RATE},
             "product pinned flags (-Pn -sT -sV -sC), rate 100"),
    "dnsx": ("dnsx-probe", {}, "domain resolution (pinned resolver, -resp-only)"),
    "httpx": ("httpx-probe", {}, "base URL probe (JSONL)"),
    "whatweb": ("whatweb-probe", {}, "level 1 fingerprint"),
    "katana": ("katana-probe", {"depth": "2"}, "crawl depth 2"),
    "feroxbuster": ("feroxbuster-probe", {},
                    "product template (t5, common.txt, FUZZ on base)"),
    "gowitness": ("gowitness-probe", {}, "screenshot into /evidence"),
    "api-probe": ("api-probe", {}, "EXTRA: read-only GET/OPTIONS baseline"),
    "openapi_probe": (None, {},
                      "direct Layer-2 template spawn (no adapter exists)"),
    "nuclei": ("nuclei-probe", {},
               "baked manifest templates only (-duc -ni, no OAST)"),
}
# tls-probe / testssl.sh: the approved target serves plain HTTP only.
SKIPPED = {
    "tls-probe": ("SKIPPED", "approved target serves plain HTTP only "
                  "(no TLS endpoint in scope)"),
}

RESULTS: list[dict] = []
OUTDIR: Path | None = None


def output_format(stdout: str) -> str:
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            return "jsonl" if line.startswith("{") else "text"
    return "empty"


def run_one(label: str, registry, cfg, adapter_id, params, note) -> None:
    engagement_id = f"lab-p4-{label}"
    entry: dict = {"tool": label, "engagement": engagement_id,
                   "label": "REAL", "note": note}
    print(f"=== {label} ({engagement_id}) ===", flush=True)
    policy = build_policy(cfg, engagement_id, TARGET)
    gate = EgressGate()
    ok, reason = gate.establish(policy)
    if not ok:
        entry.update({"label": "FAILED", "stage": "establish",
                      "detail": reason})
        RESULTS.append(entry)
        print(f"  establish FAILED: {reason}", flush=True)
        return
    params = dict(params)
    if label in ("dnsx", "naabu"):
        # PD tools (dnsx 1.3.1, naabu 2.x) query HARDCODED public
        # resolvers when -r is absent — queries the gate correctly
        # drops, so the run dies for a domain target. The value is the
        # policy's pinned resolver — exactly what the product adapter
        # lane derives from the egress policy.
        params["resolver"] = ",".join(
            str(r) for r in (policy.dns_resolvers or ()))
    audit = AuditLog(OUTDIR / "audit" / f"{label}.jsonl")
    try:
        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate,
                         evidence_dir=str(OUTDIR / "evidence"))
        before = set(os.listdir(OUTDIR / "evidence"))
        if adapter_id is None:
            # direct Layer-2 template spawn (openapi_probe.py): the same
            # argv the allowlist template renders, via the real sandbox.
            argv = ["/opt/kryonsec/openapi_probe.py", f"http://{TARGET}/"]
            started = time.monotonic()
            audit.write({"event": "manual_probe_spawn", "tool": label,
                         "argv": argv, "target": TARGET})
            res = sb.spawn(argv)
            audit.write({"event": "manual_probe_result", "tool": label,
                         "ok": res.ok, "exit_code": res.exit_code,
                         "output_chars": len(res.stdout or "")})
            entry.update({
                "argv": argv, "duration_s": round(time.monotonic() - started, 2),
                "exit_code": res.exit_code, "ok": res.ok,
                "stdout_chars": len(res.stdout or ""),
                "error_excerpt": (res.error or "")[:400],
                "excerpt": (res.stdout or "")[:1200],
                "output_format": output_format(res.stdout or ""),
            })
        else:
            prepared = prepare_adapter_run(
                registry, adapter_id, target=TARGET, target_asset="",
                scheme="http", params=dict(params))
            rec, stdout = execute_adapter(
                registry, prepared, sandbox=sb, audit=audit,
                full_output=True)
            after = set(os.listdir(OUTDIR / "evidence"))
            entry.update({
                "argv": list(rec.argv),
                "duration_s": round(rec.duration_s, 2),
                "exit_code": rec.exit_code, "ok": rec.executed,
                "failure_class": rec.failure_class or "",
                "stdout_chars": len(stdout or ""),
                "error_excerpt": (rec.error_excerpt or "")[:400],
                "excerpt": (stdout or "")[:1200],
                "output_format": output_format(stdout or ""),
                "evidence_files": sorted(after - before),
            })
        print(f"  exit={entry.get('exit_code')} "
              f"duration={entry.get('duration_s')}s "
              f"out={entry.get('stdout_chars')}B "
              f"fmt={entry.get('output_format')} "
              f"class={entry.get('failure_class', '')}", flush=True)
    except AdapterError as e:
        entry.update({"label": "FAILED", "stage": "prepare/execute",
                      "detail": str(e)[:400]})
        print(f"  adapter error: {e}", flush=True)
    finally:
        ok_r, why_r = gate.release(policy)
        if not ok_r:
            entry["release"] = f"FAILED: {why_r}"
        release_active(engagement_id)
    RESULTS.append(entry)


def pin_template_hosts(cfg) -> None:
    """Make in-sandbox DNS return EXACTLY the IPs the gate pinned for the
    three approved template hosts (fail closed on any rotation)."""
    probe = build_policy(cfg, "lab-p4-nuclei-pin", TARGET)
    # v4_allowed carries CIDR networks (the approved scope pins /32s);
    # normalize to bare addresses for the rotation check
    pinned_ips: set[str] = set()
    for n in probe.v4_allowed:
        net = ipaddress.ip_network(str(n), strict=False)
        if net.num_addresses == 1:
            pinned_ips.add(str(net.network_address))
        else:
            pinned_ips.update(str(h) for h in net.hosts())
    lines: list[str] = []
    for name in TEMPLATE_HOSTS:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET,
                                   socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        if not set(ips) <= pinned_ips:
            raise SystemExit(
                f"DNS rotation mismatch for {name}: resolved {ips}, "
                f"policy pins {sorted(pinned_ips)} — refusing to pin")
        lines += [f"{ip} {name}" for ip in ips]
    payload = "\n".join(lines) + "\n"
    # append to the lab resolver's baked hosts file inside its container
    # (lab infrastructure, disposable; lab-up.sh recreates it clean) and
    # SIGHUP dnsmasq (PID 1, --no-daemon) so it re-reads it.
    subprocess.run(["docker", "exec", DNS_CONTAINER, "sh", "-c",
                    "cat >> /etc/lab.hosts && kill -HUP 1"],
                   input=payload, text=True, check=True,
                   capture_output=True, timeout=30)
    # VERIFY the re-read took effect (the DNS container can be recreated
    # by lab infrastructure — found live 2026-11-17, which resets
    # lab.hosts to the baked 2 names and silently drops the pin): ask
    # the container's OWN dnsmasq for each name and require the pinned
    # IPs back.
    for name in TEMPLATE_HOSTS:
        q = subprocess.run(
            ["docker", "exec", DNS_CONTAINER, "sh", "-c",
             f"nslookup {name} 127.0.0.1 2>/dev/null || "
             f"getent hosts {name}"],
            capture_output=True, text=True, timeout=30)
        answered = {ln.split()[-1] for ln in q.stdout.splitlines()
                    if ln.split() and ln.split()[-1].count(".") == 3}
        if not answered <= pinned_ips:
            raise SystemExit(
                f"pin verification failed for {name}: dnsmasq answers "
                f"{sorted(answered)}, policy pins {sorted(pinned_ips)} "
                f"— refusing to continue")
    print(f"pinned {len(lines)} template-host records into {DNS_CONTAINER} "
          "+ SIGHUP, verified", flush=True)


def main() -> int:
    global OUTDIR
    requested = set(sys.argv[1:])
    # with NO arguments this is the full default sequence: every RUNS
    # entry runs AND every SKIPPED row is recorded (an explicit tool
    # list records only what was asked, as before).
    full_default = not requested
    unknown = requested - set(RUNS) - {"tls-probe"}
    if unknown:
        raise SystemExit(f"unknown tools: {sorted(unknown)}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    OUTDIR = LAB_DIR / "results" / stamp
    (OUTDIR / "audit").mkdir(parents=True, exist_ok=True)
    (OUTDIR / "evidence").mkdir(parents=True, exist_ok=True)

    cfg = load_config()  # KRYONSEC_HOME carries the approved lab scope
    registry = recon_active_registry()

    if full_default or "nuclei" in requested:
        pin_template_hosts(cfg)

    for label, (adapter_id, params, note) in RUNS.items():
        if not full_default and label not in requested:
            continue
        try:
            run_one(label, registry, cfg, adapter_id, params, note)
        except Exception as e:
            # a harness/infrastructure failure (e.g. the host resolver
            # failing to resolve a template host at policy-build time —
            # found live 2026-11-17, WSL DNS flake) is RECORDED as a
            # FAILED row, never silent and never a lost run record.
            RESULTS.append({"tool": label, "label": "FAILED",
                            "stage": "harness",
                            "detail": f"{type(e).__name__}: {e}"[:400]})
            print(f"  harness FAILED: {type(e).__name__}: {e}", flush=True)
            release_active(f"lab-p4-{label}")

    for name, (_skip, reason) in SKIPPED.items():
        if full_default or name in requested:
            RESULTS.append({"tool": name, "label": "SKIPPED",
                            "reason": reason})
            print(f"=== {name}: SKIPPED — {reason}", flush=True)

    out = OUTDIR / "phase4-tool-runs.json"
    real = [r for r in RESULTS if r["label"] == "REAL"]
    skipped = [r for r in RESULTS if r["label"] == "SKIPPED"]
    failed = [r for r in RESULTS if r["label"] == "FAILED"]
    summary = {
        "when": stamp, "target": TARGET,
        "real_runs": len(real), "skipped": len(skipped),
        "harness_failures": len(failed),
        "honest_note": ("a tool-level failure inside a REAL run is still "
                        "a REAL result (exit code recorded); detection "
                        "performance is NOT measured here"),
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "runs": RESULTS}, fh, indent=2)
    print(f"results written: {out}", flush=True)
    print(f"summary: REAL={len(real)} SKIPPED={len(skipped)} "
          f"FAILED={len(failed)}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
