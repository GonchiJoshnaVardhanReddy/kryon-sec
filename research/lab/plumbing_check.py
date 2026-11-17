"""Lab plumbing verification (Phase 2, Step 1) — INFRASTRUCTURE
VERIFICATION, not security testing.

Approved by the operator on 2026-11-16 together with the lab scope
(research/lab/README.md). It proves, through Kryonsec's REAL execution
path (load_config -> EgressGate -> EgressPolicy -> KaliSandbox runsc
spawn — exactly what a live engagement does), that:

  1. the authorized lab target is reachable from the sandbox;
  2. unrelated destinations are dropped at the network layer;
  3. DNS egress is pinned to the lab resolver only;
  4. the boundary verifies back and releases cleanly.

It runs ONE benign HTTP GET against the lab target (the same request a
browser makes) plus a public version endpoint, and the negative
controls send packets ONLY to addresses outside the approved scope
(TEST-NET-1, the lab resolver's port 80, a non-pinned public resolver)
where the expected result is a DROP. No scanning, no exploitation; the
only tool used is the allowlisted curl/dig.

Usage (WSL, user dev):
  cd /mnt/d/project/kryon-sec/research/lab
  KRYONSEC_HOME=/home/dev/.kryonsec-selftest \
  ~/venvs/kryonsec-batch1/bin/python plumbing_check.py
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, "/mnt/d/project/kryon-sec/src")

from kryonsec.config import load_config
from kryonsec.purple.egress import EgressGate, build_policy, release_active
from kryonsec.purple.sandbox import KaliSandbox

ENGAGEMENT_ID = "lab-plumbing"
TARGET = "juice-shop.lab"
LAB_RESOLVER = "10.213.44.1"  # HOST-owned dns-bridge gateway (no container IP)
VERSION_ENDPOINTS = (
    f"http://{TARGET}/rest/application-version",
    f"http://{TARGET}/rest/admin/application-version",
)

RESULTS: list[dict] = []


def record(name: str, ok: bool, detail: str, seconds: float = 0.0) -> None:
    RESULTS.append({
        "check": name,
        "result": "REAL" if ok else "FAILED",
        "seconds": round(seconds, 3),
        "detail": detail,
    })
    print(("PASS" if ok else "FAIL"), name, "-", detail, flush=True)


def timed(label: str, ok: bool, detail: str, started: float) -> None:
    record(label, ok, detail, time.time() - started)


def main() -> int:
    cfg = load_config()  # KRYONSEC_HOME carries the approved lab scope
    policy = build_policy(cfg, ENGAGEMENT_ID, TARGET)
    print("policy:", json.dumps(policy.summary()), flush=True)

    gate = EgressGate()
    started = time.time()
    ok, reason = gate.establish(policy)
    timed("egress.establish", ok, reason, started)
    if not ok:
        return 2
    started = time.time()
    ok_v, why = gate.verify(policy)
    timed("egress.verify_before_spawns", ok_v, why, started)

    try:
        sb = KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate)

        # 1) ALLOWED: one benign GET to the lab target root (browser-like)
        started = time.time()
        root = sb.spawn(["curl", "-s", "--max-time", "25", "-o", "/dev/null",
                         "-w", "%{http_code}", f"http://{TARGET}/"])
        timed("target.http_get_200",
              root.ok and root.exit_code == 0 and root.stdout.strip() == "200",
              f"exit={root.exit_code} status={root.stdout.strip()!r}", started)

        # 2) ALLOWED: the app-reported version (target identity record)
        started = time.time()
        version_json = ""
        for url in VERSION_ENDPOINTS:
            ver = sb.spawn(["curl", "-s", "--max-time", "25",
                            "-w", "\n%{http_code}", url])
            body = ver.stdout.strip()
            if ver.ok and ver.exit_code == 0 and body.endswith("200"):
                version_json = body.rsplit("\n", 1)[0]
                break
        timed("target.app_version",
              bool(version_json), version_json[:200] or "no public version endpoint answered 200",
              started)

        # 3) ALLOWED: DNS through the PINNED lab resolver — and it must
        #    serve the lab record (the RIGHT answer, not any answer)
        started = time.time()
        dig = sb.spawn(["dig", f"@{LAB_RESOLVER}", TARGET, "+time=5",
                        "+tries=2"])
        dig_ok = (dig.ok and dig.exit_code == 0
                  and "NOERROR" in dig.stdout
                  and "10.213.43.10" in dig.stdout)
        timed("dns.pinned_resolver_serves_lab_record", dig_ok,
              f"exit={dig.exit_code} NOERROR={'NOERROR' in dig.stdout} "
              f"answer_10.213.43.10={'10.213.43.10' in dig.stdout}", started)

        # 4) BLOCKED: unrelated destination (TEST-NET-1) — dropped, not refused
        started = time.time()
        neg = sb.spawn(["curl", "--max-time", "12", "-o", "/dev/null",
                        "-sS", "http://192.0.2.1/"])
        timed("egress.unrelated_destination_dropped", neg.exit_code == 28,
              f"exit={neg.exit_code} (28 = dropped at the boundary)", started)

        # 5) BLOCKED: the lab resolver on a NON-53 port — only DNS is allowed
        started = time.time()
        neg2 = sb.spawn(["curl", "--max-time", "12", "-o", "/dev/null",
                         "-sS", f"http://{LAB_RESOLVER}:80/"])
        timed("egress.resolver_port80_dropped", neg2.exit_code == 28,
              f"exit={neg2.exit_code}", started)

        # 6) BLOCKED: a public resolver outside the pinned set — no DNS egress
        started = time.time()
        neg3 = sb.spawn(["dig", "@8.8.8.8", "example.com", "+time=5",
                         "+tries=2"])
        timed("egress.public_resolver_dns_dropped",
              not (neg3.ok and neg3.exit_code == 0
                   and "NOERROR" in neg3.stdout),
              f"exit={neg3.exit_code} (must NOT get a NOERROR answer)",
              started)

        # 7) the boundary still verifies AFTER the spawns
        started = time.time()
        ok_v2, why2 = gate.verify(policy)
        timed("egress.verify_after_spawns", ok_v2, why2, started)

    finally:
        started = time.time()
        ok_r, why_r = gate.release(policy)
        timed("egress.release", ok_r, why_r, started)
        release_active(ENGAGEMENT_ID)

    failures = [r for r in RESULTS if r["result"] != "REAL"]
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "plumbing-results.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"engagement": ENGAGEMENT_ID, "target": TARGET,
                   "checks": RESULTS,
                   "summary": f"{len(RESULTS) - len(failures)}/{len(RESULTS)} passed"},
                  fh, indent=2)
    print("results written:", out, flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
