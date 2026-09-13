#!/usr/bin/env python3
"""Post-exploit process enumeration (baked into the sandbox image).

argv: /opt/kryonsec/enum_processes.py <target>

EVIDENCE COLLECTION ONLY. Enumerates processes visible inside the sandbox
(/proc) — cron jobs, running commands, interesting binaries — and prints a
JSON summary. The <target> argument is engagement CONTEXT for the record
(it labels the output; nothing is sent to the target).

No output of full command lines beyond a bound, no environment variable
values (secrets policy — names only), no network activity.
"""

import json
import os
import sys

MAX_PROCS = 500
MAX_CMDLINE = 200
INTERESTING_ENV = {"USER", "HOME", "SHELL", "PATH", "PWD", "TERM"}
INTERESTING_BINARIES = {
    "ssh", "scp", "wget", "curl", "python", "python3", "perl", "ruby",
    "gcc", "nc", "ncat", "socat", "bash", "sh", "docker", "sudo",
}


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except (OSError, ValueError):
        return ""


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    procs = []
    interesting = []
    try:
        pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    except OSError:
        pids = []

    for pid in pids[:MAX_PROCS]:
        comm = _read(f"/proc/{pid}/comm").strip()
        if not comm:
            continue
        cmdline = _read(f"/proc/{pid}/cmdline").replace("\x00", " ").strip()
        procs.append({"pid": pid, "comm": comm[:64]})
        if any(b in comm for b in INTERESTING_BINARIES):
            interesting.append({"pid": pid, "comm": comm[:64],
                                "cmdline": cmdline[:MAX_CMDLINE]})

    env_names = []
    for line in _read("/proc/self/environ").split("\x00"):
        if "=" in line:
            name = line.split("=", 1)[0]
            if name in INTERESTING_ENV:
                env_names.append(name)  # names only — never values

    print(json.dumps({
        "probe": "enum_processes",
        "target_context": target,
        "proc_count": len(procs),
        "processes": procs,
        "interesting": interesting,
        "environment_names": env_names,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
