#!/usr/bin/env python3
"""Post-exploit network enumeration (baked into the sandbox image).

argv: /opt/kryonsec/enum_network.py <target>

EVIDENCE COLLECTION ONLY — and LOCAL ONLY: it reads the SANDBOX's OWN
network configuration (/proc/net, interface addresses, the container's
hosts/resolv.conf). It sends NO packets anywhere, and specifically none
to the engagement target. The <target> argument is engagement CONTEXT
for the record.
"""

import json
import socket
import sys


def _read(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""

    try:
        hostname = socket.gethostname()
        addresses = [
            {"interface": name, "address": info[0][1]}
            for name, infos in socket.getifaddrs().items()
            if infos and infos[0] and infos[0][0] in (socket.AF_INET, socket.AF_INET6)
            for info in [infos[0]]
        ]
    except OSError:
        hostname, addresses = "", []

    # established sockets only — the listening list would just be the
    # sandbox's own processes
    established = []
    for line in _read("/proc/net/tcp").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[3] == "01":  # TCP_ESTABLISHED
            established.append({"local": fields[1], "remote": fields[2]})

    print(json.dumps({
        "probe": "enum_network",
        "target_context": target,
        "hostname": hostname,
        "interfaces": addresses,
        "established_sockets": established[:100],
        "resolver": [l for l in _read("/etc/resolv.conf").splitlines()
                     if l.strip() and not l.startswith("#")],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
