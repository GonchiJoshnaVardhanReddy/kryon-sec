#!/usr/bin/env python3
"""Post-exploit network enumeration (baked into the sandbox image).

argv: /opt/kryonsec/enum_network.py <target>

EVIDENCE COLLECTION ONLY — and LOCAL ONLY: it reads the SANDBOX's OWN
network configuration (/proc/net, interface addresses, the container's
hosts/resolv.conf). It sends NO packets anywhere, and specifically none
to the engagement target. The <target> argument is engagement CONTEXT
for the record.

An evidence probe must ALWAYS emit its JSON record. A probe that dies
with a traceback produces no evidence at all, which a reader cannot tell
apart from "nothing found" — so every collection step is individually
guarded and a failure is reported as data (``errors``), never raised.

(2026-11-18: the interface list used ``socket.getifaddrs()``, an API
CPython has never had. Every real run crashed with AttributeError before
printing anything, so this probe had never produced one byte of
evidence. IPv4 now comes from SIOCGIFADDR, IPv6 from /proc/net/if_inet6.)
"""

import json
import socket
import struct
import sys

#: Linux SIOCGIFADDR ioctl number (bits/ioctls.h) — used with
#: struct.pack("256s", ifname), returning a struct ifreq whose bytes
#: 20..24 are the interface's IPv4 address.
_SIOCGIFADDR = 0x8915


def _read(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _interface_addresses() -> "tuple[list[dict], list[str]]":
    """The sandbox's own interface addresses, plus per-step error notes."""
    errors: "list[str]" = []
    try:
        names = socket.if_nameindex()
    except OSError as exc:
        return [], [f"if_nameindex: {exc}"]
    try:
        import fcntl  # Linux-only; the sandbox image is Linux
    except ImportError as exc:  # pragma: no cover — never true in the image
        return [], [f"fcntl unavailable: {exc}"]

    out: "list[dict]" = []
    for _index, name in names:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                packed = fcntl.ioctl(
                    sock.fileno(), _SIOCGIFADDR,
                    struct.pack("256s", name[:15].encode()),
                )
            out.append({"interface": name,
                        "address": socket.inet_ntoa(packed[20:24])})
        except OSError as exc:
            # lo has no AF_INET ioctl on some kernels; other interfaces
            # may be IPv6-only. Neither is an error worth failing over.
            if name != "lo":
                errors.append(f"{name}: {exc}")

    # IPv6 lives in /proc/net/if_inet6: addr idx prefixlen scope flags name
    for line in _read("/proc/net/if_inet6").splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        raw, name = fields[0], fields[5]
        if len(raw) != 32:
            continue
        groups = [raw[i:i + 4] for i in range(0, 32, 4)]
        try:
            out.append({"interface": name,
                        "address": socket.inet_ntop(
                            socket.AF_INET6,
                            b"".join(bytes.fromhex(g) for g in groups))})
        except (OSError, ValueError) as exc:
            errors.append(f"{name} ipv6: {exc}")
    return out, errors


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    errors: "list[str]" = []

    try:
        hostname = socket.gethostname()
    except OSError as exc:
        hostname = ""
        errors.append(f"hostname: {exc}")

    addresses, address_errors = _interface_addresses()
    errors.extend(address_errors)

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
        "errors": errors,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
