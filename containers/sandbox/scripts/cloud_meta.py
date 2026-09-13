#!/usr/bin/env python3
"""Cloud metadata enumeration probe (baked into the sandbox image).

argv: /opt/kryonsec/cloud_meta.py <target-context-label>

Probes the well-known cloud instance-metadata endpoints from INSIDE the
sandbox (AWS/GCP/Azure/Aliyun styles) and prints a compact JSON summary:
which endpoint answered, and a bounded excerpt of what it returned.

Deliberately inert in the current sandbox: there is no metadata service
reachable from a gVisor container on the default bridge — every probe
fails to connect, which is itself the finding ("no cloud metadata
reachable"). This script exists so the CHECK exists: the day POST_EXPLOIT
runs with a real shell context, this is the evidence-collection step.

Metadata endpoints can return credentials — the response is capped at
2000 chars and printed as JSON (the host bounds output again), and never
written anywhere.
"""

import json
import socket
import sys
import urllib.error
import urllib.request

TIMEOUT_S = 10
MAX_BODY = 2000  # bounded — metadata can contain credentials

# (label, url, headers): the 169.254.169.254 style requires the token hop
# on AWS (IMDSv2) — a plain GET answers 401 there, still a signal.
PROBES = (
    ("aws-imds", "http://169.254.169.254/latest/meta-data/", {}),
    ("gcp-metadata", "http://metadata.google.internal/computeMetadata/v1/",
     {"Metadata-Flavor": "Google"}),
    ("azure-imds",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     {"Metadata": "true"}),
    ("aliyun-metadata", "http://100.100.100.200/latest/meta-data/", {}),
)


def _probe(label: str, url: str, headers: dict) -> dict:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "kryonsec-probe/1.0", **headers})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read(MAX_BODY)
            return {
                "endpoint": label, "status": resp.status,
                "excerpt": body.decode("utf-8", "replace")[:MAX_BODY],
            }
    except urllib.error.HTTPError as e:
        # an answering 401/404 still proves SOMETHING is there
        return {"endpoint": label, "status": e.code,
                "note": "endpoint answered with an error"}
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return {"endpoint": label, "status": None,
                "note": f"unreachable: {str(e)[:80]}"}


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: cloud_meta.py <target-context>"}))
        return 2
    context = sys.argv[1]

    results = [_probe(label, url, headers) for label, url, headers in PROBES]
    reachable = [r for r in results if r.get("status") not in (None,)]
    print(json.dumps({
        "context": context,
        "reachable": len(reachable),
        "results": results,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
