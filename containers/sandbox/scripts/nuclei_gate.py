#!/usr/bin/env python3
"""Nuclei template-policy gate (baked sandbox script, Phase 2B.8).

Called by the image entrypoint BEFORE every nuclei run:

    python3 /opt/kryonsec/nuclei_gate.py nuclei -u <url> -t <path> ...

Enforces the reviewed, hash-pinned template manifest AT EXECUTION TIME
(defense-in-depth Layer 2b — the host Layer-2 argv allowlist is the
authoritative gate):

  - every ``-t <value>`` must be a manifest-approved template FILE with
    the exact reviewed sha256, and must resolve INSIDE the template
    tree (symlink escape refused);
  - the ONE allowed directory value is the exact tree root
    ``/opt/nuclei-templates`` — the legacy EXPLOIT-stage path (human
    Gate-2 approval upstream); its semantics are unchanged. Every other
    directory is refused: no subtree (token-spray/, misconfiguration/,
    cves/, ...) is ever selectable here;
  - remote template / workflow / update sources, OAST endpoints,
    local-file access, self-contained, code, fuzz/DAST, headless,
    dynamic-template and config-injection flags are refused on EVERY
    nuclei run (none of the shipped argv templates ever carry them);
  - a missing/unreadable manifest is fail closed: nuclei refuses to
    run rather than run ungated.

On any violation the gate prints ONE JSON object on stdout —
``{"error": "template_not_approved", ...}`` — and exits 125; the
entrypoint relays it and exits 125 (the host sandbox parser reads it
as a refusal, the same channel as ``tool_not_in_allowlist``).

Exit codes: 0 = the argv is policy-clean; 125 = refused (JSON error
emitted); 2 = internal misuse (gate called without a nuclei argv).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

MANIFEST_PATH = "/opt/kryonsec/nuclei_manifest.json"
TREE_ROOT = "/opt/nuclei-templates"
REAL_TREE_ROOT = os.path.realpath(TREE_ROOT)

#: flags that must NEVER appear on a nuclei run in this image: remote
#: template/workflow loading, template updates, OAST endpoints,
#: local-file payload access, self-contained/code/fuzz/DAST/headless
#: templates, dynamic template selection, config injection.
FORBIDDEN_FLAGS = (
    "-turl", "-wurl", "-ut", "-update-templates", "-ud",
    "-iserver", "-itoken",
    "-lfa", "-allow-local-file-access",
    "-esc", "-enable-self-contained",
    "-code", "-fuzz", "-dast", "-headless",
    "-automatic-scan", "-new-templates", "-ai",
    "-config", "-profile", "-itags",
)


def _refuse(error: str, **extra: str) -> int:
    print(json.dumps({"error": error, **extra}, sort_keys=True))
    return 125


def _sha256_of(path: str) -> "str | None":
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def main(argv: "list[str]") -> int:
    if len(argv) < 2 or argv[1] != "nuclei":
        # internal misuse: the entrypoint only ever calls this with the
        # full nuclei tool argv
        return _refuse("template_policy_gate_misuse")

    try:
        with open(MANIFEST_PATH, encoding="utf-8") as fh:
            manifest = json.load(fh)
        entries = manifest.get("templates")
        if not isinstance(entries, dict) or not entries:
            raise ValueError("manifest carries no reviewed templates")
    except (OSError, ValueError) as exc:
        # fail closed: an unreadable manifest means no verified policy
        return _refuse("template_manifest_unreadable", reason=str(exc)[:120])

    args = argv[2:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in FORBIDDEN_FLAGS:
            return _refuse("forbidden_nuclei_flag", flag=a)
        if a == "-t":
            if i + 1 >= len(args):
                return _refuse("template_not_approved",
                               template="(unterminated -t)")
            value = args[i + 1]
            i += 2
            # Phase 4 tightening (2026-11-17): the legacy allow for the
            # exact tree root (TREE_ROOT == value) is GONE. Phase 1 made
            # every product spawn a manifest-pinned -t FILE pair, so no
            # product code passes a directory anymore — the allow was
            # dead policy that still said "a whole directory is
            # selectable", which the Phase 2B.7 audit disproved
            # (directory membership does not establish safety). Now NO
            # directory value is ever accepted, only manifest-listed,
            # hash-verified files.
            real = os.path.realpath(value)
            if not real.startswith(REAL_TREE_ROOT + os.sep):
                return _refuse("template_not_approved",
                               template=value[:120])
            if os.path.isdir(value):
                # directories other than the exact tree root are never
                # selectable: the Phase 2B.7 audit proved directory
                # membership does not establish safety
                return _refuse("template_not_approved",
                               template=value[:120])
            meta = entries.get(value)
            if not isinstance(meta, dict):
                return _refuse("template_not_approved",
                               template=value[:120])
            want = meta.get("sha256") or ""
            got = _sha256_of(real)
            if not want or got != want:
                return _refuse("template_not_approved",
                               template=value[:120],
                               reason="missing or content-changed")
            continue
        i += 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
