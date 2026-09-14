#!/usr/bin/env python3
"""Nuclei template metadata search (baked into the sandbox image).

argv: /opt/kryonsec/nuclei_meta.py <term>

Scans the baked /opt/nuclei-templates directory for template files whose
id / tags / description / references mention the search term (a CVE id or
product name), and prints a compact JSON summary:

    {"matches": [{"id": ..., "severity": ..., "tags": [...], "path": ...}]}

Front-matter parsing is deliberately dumb (key: value lines in the YAML
header between the leading --- markers) — no YAML dependency, no code
execution, bounded output. Used by HYPOTHESIZE enrichment: "is there a
public nuclei template for this?" is exploit-availability evidence.
"""

import json
import os
import re
import sys

TEMPLATE_ROOT = "/opt/nuclei-templates"
MAX_MATCHES = 10
MAX_VALUE_LEN = 120
MAX_LIST_ITEMS = 3  # block-list items captured per key (bounded, no YAML dep)


def _front_matter(text: str) -> dict:
    """Parse the leading YAML front-matter (--- delimited) as flat
    key: value pairs. Inline lists appear as '[a, b]' strings; block
    lists (key:\\n  - item) capture up to MAX_LIST_ITEMS item lines
    joined by spaces (M9: multi-line reference lists used to parse as
    empty and never matched). Still no YAML dependency."""
    if not text.startswith("---"):
        return {}
    parts = text.split("---")
    if len(parts) < 3:
        return {}
    header = parts[1]
    out: dict = {}
    last_key: str | None = None  # key whose block list we are inside
    items_seen = 0
    for line in header.splitlines():
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m:
            key, value = m.group(1), m.group(2)
            if value:
                out[key] = value[:MAX_VALUE_LEN]
                last_key = None  # inline value: following lines are not list items
            else:
                last_key = key  # block list starts here
                items_seen = 0
            continue
        item = re.match(r"^\s+-\s*(\S.*)$", line)
        if item and last_key is not None and items_seen < MAX_LIST_ITEMS:
            existing = out.get(last_key)
            out[last_key] = (
                f"{existing} {item.group(1)}" if existing else item.group(1)
            )[:MAX_VALUE_LEN]
            items_seen += 1
    return out


def _iter_templates(root: str):
    """Yield .yaml template paths under root, bounded at 20000 files —
    the full tree is ~15k templates; a bound keeps a corrupted image
    from looping forever."""
    count = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith((".yaml", ".yml")):
                yield os.path.join(dirpath, name)
                count += 1
                if count >= 20000:
                    return


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: nuclei_meta.py <term>"}))
        return 2
    term = sys.argv[1].strip().lower()
    if not term:
        print(json.dumps({"error": "empty term"}))
        return 2

    matches = []
    if not os.path.isdir(TEMPLATE_ROOT):
        print(json.dumps({"error": f"no template dir at {TEMPLATE_ROOT}",
                          "matches": []}))
        return 0
    for path in _iter_templates(TEMPLATE_ROOT):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                fm = _front_matter(f.read(4096))  # header only, bounded
        except OSError:
            continue
        haystack = " ".join(
            str(v) for v in (
                fm.get("id"), fm.get("name"), fm.get("tags"),
                fm.get("description"), fm.get("reference"),
                # newer templates use the plural key with a block list
                fm.get("references"),
            ) if v
        ).lower()
        if term in haystack:
            tags = [
                t for t in str(fm.get("tags", "")).strip("[]").split(",")
                if t.strip()
            ][:8]
            matches.append({
                "id": fm.get("id", os.path.basename(path)),
                "severity": fm.get("severity", ""),
                "tags": tags,
                "path": path,
            })
            if len(matches) >= MAX_MATCHES:
                break
    print(json.dumps({"matches": matches}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
