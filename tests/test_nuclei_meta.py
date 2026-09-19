"""Tests for the baked nuclei_meta.py script (Phase 8 enrichment).

The script lives in containers/sandbox/scripts/ (baked into the image, not
part of the installed package), so it is loaded by path like the
openapi_probe tests do.

Regression note (2026-09-18): the front-matter key regex was anchored with
``^([a-z_]+):``, but real nuclei templates nest every useful field inside the
top-level ``info:`` block. The parser therefore captured only ``id`` —
``severity`` always came back empty and product-name searches never matched.
"""

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# A template shaped the way nuclei actually writes them: a leading `---`
# front-matter block with everything useful nested under `info:`, a
# block-list `reference:`, then the request section after the closing `---`.
TEMPLATE = """---
id: CVE-2021-44228

info:
  name: Apache Log4j2 RCE
  author: kryonsec
  severity: critical
  description: Apache Log4j2 remote code execution
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://logging.apache.org/log4j/2.x/security.html
  tags: cve,cve2021,rce,log4j
---

http:
  - method: GET
    path:
      - "{{BaseURL}}"
"""


def _load():
    path = REPO_ROOT / "containers" / "sandbox" / "scripts" / "nuclei_meta.py"
    spec = importlib.util.spec_from_file_location("nuclei_meta", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _haystack(fm: dict) -> str:
    """The search haystack main() builds, extracted so it can be tested."""
    return " ".join(
        str(v) for v in (
            fm.get("id"), fm.get("name"), fm.get("tags"),
            fm.get("description"), fm.get("reference"),
            fm.get("references"),
        ) if v
    ).lower()


def test_front_matter_captures_nested_info_block():
    fm = _load()._front_matter(TEMPLATE)
    assert fm["id"] == "CVE-2021-44228"
    # these all live inside `info:` — the old anchored regex missed every one
    assert fm["name"] == "Apache Log4j2 RCE"
    assert fm["severity"] == "critical"
    assert fm["description"] == "Apache Log4j2 remote code execution"


def test_front_matter_captures_inline_tags():
    fm = _load()._front_matter(TEMPLATE)
    assert fm["tags"] == "cve,cve2021,rce,log4j"


def test_front_matter_captures_block_list_reference():
    fm = _load()._front_matter(TEMPLATE)
    assert "nvd.nist.gov" in fm["reference"]
    assert "logging.apache.org" in fm["reference"]


def test_product_name_search_matches():
    """The headline use case: 'is there a public template for this product?'

    severity is parsed but deliberately not part of the haystack (it is not
    something anyone searches for), so it is asserted in the parser tests.
    """
    hay = _haystack(_load()._front_matter(TEMPLATE))
    for term in ("log4j", "rce", "apache", "cve-2021-44228"):
        assert term in hay, f"expected {term!r} to be searchable"
    # reference URLs are searchable — the M9 case
    assert "nvd.nist.gov" in hay


def test_unrelated_term_does_not_match():
    hay = _haystack(_load()._front_matter(TEMPLATE))
    assert "heartbleed" not in hay


def test_missing_front_matter_returns_empty():
    mod = _load()
    assert mod._front_matter("just some text, no delimiters") == {}
    assert mod._front_matter("---\nonly one delimiter\n") == {}


def test_block_list_capture_is_bounded():
    """Only MAX_LIST_ITEMS items are kept per key — no unbounded growth."""
    mod = _load()
    body = "---\nid: X\ninfo:\n  reference:\n" + "".join(
        f"    - https://example.com/{i}\n" for i in range(20))
    body += "---\n"
    fm = mod._front_matter(body)
    assert fm["reference"].count("http") == mod.MAX_LIST_ITEMS
