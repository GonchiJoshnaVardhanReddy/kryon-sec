"""The second production Mode B tool adapter: searchsploit-term
(Phase 2B.4).

Purpose: enrich reconnaissance findings and vulnerability hypotheses
using the Exploit-Database COPY INSIDE the sandbox — read-only
vulnerability intelligence, no network, no target contact, no exploit
execution, no shell, no Post-Exploit capability.

VERIFIED against the digest-pinned sandbox image (live probes, 2B.4):
- executable: `searchsploit` (bash wrapper from Kali's `exploitdb`
  package), database at /usr/share/exploitdb, JSON output via `-j`.
- JSON contract (verified live): one JSON object with SEARCH,
  DB_PATH_EXPLOIT, RESULTS_EXPLOIT[] / RESULTS_SHELLCODE[] whose
  entries carry Title, EDB-ID, Date_Published, Author, Type, Platform,
  Port, Verified ("0"/"1"), Codes ("CVE-...;OSVDB-..."), Source, Path.
  An empty search yields RESULTS_EXPLOIT/SHELLCODE: [].
- options go BEFORE the term (getopts); the FIXED template is
  ["-j", "-t", "{term}"] — title-only search, JSON output, term last.

EXPRESSLY PROHIBITED (never in the template, attested by tests):
  -u/--update (network package update), -m/--mirror (copies exploit
  files to the CWD), -x/--examine (opens exploit in $PAGER),
  -p/--path (copies a path to the clipboard), -w/--www,
  --nmap (executes tools against XML input), --exclude (free value).
A caller value beginning with "-" is REJECTED outright by the shared
option-injection guard in adapters._fill_template (a term "-u ..." is
an option, not a search string).

Search results are recorded as POTENTIAL REFERENCES ONLY: a matching
ExploitDB entry does NOT prove the target is vulnerable, reference
nodes and enrichment flags never unlock a gate, and no exploit code is
ever selected or executed from search results. Verification stays
``not_verified`` everywhere (only VERIFY's independent check upgrades
a finding, Phase 1C).
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "searchsploit-term"
TOOL_EXECUTABLE = "searchsploit"

#: the fixed argv template (options FIRST, term LAST — getopts order),
#: exactly the shape verified live in the pinned image
SEARCHSPLOIT_TERM_TEMPLATE: tuple[str, ...] = (
    "-j", "-t", "{term}",
)


def make_searchsploit_term_adapter():
    """Build the frozen adapter definition."""
    from .adapters import ModeBToolAdapter

    return ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="searchsploit term lookup",
        purpose=(
            "Read-only ExploitDB intelligence from the database baked "
            "into the sandbox: supplies potential public-exploit "
            "REFERENCES for HYPOTHESIZE enrichment. Local JSON query "
            "only — no network, no target contact, and never any "
            "selection or execution of exploit code."
        ),
        category="recon",
        stages=("HYPOTHESIZE",),
        executable=TOOL_EXECUTABLE,
        command_template=SEARCHSPLOIT_TERM_TEMPLATE,
        target_kind="term",
        max_seconds=120,
        output_bound_chars=20_000,
        approvals=(),            # no gate touches HYPOTHESIZE enrichment;
        network="none",          # the local database read changes nothing
        risk="informational",    # about the engagement's authorization
        evidence_kind="json_report",
    )


def production_registry():
    """The shipped registry for the stage that consumes it: explicitly
    the one vetted adapter and nothing else (unknown stays disabled)."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_searchsploit_term_adapter())
    return registry


def secure_term(term: str, *, max_chars: int = 60) -> str:
    """The safe, deterministic search term.

    Same stripping the legacy enrichment applies (alnum/space/dash/dot,
    collapsed) plus REJECTIONS it cannot express:
    - option-shaped values (leading '-') — could be read as a CLI
      option by the tool itself (defense-in-depth on top of the shared
      _fill_template guard);
    - terms with no alphanumeric character (empty/malformed queries).
    """
    import re as _re

    cleaned = _re.sub(r"[^A-Za-z0-9 .\-,]+", " ",
                      (term or "").strip())
    cleaned = _re.sub(r"\s+", " ", cleaned).strip()[:max_chars]
    if not cleaned or not any(ch.isalnum() for ch in cleaned):
        raise ValueError(
            f"searchsploit term {term[:60]!r} reduces to no usable "
            "query characters")
    if cleaned.startswith("-"):
        raise ValueError(
            f"searchsploit term {cleaned[:60]!r} is option-shaped — "
            "refused (option injection)")
    return cleaned


# ---- the parsed output schema -------------------------------------------------


class SearchExploitReference(BaseModel):
    """ONE ExploitDB search result — a potential reference, bounded.

    Honest facts only: what the LOCAL database copy reported for the
    term. No confirmed / vulnerable field exists: a reference matching
    a hypothesis's technology does NOT prove the target is vulnerable.
    """

    model_config = ConfigDict(frozen=True)

    edb_id: str = Field(min_length=1, max_length=16, pattern=r"^[0-9]+$")
    title: str = Field(min_length=1, max_length=200)
    exploit_type: str = Field(default="", max_length=40)
    platform: str = Field(default="", max_length=60)
    date_published: str = Field(default="", max_length=12)
    verified: bool = False
    codes: "tuple[str, ...]" = Field(default=(), max_length=5)
    source: str = Field(default="", max_length=200)
    path: str = Field(default="", max_length=200)

    def properties(self, *, request_id: str, term: str,
                   hypothesis_id: str = "") -> dict:
        """The ``exploit_reference`` node properties — potential
        reference only, provenance verbatim."""
        return {
            "edb_id": self.edb_id,
            "title": self.title,
            "exploit_type": self.exploit_type,
            "platform": self.platform,
            "date_published": self.date_published,
            "verified": self.verified,
            "codes": list(self.codes),
            "source": self.source,
            "path": self.path,
            "search_term": term[:60],
            "hypothesis_id": hypothesis_id,
            "source_tool": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "reference_only": True,
            "untrusted": True,
            "verification": "not_verified",
        }

    def display_line(self) -> str:
        """One bounded report/enrichment line (the same consumer
        surface the legacy table-tail produced — never a verdict)."""
        kind = self.exploit_type or "exploit"
        base = f"EDB-{self.edb_id} [{kind}/{self.platform}] {self.title}"
        if self.codes:
            base += f" ({';'.join(self.codes)})"
        return base[:300]


def parse_searchsploit_json(
    stdout: str,
    *,
    max_references: int = 20,
) -> "tuple[list[SearchExploitReference], int]":
    """Parse bounded references from a `searchsploit -j` run.

    Returns ``(references, malformed)``. The documented contract is ONE
    JSON object (RESULTS_EXPLOIT/RESULTS_SHELLCODE); anything that is
    not that — banner text, a truncated tail (oversized output), a
    half-written dump — is ONE malformed payload, counted, never
    interpreted (fail closed: no reference can be invented from partial
    data). Entries missing EDB-ID/Title or carrying non-numeric ids are
    malformed individually. The count is capped at max_references.
    """
    references: "list[SearchExploitReference]" = []
    malformed = 0

    def _from_rows(rows: object) -> "list[tuple[bool, dict]]":
        rows = rows if isinstance(rows, list) else []
        return [(False, row) for row in rows if isinstance(row, dict)]

    try:
        payload = json.loads(stdout)
    except ValueError:
        return [], 1
    if not isinstance(payload, dict) or not (
            "RESULTS_EXPLOIT" in payload or "RESULTS_SHELLCODE" in payload):
        return [], 1
    rows = _from_rows(payload.get("RESULTS_EXPLOIT")) + \
        _from_rows(payload.get("RESULTS_SHELLCODE"))
    for _verified_flag, row in rows:
        if len(references) >= max_references:
            break
        edb_id = str(row.get("EDB-ID") or "").strip()
        title = str(row.get("Title") or "").strip()
        if not edb_id.isdigit() or not title:
            malformed += 1
            continue
        codes_raw = str(row.get("Codes") or "").strip()
        codes = tuple(
            c.strip()[:60] for c in codes_raw.split(";") if c.strip()
        )
        verified = str(row.get("Verified")).strip() == "1"
        try:
            references.append(SearchExploitReference(
                edb_id=edb_id[:16],
                title=title[:200],
                exploit_type=str(row.get("Type") or "").strip()[:40],
                platform=str(row.get("Platform") or "").strip()[:60],
                date_published=str(row.get("Date_Published") or "")
                .strip()[:12],
                verified=verified,
                codes=codes[:5],
                source=str(row.get("Source") or "").strip()[:200],
                path=str(row.get("Path") or "").strip()[:200],
            ))
        except Exception:    # defensive: bad data is counted, never fatal
            malformed += 1
    return references, malformed


# ---- evidence recording --------------------------------------------------------


def find_adapter_attempt_node(graph: EngagementGraph,
                              request_id: str) -> "dict | None":
    """The ``adapter_attempt`` node this run produced (by request_id);
    None when the run never produced one (refusals are audit-only)."""
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        if props.get("request_id") == request_id:
            return node
    return None


def record_exploitdb_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    term: str,
    references: "list[SearchExploitReference]",
    hypothesis_id: str = "",
    malformations: int = 0,
) -> "list[str]":
    """Map one searchsploit adapter run onto the evidence graph.

    Per reference: one ``exploit_reference`` node (potential-reference-
    only markers, verification not_verified) and a ``produced`` lineage
    edge from the run's ``adapter_attempt`` node. Duplicates (same
    EDB-id label already on the graph) are skipped — first observation
    wins. A run that never executed fabricates NO reference nodes
    (audited refusal instead). Returns created node ids.
    """
    created: "list[str]" = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        audit.write({
            "event": "exploitdb_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "references_offered": len(references),
        })
        return []
    for reference in references:
        label = f"EDB-{reference.edb_id}"
        existing = [n for n in graph.by_type("exploit_reference")
                    if n.get("label") == label]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="exploit_reference",
                label=label,
                properties=reference.properties(
                    request_id=run_record.request_id,
                    term=term,
                    hypothesis_id=hypothesis_id,
                ),
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": TOOL_EXECUTABLE,
                    "adapter": ADAPTER_ID,
                    "local_database": True,
                },
            )
        except Exception as e:   # graph validation: audited, not fatal
            audit.write({
                "event": "exploitdb_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"exploit_reference node refused: {e}"[:200],
                "edb_id": reference.edb_id,
            })
            continue
        created.append(node["id"])
        link(
            graph, "produced", attempt["id"], node["id"],
            provenance={
                "agent": "ADAPTER", "source_type": "tool",
                "adapter": ADAPTER_ID,
            },
            on_refuse=lambda reason, _nid=node["id"]: audit.write({
                "event": "exploitdb_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "exploitdb_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "term": term[:60],
        "references": len(references),
        "malformed": malformations,
        "reference_nodes": len(created),
        "duplicate_or_refused": len(references) - len(created),
    })
    return created
