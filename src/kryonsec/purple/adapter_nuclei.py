"""The fourth production Mode B tool adapter: nuclei-probe (Phase 2B.4).

Target: the sandbox image's bundled Nuclei (verified in the pinned
image: executable ``nuclei``, engine v3.11.1, entrypoint-allowlisted)
for authorized NON-DESTRUCTIVE vulnerability checks against in-scope
web endpoints, in the RECON_ACTIVE stage only, through the Phase 2B.2
adapter framework — the SAME engine, sandbox, allowlist, egress
boundary, scope checks, audit chain and evidence graph as every other
tool. This module adds NO general-purpose command interface: the
executable is the fixed ``nuclei`` binary and the argv template is
fixed and Layer-2 validated.

TEMPLATE POLICY (the reviewed, hash-pinned manifest — Phase 2B.8):

- Phase 2B.7 audited the previous directory-level allowlist and found
  UNSAFE templates inside dirs it had called "vetted": token-spray/
  (third-party token validation using discovered credentials),
  misconfiguration/ (state-changing POST/PURGE operations, unsafe raw
  HTTP requests, OAST/interactsh dependencies) and a login/logout
  template inside exposed-panels/. DIRECTORY MEMBERSHIP ALONE DOES NOT
  ESTABLISH SAFETY.
- The sandbox image bakes the upstream nuclei-templates tree at build
  time (Dockerfile.kali, PINNED to the reviewed commit recorded in the
  manifest); the image is digest-pinned, so the tree is IMMUTABLE for
  every run — no template can be uploaded, fetched or changed at
  runtime.
- The policy is an EXPLICIT, version-pinned allowlist of individually
  REVIEWED templates (``nuclei_manifest.json``: template id, image
  path, sha256 of the reviewed content). The adapter's argv carries
  the approved set as FIXED LITERALS — one ``-t <file>`` pair per
  reviewed template, built FROM the manifest, so a manifest change is
  an adapter change. There is NO ``{template}`` variable: a caller
  cannot choose a template. token-spray/ and misconfiguration/ are
  entirely ABSENT from the manifest this phase (no per-template
  review passed them yet); everything else the tree contains — cves,
  vulnerabilities, default-logins, fuzzing, credential-stuffing,
  takeovers and the unreviewed rest of exposures — is simply never
  emitted by the adapter.
- Every manifest entry was machine-reviewed (per-template gates:
  GET-only, no body/raw HTTP, no credential-bearing parameters, no
  login/logout or session-destroying paths, no external hosts, no
  interactsh/OAST, no payloads/fuzzing, no intrusive tag, no
  code/network/file protocol blocks) and only templates that passed
  ALL gates are approved — if a template cannot be confidently
  demonstrated safe, it is not approved.
- The Docker build verifies EVERY manifest entry against the baked
  tree (exists + sha256 match) and FAILS the build on drift; the
  sandbox entrypoint re-verifies the argv's -t files against the
  baked manifest at every spawn and refuses unreviewed, missing or
  content-changed templates (fail closed, never silently executed).
- Remote template sources are structurally impossible here: the fixed
  argv never carries ``-turl``/``-wurl``/``-ut`` (remote template /
  workflow URLs, template update), ``-duc`` additionally disables
  the update check, and the entrypoint refuses those flags on every
  nuclei run. The sandbox's egress boundary is target-scope anyway.
- ``-etags intrusive`` excludes any template that declares itself
  intrusive; OAST/out-of-band callbacks are OFF via ``-ni`` (which
  also excludes OAST-based templates); local-file payload access
  (``-lfa``), self-contained templates (``-esc``), code templates
  (``-code``), fuzz/DAST templates (``-fuzz``/``-dast``) and headless
  templates (``-headless``) are NOT enabled — the defaults that refuse
  them hold, and the fixed argv can never turn them on.

BOUNDS: ``-rl 20`` requests/second, ``-c 10`` template concurrency,
``-timeout 15`` per request, ``-retries 1``, ``-mt 2m`` nuclei's own
graceful max-time (measured live through gVisor under the sandbox's
caps; the entrypoint kills any tool at 300s hard; the adapter's
max_seconds is 300).

OUTPUT CONTRACT (verified against the pinned image's nuclei v3.11.1):
    -j / -jsonl   one JSON object per match line (stable contract)
    -silent       findings only (no banners in the JSONL stream)
    -nc           no ANSI escapes
    -or           omit raw request/response pairs (bounded, and the
                  raw traffic is not evidence we need to keep)

Every parse is DEFENSIVE: a line that is not a JSON object carrying a
template id and a matched target is skipped and counted — nuclei's own
non-JSON chatter, [INF]/[WRN]/[ERR] log lines and half-written tails
are all malformed, never interpreted. A detected template match is a
CANDIDATE: its textual severity label is reported metadata, and no
exit code, severity or matcher outcome is ever a confirmed finding.
``verification`` is HARD-WIRED to ``not_verified``; only the VERIFY
subagent (independent tool, same Phase-1C rule) can upgrade anything.

DUPLICATE AVOIDANCE: the existing ``nuclei`` EXPLOIT semantics
(allowlist template, exploit.py's fixed argv + verdict-word
confirmation markers) are UNTOUCHED — this adapter does not enter the
EXPLOIT stage and produces ``vuln_candidate`` nodes, a different node
type from EXPLOIT's ``finding`` nodes, so detection can never
 masquerade as a confirmed exploit finding.

Registration is explicit: :func:`production_registry` is the shipped
registry for this adapter; :func:`recon_active_registry` is the
combined RECON_ACTIVE registry (httpx-probe 2B.3 + whatweb-probe 2B.5
+ nuclei-probe 2B.4) the runner injects. Anything not registered stays
disabled.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .adapters import AdapterRunRecord
from .lineage import link
from .recon_passive import EngagementGraph

log = logging.getLogger(__name__)

ADAPTER_ID = "nuclei-probe"
#: the id RECON_ACTIVE's wiring looks up (same identity; the whatweb
#: and httpx modules keep their ids locally — this module exposes its
#: own constant for the same lookup pattern)
NUCLEI_ADAPTER_ID = ADAPTER_ID
TOOL_EXECUTABLE = "nuclei"

#: where the digest-pinned image bakes the nuclei template tree
#: (Dockerfile.kali — world-readable at build time; runtime egress to
#: template sources does not exist in the sandbox anyway)
TEMPLATE_ROOT = "/opt/nuclei-templates/http"

#: the reviewed, hash-pinned template manifest (Phase 2B.8):
#:
#: Phase 2B.7 audited the previous directory-allowlist policy and found
#: UNSAFE templates inside dirs it called "vetted": token-spray/
#: (third-party token validation with discovered credentials),
#: misconfiguration/ (state-changing POST/PURGE, unsafe raw HTTP,
#: OAST/interactsh dependencies) and a login/logout template inside
#: exposed-panels/. Directory membership never established safety, so
#: the policy now draws from an EXPLICIT, version-pinned allowlist of
#: individually reviewed template files:
#:
#: - every entry is a reviewed template ID + its IMAGE path + the
#:   sha256 of the reviewed content, produced by
#:   ``tools/nuclei_template_review.py`` against a pinned
#:   nuclei-templates commit (recorded inside the manifest);
#: - the Docker build verifies every entry against the baked tree and
#:   FAILS the build on any mismatch (reproducibility);
#: - the sandbox entrypoint re-verifies the argv's -t files against the
#:   baked manifest at every spawn and REFUSES unreviewed, missing or
#:   content-changed templates (fail closed);
#: - remote template sources stay structurally impossible: the fixed
#:   argv never carries -turl/-wurl/-ut, -duc disables the update
#:   check, and the entrypoint additionally refuses those flags on
#:   every nuclei run.
#:
#: token-spray/ and misconfiguration/ are NOT in the manifest at all
#: this phase (no per-template review passed them yet). The non-GET,
#: body/raw, credential-parameter, login/logout, external-host,
#: interactsh, payloads/fuzzing, intrusive-tag and code/network/file
#: protocol gates all REJECTED during review; only pure-GET, single/
#: few-request, BaseURL-rooted detection templates are approved.

_MANIFEST_PATH = Path(__file__).resolve().parent / "nuclei_manifest.json"


class NucleiPolicyError(RuntimeError):
    """The template manifest is missing, malformed or inconsistent —
    Nuclei execution stays DISABLED (fail closed, never a fallback to
    the unsafe directory policy)."""


def load_template_manifest() -> dict[str, dict[str, str]]:
    """The reviewed manifest: {image template path: {id, sha256}}.

    Hard-requires every entry to carry a non-empty id and a 64-hex
    sha256; any malformed entry refuses the whole manifest.
    """
    try:
        raw = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise NucleiPolicyError(
            f"nuclei template manifest unreadable at {_MANIFEST_PATH}: "
            f"{e} — Nuclei execution stays disabled") from e
    entries = raw.get("templates")
    if not isinstance(entries, dict) or not entries:
        raise NucleiPolicyError(
            "nuclei template manifest carries no reviewed templates "
            "— Nuclei execution stays disabled")
    for path, meta in entries.items():
        ok = (
            isinstance(path, str)
            and path.startswith(f"{TEMPLATE_ROOT}/")
            and path.endswith(".yaml")
            and isinstance(meta, dict)
            and isinstance(meta.get("id"), str) and meta["id"].strip()
            and isinstance(meta.get("sha256"), str)
            and len(meta["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in meta["sha256"])
        )
        if not ok:
            raise NucleiPolicyError(
                f"malformed manifest entry for {path!r} — Nuclei "
                "execution stays disabled")
    return entries


#: THE approved inventory — the ONLY template files the adapter may
#: ever schedule (frozen literals in the argv template below).
APPROVED_TEMPLATES: dict[str, dict[str, str]] = load_template_manifest()

#: the approved paths in manifest order (deterministic; the argv is
#: built from these, so a manifest change IS an adapter change)
APPROVED_TEMPLATE_PATHS: tuple[str, ...] = tuple(
    sorted(APPROVED_TEMPLATES))

#: the manifest's reviewed templates commit (reproducibility record)
NUCLEI_TEMPLATES_COMMIT = json.loads(_MANIFEST_PATH.read_text(
    encoding="utf-8")).get("templates_commit", "")

#: the fixed argv template — frozen literals everywhere except {url}.
#: Every safety flag is a LITERAL: the caller cannot add, remove or
#: reshape a single argument (the Layer-2 check re-validates the
#: rendered argv against exactly this template). The template list is
#: EXACTLY the reviewed manifest: no directory is ever passed.
_TEMPLATE_ARGS: tuple[str, ...] = tuple(
    arg for path in APPROVED_TEMPLATE_PATHS for arg in ("-t", path)
)
NUCLEI_PROBE_TEMPLATE: tuple[str, ...] = (
    "-u", "{url}",
    *_TEMPLATE_ARGS,
    "-etags", "intrusive",     # never run a self-declared intrusive template
    "-j",                      # JSONL output (one object per match line)
    "-silent",                 # matches only; no banners in the stream
    "-nc",                     # no ANSI escapes
    "-ni",                     # NO interactsh / OOB callbacks; OAST-based
                               # templates are excluded entirely
    "-duc",                    # no update check (offline-deterministic)
    "-or",                     # omit raw request/response pairs
    "-rl", "20",               # 20 requests/second
    "-c", "10",                # 10 templates in parallel
    "-timeout", "15",          # per-request timeout (seconds)
    "-retries", "1",           # single retry, no hammering
    "-mt", "2m",               # nuclei's own graceful max-time: the
                               # reviewed-template run is bounded well
                               # inside it (the entrypoint kills at 300s
                               # hard — measured live)
)


def template_policy_violations(argv: "tuple[str, ...] | list[str]") \
        -> "list[str]":
    """Every way ``argv`` violates the non-destructive template policy.

    The hard rule: a ``-t`` value must be EXACTLY an approved manifest
    path — no directories, no unreviewed files, no token-spray/ or
    misconfiguration/ subtree, nothing outside the manifest. (The
    legacy EXPLOIT stage keeps its own path via its own allowlist; this
    policy is the RECON_ACTIVE probe's.) Remote-template/OAST/update
    flags are refused here too, so the check documents the whole
    boundary in one place; Layer-2 argv validation remains the
    execution-time enforcement.
    """
    violations: list[str] = []
    args = list(argv)
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-t":
            value = args[i + 1] if i + 1 < len(args) else ""
            if value not in APPROVED_TEMPLATES:
                violations.append(
                    f"template not in the reviewed inventory: {value!r}")
            i += 2
            continue
        for flag in ("-turl", "-wurl", "-ut", "-update-templates", "-ud",
                     "-iserver", "-itoken", "-lfa", "-esc", "-code",
                     "-fuzz", "-dast", "-headless", "-automatic-scan",
                     "-new-templates", "-ai", "-config", "-profile",
                     "-itags"):
            if a == flag:
                violations.append(f"forbidden flag: {flag}")
        i += 1
    return violations


def make_nuclei_probe_adapter():
    """Build the frozen adapter definition.

    A factory (not a module constant) keeps the import graph light and
    lets each caller own its instance; the definition itself is fully
    determined — same registry identity everywhere. Registration
    REFUSES (NucleiPolicyError) unless the argv template's -t values
    are exactly the reviewed manifest — the policy is enforced by the
    adapter itself, not merely documented.
    """
    from .adapters import ModeBToolAdapter

    adapter = ModeBToolAdapter(
        adapter_id=ADAPTER_ID,
        title="nuclei non-destructive check",
        purpose=(
            "Authorized non-destructive vulnerability checks against "
            "in-scope web endpoints: Nuclei over the reviewed, "
            "hash-pinned template manifest (exposed configs and "
            "panels; no token spraying, no state-changing checks) — "
            "detection only, RECON_ACTIVE only. Matches are "
            "candidates, never confirmed findings."
        ),
        category="web_recon",
        stages=("RECON_ACTIVE",),
        executable=TOOL_EXECUTABLE,
        command_template=NUCLEI_PROBE_TEMPLATE,
        target_kind="url",
        max_seconds=300,        # <= the sandbox's own 330s ceiling
        output_bound_chars=20_000,
        approvals=(),            # RECON_ACTIVE authorization = the
        network="target_scope",  # engagement model, the SAME standing
        risk="active",           # as the legacy recon probes
        evidence_kind="json_report",
    )
    # self-check: the adapter's argv must carry EXACTLY the reviewed
    # inventory — a drift between the manifest and the frozen template
    # refuses registration (fail closed)
    violations = template_policy_violations(adapter.command_template)
    if violations:
        raise NucleiPolicyError(
            f"{ADAPTER_ID}: template policy violated — "
            f"{violations[:3]} — Nuclei execution stays disabled")
    return adapter


def production_registry():
    """The shipped Mode B adapter registry: EXPLICITLY contains this
    one vetted production adapter and nothing else. Unknown adapters
    remain disabled elsewhere."""
    from .adapters import AdapterRegistry

    registry = AdapterRegistry()
    registry.register(make_nuclei_probe_adapter())
    return registry


# ---- the parsed output schema ------------------------------------------------


class NucleiCandidate(BaseModel):
    """ONE parsed nuclei JSONL match line — one detected candidate.

    Honest fields only: what nuclei reported, bounded. There is NO
    confirmed/verified field and the severity is named
    ``severity_as_reported`` on purpose: the template author's label is
    DATA about the match, not a verdict this engine reached, and it
    must never be confused with the finding verification workflow.
    """

    model_config = ConfigDict(frozen=True)

    template_id: str = Field(min_length=1, max_length=120)
    name: str = Field(default="", max_length=300)
    severity_as_reported: str = Field(default="", max_length=20)
    matched: str = Field(min_length=1, max_length=500)
    host: str = Field(default="", max_length=300)
    tags: tuple[str, ...] = Field(default=(), max_length=12)
    template_path: str = Field(default="", max_length=300)
    #: the matcher that fired (one template can fire several — the
    #: node is the (template @ matched) candidate, first observation wins)
    matcher_name: str = Field(default="", max_length=120)
    excerpt: str = Field(max_length=600)

    def label(self) -> str:
        """The ``vuln_candidate`` node label: (template, matched
        target) — the dedupe key (a repeat run adds no node)."""
        return f"{self.template_id} @ {self.matched}"[:300]

    def properties(self, *, request_id: str) -> dict:
        """The ``vuln_candidate`` node properties — classification is
        ``detected_candidate`` and verification is ``not_verified``:
        detection is neither confirmation nor independent
        verification, whatever the matcher or severity says."""
        return {
            "classification": "detected_candidate",
            "template_id": self.template_id,
            "name": self.name,
            "severity_as_reported": self.severity_as_reported,
            "matched": self.matched,
            "host": self.host,
            "tags": list(self.tags),
            "template_path": self.template_path,
            "matcher_name": self.matcher_name,
            "excerpt": self.excerpt,
            "source": TOOL_EXECUTABLE,
            "adapter": ADAPTER_ID,
            "request_id": request_id,
            "untrusted": True,
            "verification": "not_verified",
        }


#: nuclei only reports a textual severity in one of these (v3.11.1);
#: anything else is not trusted into the field
_SEVERITIES = frozenset({
    "info", "low", "medium", "high", "critical", "unknown",
})


def parse_nuclei_json_lines(
    stdout: str,
    *,
    max_candidates: int = 50,
) -> "tuple[list[NucleiCandidate], int]":
    """Parse bounded JSONL candidates from a nuclei run.

    Returns ``(candidates, malformed_lines)``. A line counts as
    malformed when it is non-empty and NOT a strict JSON object
    carrying a template id and a matched target — nuclei's own log
    chatter, error lines and half-written tails are all malformed,
    never interpreted, never labelled candidates. An explicit
    ``matcher-status: false`` object (a non-result, not a detection)
    is likewise counted, never promoted. The count is capped at
    ``max_candidates``; anything over the cap is left unparsed
    (bounded output, honest and deterministic).
    """
    candidates: list[NucleiCandidate] = []
    malformed = 0
    for line in (stdout or "").splitlines():
        if len(candidates) >= max_candidates:
            break
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        if raw.get("matcher-status") is False:
            malformed += 1          # a non-result is not an observation
            continue
        template_id = raw.get("template-id") or raw.get("template")
        # the REAL v3.11.1 shape carries "matched-at" (verified live);
        # "matched" is the older key and "url"/"host" last resorts —
        # all are just WHERE the template matched, defensively read
        matched = (raw.get("matched-at") or raw.get("matched")
                   or raw.get("url") or raw.get("host"))
        if not isinstance(template_id, str) or not template_id.strip() \
                or not isinstance(matched, str) or not matched.strip():
            malformed += 1
            continue
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        severity = info.get("severity")
        tags = info.get("tags")
        if isinstance(tags, str):
            tags = [t for t in (part.strip() for part in tags.split(","))
                    if t]
        elif not isinstance(tags, list):
            tags = []
        try:
            candidates.append(NucleiCandidate(
                template_id=template_id.strip()[:120],
                name=str(info.get("name") or "")[:300],
                severity_as_reported=(severity if isinstance(severity, str)
                                      and severity.lower() in _SEVERITIES
                                      else ""),
                matched=matched.strip()[:500],
                host=str(raw.get("host") or "")[:300],
                tags=tuple(str(t)[:60] for t in tags[:12]),
                template_path=str(raw.get("template-path")
                                  or raw.get("template-url") or "")[:300],
                matcher_name=str(raw.get("matcher-name") or "")[:120],
                excerpt=line[:600],
            ))
        except Exception:   # defensive: a bad line is data, never a crash
            malformed += 1
    return candidates, malformed


# ---- evidence recording -------------------------------------------------------


def find_adapter_attempt_node(graph: EngagementGraph,
                              request_id: str) -> "dict | None":
    """The ``adapter_attempt`` node this run produced (by request_id —
    stable across node hunting). None when the run never produced one
    (refusals are audit-only by the 2B.2 design)."""
    for node in graph.by_type("adapter_attempt"):
        props = node.get("properties") or {}
        if props.get("request_id") == request_id:
            return node
    return None


def record_nuclei_evidence(
    graph: EngagementGraph,
    audit: AuditLog,
    *,
    run_record: AdapterRunRecord,
    candidates: "list[NucleiCandidate]",
    malformed_lines: int = 0,
) -> "list[str]":
    """Map one nuclei adapter run onto the evidence graph.

    For each candidate: one ``vuln_candidate`` node (a node type
    RESERVED for pre-confirmation detections — never the ``finding``
    nodes EXPLOIT and VERIFY own), a ``produced`` lineage edge from the
    run's ``adapter_attempt`` node, with provenance kept verbatim.
    Duplicate candidates (same template @ matched target already on
    the graph) are skipped — first observation wins, matching the
    graph's own idempotence rule. Refusal to link is AUDITED, never
    silent and never fatal to the run.

    Returns the list of created node ids.
    """
    created: list[str] = []
    attempt = find_adapter_attempt_node(graph, run_record.request_id)
    if attempt is None:
        # no run node -> no candidate nodes: a refusal must never
        # leave fabricated detection evidence behind
        audit.write({
            "event": "nuclei_adapter_evidence_refused",
            "request_id": run_record.request_id,
            "reason": "run produced no adapter_attempt node "
                      "(refused or not executed)",
            "candidates_offered": len(candidates),
        })
        return []
    for candidate in candidates:
        label = candidate.label()
        existing = [n for n in graph.by_type("vuln_candidate")
                    if n.get("label") == label]
        if existing:
            continue
        try:
            node = graph.add_node(
                node_type="vuln_candidate",
                label=label,
                properties=candidate.properties(
                    request_id=run_record.request_id),
                provenance={
                    "agent": "ADAPTER",
                    "source_type": "tool",
                    "tool": TOOL_EXECUTABLE,
                    "adapter": ADAPTER_ID,
                },
            )
        except Exception as e:   # graph validation: audited, not fatal
            audit.write({
                "event": "nuclei_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "reason": f"vuln_candidate node refused: {e}"[:200],
                "label": label[:300],
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
                "event": "nuclei_adapter_evidence_refused",
                "request_id": run_record.request_id,
                "node_id": _nid,
                "reason": str(reason)[:200],
            }),
        )
    audit.write({
        "event": "nuclei_adapter_evidence",
        "adapter": ADAPTER_ID,
        "tool": TOOL_EXECUTABLE,
        "request_id": run_record.request_id,
        "candidates": len(candidates),
        "malformed_lines": malformed_lines,
        "vuln_candidate_nodes": len(created),
        "duplicate_or_refused": len(candidates) - len(created),
    })
    return created
