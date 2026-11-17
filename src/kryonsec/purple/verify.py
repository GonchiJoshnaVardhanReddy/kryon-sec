"""VERIFY subagent (spec v2.1.1 §4.2, Zone B).

Independently re-checks every CONFIRMED finding using a different tool
than the one that found it (curl instead of sqlmap). For SQL-injection
findings this is the classic boolean check: fetch the URL with
`param=1 AND 1=1` and with `param=1 AND 1=2`; if the server treats the
injected boolean as SQL, the two responses differ.

A finding is marked "verified" only when this independent method agrees.
Phase 1C: every verify_attempt record now carries a derived status —
verified / disagreed / inconclusive / not_run — derived from its own
execution evidence (views.verification_status; the read-time derivation
stays authoritative). A blocked check (scope refusal, missing probe
parameter, failed spawn) keeps its actual blocking reason and is never
described as disproven or safe. The finding is linked to its check by a
verified_by lineage edge between node ids.

Batch 5B: the method a category is verified with is a REGISTERED
contract (``verify_contract.py``), not a hardcoded branch. A finding is
probed only when its category has a contract — the boolean probe is
evidence for SQL injection and for nothing else, so other categories
are no longer probed with it (that was a false-positive factory).
An unsupported category keeps its honest ``not_run`` with the real
reason and its reachability evidence; the contract's tool must differ
from the finding's own tool (independence); the contract's budget and
confidence limit travel with every attempt record.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ..config import KryonsecConfig
from . import lineage
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .exploit import compose_url
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph
from .sandbox import KaliSandbox
from .verify_contract import (
    finding_category,
    verification_contract_for,
)
from .views import (
    VERIFICATION_DISAGREED,
    VERIFICATION_INCONCLUSIVE,
    VERIFICATION_NOT_RUN,
    VERIFICATION_UNRESOLVED,
    VERIFICATION_VERIFIED,
)

log = logging.getLogger(__name__)


def _boolean_probe_urls(url: str) -> tuple[str, str] | None:
    """From a URL like http://t/showthread.asp?id=1 build the
    (true, false) pair: id=1 AND 1=1 vs id=1 AND 1=2.

    Returns None when the URL has no query string (nothing to probe).
    """
    parts = urlsplit(url)
    if not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    # probe the first parameter that already has a numeric value
    for i, (k, v) in enumerate(pairs):
        if v.isdigit():
            true_pairs = list(pairs)
            true_pairs[i] = (k, f"{v} AND 1=1")
            false_pairs = list(pairs)
            false_pairs[i] = (k, f"{v} AND 1=2")
            base = (parts.scheme, parts.netloc, parts.path, "", "")
            return (
                urlunsplit(base) + "?" + urlencode(true_pairs, quote_via=quote),
                urlunsplit(base) + "?" + urlencode(false_pairs, quote_via=quote),
            )
    return None


class VerifySubagent:
    """Runs the VERIFY state: independent confirmation of findings."""

    def __init__(
        self,
        cfg: KryonsecConfig,
        graph: EngagementGraph,
        audit: AuditLog,
        target: str,
        sandbox: KaliSandbox,
        allowlist: ToolAllowlist | None = None,
    ):
        self.cfg = cfg
        self.graph = graph
        self.audit = audit
        self.target = target
        self.sandbox = sandbox
        self.allowlist = allowlist or ToolAllowlist()

    def run(self) -> SubagentResult:
        self.audit.write({
            "event": "state_enter",
            "state": "VERIFY",
            "target": self.target,
        })

        findings = [
            n for n in self.graph.by_type("finding")
            if n["properties"].get("confirmed", True)
        ]
        from .verify_contract import FINDING_VERIFICATION_CONTRACTS
        self.audit.write({
            "event": "verify_plan",
            "findings_to_verify": len(findings),
            "method": "independent curl boolean probe (AND 1=1 vs AND 1=2)",
            "contracts": sorted(FINDING_VERIFICATION_CONTRACTS),
        })

        verified = 0
        for f in findings:
            verified += self._verify_one(f)

        self.audit.write({
            "event": "verify_done",
            "verified": verified,
            "failed_or_unverifiable": len(findings) - verified,
        })
        return SubagentResult(status="ok")

    def _discovered_scheme(self) -> str:
        """https when EXPLOIT discovered the target resets plain http
        (engagement_note node in the graph), else http."""
        for n in self.graph.by_type("engagement_note"):
            if n["label"] == "scheme" and n["properties"].get("scheme") == "https":
                return "https"
        return "http"

    def _verify_one(self, finding: dict) -> int:
        """Independently check one finding. Returns 1 if verified.

        Batch 5B: the method comes from the finding category's REGISTERED
        contract. No contract — the category is unsupported, the finding
        keeps its honest ``not_run`` (plus whatever reachability evidence
        the secondary probes can supply), and nothing is probed with a
        method that would not be evidence for it.
        """
        finding_id = finding["label"]
        # the finding's hypothesis supplies the URL
        hyp = next(
            (n for n in self.graph.by_type("hypothesis")
             if n["label"] == finding_id), None,
        )
        if hyp is None:  # pragma: no cover — findings always have one
            return 0
        category = finding_category(finding)
        contract = verification_contract_for(category)
        asset = hyp["properties"].get("target_asset", "")
        # subdomain-aware like EXPLOIT: '/webmail/x' means webmail.<target> —
        # without this the probe hits the wrong vhost on the main host
        subs = [n["label"] for n in self.graph.by_type("subdomain")]
        url = compose_url(self.target, asset, subs, scheme=self._discovered_scheme())
        if url is None:
            # asset is out of engagement scope — never probe it
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "reason": "hypothesis asset outside engagement scope",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"status": VERIFICATION_NOT_RUN,
                            "verified": False, "method": "n/a",
                            "category": category,
                            "reason": "asset outside engagement scope"},
            )
            return 0

        if contract is None:
            # Unsupported category: no registered method is evidence for
            # it, so nothing is probed with one. Gather what SECONDARY
            # evidence exists (asset reachable / TLS up) — honest
            # reachability evidence that never marks a finding verified.
            secondary = self._secondary_probes(url)
            reason = (
                f"no verification contract for category '{category}'")
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "category": category,
                "reason": reason,
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"status": VERIFICATION_NOT_RUN,
                            "verified": False, "method": "n/a",
                            "category": category,
                            "reason": reason,
                            "secondary_evidence": secondary},
            )
            return 0

        # Independence: the verification tool must differ from the tool
        # that produced the finding — re-running the finding's own tool
        # is a repeat, not an independent check.
        origin_tool = str(finding["properties"].get("tool") or "")
        if origin_tool == contract.tool:
            reason = ("verification tool is the finding's own tool "
                      f"({contract.tool!r}) — not independent")
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "category": category,
                "reason": reason,
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"status": VERIFICATION_NOT_RUN,
                            "verified": False, "method": "n/a",
                            "category": category,
                            "reason": reason},
            )
            return 0

        probes = _boolean_probe_urls(url)
        if probes is None:
            # The contract's numeric-parameter prerequisite is unmet.
            # Gather what SECONDARY evidence exists (asset reachable /
            # TLS up) with tools other than curl — honest reachability
            # evidence, but it never marks a finding "verified" by itself.
            secondary = self._secondary_probes(url)
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "category": category,
                "reason": "no numeric query parameter to probe",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"status": VERIFICATION_NOT_RUN,
                            "verified": False, "method": "n/a",
                            "category": category,
                            "reason": "no numeric query parameter",
                            "secondary_evidence": secondary},
            )
            return 0

        true_url, false_url = probes
        # the contract's budget bounds every probe, enforced in the fixed
        # argv (curl --max-time) — see _curl
        budget = contract.max_probe_seconds
        # run all three curls through the sandbox + allowlist (fixed argv)
        true_out = self._curl(true_url, timeout_s=budget)
        false_out = self._curl(false_url, timeout_s=budget)
        if true_out is None or false_out is None:
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "category": category,
                "reason": "curl probes failed to run",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"status": VERIFICATION_NOT_RUN,
                            "verified": False, "method": "curl boolean",
                            "category": category,
                            "reason": "probe run failed"},
            )
            return 0

        # boolean verdict with a BASELINE: pages with rotating content
        # (timestamps, CSRF tokens, ads) differ between ANY two fetches —
        # raw true!=false would "verify" those. The vulnerable signature
        # is: the TRUE injection changes nothing vs baseline (1 AND 1=1
        # is a no-op) while the FALSE injection changes the page.
        # the baseline is the ORIGINAL url with its ORIGINAL query string:
        # stripping the query fetches a different page (missing-param
        # error / default view), and then true_out == base_out could never
        # hold — every genuine boolean-SQLi finding would "fail"
        # verification (v1.1.1 regression)
        base_out = self._curl(url, timeout_s=budget)
        baseline_used = base_out is not None
        counterevidence: list[str] = []
        baseline2_len: "int | None" = None
        if baseline_used:
            responses_differ = (
                true_out != false_out
                and true_out == base_out
                and false_out != base_out
            )
            # the baseline method ran its full course: agreement or a real
            # contradiction — both are conclusions an independent test made
            if responses_differ:
                # The agreement is not yet a conclusion: content that
                # ROTATES between requests can produce exactly this
                # signature (first baseline A, true A, false B). One more
                # baseline fetch tests the benign explanation — if the
                # baseline itself moves, the observed difference may be
                # rotation, not the injected boolean. This is
                # counterevidence GATHERING: the observation that
                # contradicts the claim is recorded on the attempt, the
                # claim is NOT promoted, and the question stays open.
                base2_out = self._curl(url, timeout_s=budget)
                baseline2_len = len(base2_out) if base2_out is not None else None
                if base2_out is not None and base2_out != base_out:
                    counterevidence.append(
                        "a second baseline fetch differed from the first — "
                        "content rotates between requests, so the observed "
                        "true/false difference may be rotation, not the "
                        "injected boolean")
            else:
                counterevidence.append(
                    "the true injection and the false injection matched the "
                    "baseline equally — the injected boolean was not "
                    "executed as SQL")
            status = (VERIFICATION_VERIFIED if responses_differ
                      and not counterevidence
                      else VERIFICATION_UNRESOLVED if responses_differ
                      else VERIFICATION_DISAGREED)
        else:
            # no baseline possible — fall back to plain difference, but
            # only when the difference is substantial (not nonce churn).
            # Non-substantial without a baseline is the classic "ran but
            # cannot establish either conclusion": noise could explain it.
            responses_differ = abs(len(true_out) - len(false_out)) > max(
                32, int(0.02 * max(len(true_out), len(false_out)))
            )
            status = (VERIFICATION_UNRESOLVED if responses_differ
                      else VERIFICATION_INCONCLUSIVE)
            if responses_differ:
                counterevidence.append(
                    "no baseline could be fetched — dynamic content cannot "
                    "be ruled out, so a response difference alone is not "
                    "evidence the injected boolean executed")

        attempt_node = self.graph.add_node(
            node_type="verify_attempt",
            label=finding_id,
            properties={
                "verified": responses_differ,
                # producer convenience (read-time derivation is
                # authoritative — views.verification_status re-derives
                # from the execution fields below):
                "status": status,
                "method": "curl boolean probe",
                "true_len": len(true_out),
                "false_len": len(false_out),
                "baseline_len": len(base_out) if baseline_used else None,
                # the confirmation fetch (second baseline) — when it
                # differed from the first, its length records the rotation
                "baseline2_len": baseline2_len,
                # Batch 5C: counterevidence the check itself observed —
                # recorded, never discarded; non-empty means the verdict
                # does NOT promote (the question stays open)
                "counterevidence": counterevidence,
                # Batch 5B: the registered contract this check ran under —
                # its identity, its budget, and what the method cannot
                # establish, recorded with the result it produced
                "category": category,
                "contract": {
                    "category": contract.category,
                    "method": contract.method,
                    "tool": contract.tool,
                    "stage": contract.stage,
                    "max_probe_seconds": contract.max_probe_seconds,
                },
                "confidence_limit": contract.confidence_limit,
            },
        )
        # Phase 1C lineage: finding --verified_by--> its independent check,
        # by node ids. A refused link is audited — the refusal reason is
        # the record, not a missing edge on the graph.
        finding_node = next(
            (n for n in self.graph.by_type("finding")
             if n["label"] == finding_id), None)
        if finding_node is not None:
            refused: list[str] = []
            lineage.link(
                self.graph, "verified_by", finding_node, attempt_node,
                provenance={"agent": "VERIFY", "source_type": "tool"},
                properties={"finding_id": finding_id},
                on_refuse=refused.append,
            )
            if refused:
                self.audit.write({
                    "event": "lineage_refused",
                    "relationship": "verified_by",
                    "finding_id": finding_id,
                    "reason": refused[0],
                })
        if responses_differ and not counterevidence:
            # the finding node gains independent confirmation — ONLY when
            # the check observed no counterevidence: a verdict with a
            # standing benign explanation does not promote the finding
            for n in self.graph.by_type("finding"):
                if n["label"] == finding_id:
                    n["properties"]["verified"] = True
            self.audit.write({
                "event": "finding_verified",
                "finding_id": finding_id,
                "true_len": len(true_out),
                "false_len": len(false_out),
            })
            return 1

        self.audit.write({
            "event": "finding_verification_failed",
            "finding_id": finding_id,
            "true_len": len(true_out),
            "false_len": len(false_out),
        })
        return 0

    def _secondary_probes(self, url: str) -> dict:
        """Reachability evidence with tools OTHER than curl: httpie fetch,
        raw TCP connect (nc), TLS handshake (openssl, https only), and a
        DNS resolution (dig). Each probe is allowlist-validated and
        audited like every other spawn.

        These prove the ASSET is live — never that the vulnerability is
        real. They attach as supporting evidence only; "verified" stays
        the boolean probe's call.
        """
        parts = urlsplit(url)
        host = parts.hostname or self.target
        port = parts.port or (443 if parts.scheme == "https" else 80)

        probes: list[tuple[str, list[str]]] = [
            ("http", ["http", "--ignore-stdin", "--check-status", url]),
            ("nc", ["nc", "-z", "-w", "30", host, str(port)]),
            ("dig", ["dig", host, "+short"]),
        ]
        if parts.scheme == "https":
            probes.append(
                ("openssl", ["openssl", "s_client", "-connect",
                             f"{host}:{port}", "-brief"]))

        evidence: dict[str, dict] = {}
        for tool, argv in probes:
            result = self._spawn_tool(tool, argv)
            if result is None:
                evidence[tool] = {"ran": False}
                continue
            evidence[tool] = {
                "ran": True,
                "ok": result.ok,
                "exit_code": result.exit_code,
            }
        return evidence

    def _curl(self, url: str, timeout_s: "int | None" = None) -> str | None:
        """Run one curl via the sandbox. None = the run itself failed.

        ``timeout_s`` is the contract's per-probe budget, enforced in the
        fixed argv (curl ``--max-time``) — the tool self-bounds at the
        contract's number."""
        seconds = str(timeout_s) if timeout_s else "30"
        result = self._spawn_tool(
            "curl", ["curl", "-sS", "--max-time", seconds, url],
            timeout_s=timeout_s)
        if result is not None and result.exit_code == 56 and url.startswith("http://"):
            # https-only target and EXPLOIT never discovered it (no curl
            # hypothesis ran) — retry over https
            result = self._spawn_tool(
                "curl",
                ["curl", "-sS", "--max-time", seconds,
                 "https://" + url[len("http://"):]],
                timeout_s=timeout_s)
        if result is None or not result.ok:
            return None
        return result.stdout

    def _spawn_tool(self, tool: str, argv: list[str],
                    timeout_s: "int | None" = None):
        """One allowlisted sandbox spawn; returns SpawnResult or None.

        ``timeout_s`` is accepted so callers can pass a contract budget
        through, but the budget is enforced in the fixed argv itself
        (curl's ``--max-time``) — the same fixed-template enforcement
        EXPLOIT uses — so the spawn call shape is unchanged for every
        sandbox."""
        try:
            self.allowlist.validate(argv[0], argv)
            self.allowlist.check_blocklist(argv)
        except AllowlistViolation as e:  # pragma: no cover — fixed argv
            self.audit.write({
                "event": "verify_rejected_by_allowlist",
                "reason": str(e)[:200],
            })
            return None

        self.audit.write({
            "event": "tool_spawn",
            "state": "VERIFY",
            "tool": tool,
            "argv": argv,
        })
        result = self.sandbox.spawn(argv)
        self.audit.write({
            "event": "tool_result",
            "state": "VERIFY",
            "tool": tool,
            "ok": result.ok,
            "exit_code": result.exit_code,
            "output_chars": len(result.stdout),
        })
        return result
