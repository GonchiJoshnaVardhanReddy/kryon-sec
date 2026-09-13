"""VERIFY subagent (spec v2.1.1 §4.2, Zone B).

Independently re-checks every CONFIRMED finding using a different tool
than the one that found it (curl instead of sqlmap). For SQL-injection
findings this is the classic boolean check: fetch the URL with
`param=1 AND 1=1` and with `param=1 AND 1=2`; if the server treats the
injected boolean as SQL, the two responses differ.

A finding is marked "verified" only when this independent method agrees.
If it does not, the finding keeps its "confirmed" status but is marked
verification_failed — honest evidence either way, audited.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ..config import KryonsecConfig
from .allowlist import AllowlistViolation, ToolAllowlist
from .audit import AuditLog
from .exploit import compose_url
from .orchestrator import SubagentResult
from .recon_passive import EngagementGraph
from .sandbox import KaliSandbox

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
        self.audit.write({
            "event": "verify_plan",
            "findings_to_verify": len(findings),
            "method": "independent curl boolean probe (AND 1=1 vs AND 1=2)",
        })

        verified = 0
        for f in findings:
            verified += self._verify_one(f["label"])

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

    def _verify_one(self, finding_id: str) -> int:
        """Independently check one finding. Returns 1 if verified."""
        # the finding's hypothesis supplies the URL
        hyp = next(
            (n for n in self.graph.by_type("hypothesis")
             if n["label"] == finding_id), None,
        )
        if hyp is None:  # pragma: no cover — findings always have one
            return 0
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
                properties={"verified": False, "method": "n/a",
                            "reason": "asset outside engagement scope"},
            )
            return 0

        probes = _boolean_probe_urls(url)
        if probes is None:
            # No numeric query parameter to boolean-probe. Gather what
            # SECONDARY evidence exists (asset reachable / TLS up) with
            # tools other than curl — honest reachability evidence, but
            # it never marks a finding "verified" by itself.
            secondary = self._secondary_probes(url)
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "reason": "no numeric query parameter to probe",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"verified": False, "method": "n/a",
                            "reason": "no numeric query parameter",
                            "secondary_evidence": secondary},
            )
            return 0

        true_url, false_url = probes
        # run all three curls through the sandbox + allowlist (fixed argv)
        true_out = self._curl(true_url)
        false_out = self._curl(false_url)
        if true_out is None or false_out is None:
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "reason": "curl probes failed to run",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"verified": False, "method": "curl boolean",
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
        base_out = self._curl(url)
        if base_out is not None:
            responses_differ = (
                true_out != false_out
                and true_out == base_out
                and false_out != base_out
            )
        else:
            # no baseline possible — fall back to plain difference, but
            # only when the difference is substantial (not nonce churn)
            responses_differ = abs(len(true_out) - len(false_out)) > max(
                32, int(0.02 * max(len(true_out), len(false_out)))
            )

        self.graph.add_node(
            node_type="verify_attempt",
            label=finding_id,
            properties={
                "verified": responses_differ,
                "method": "curl boolean probe",
                "true_len": len(true_out),
                "false_len": len(false_out),
                "baseline_len": len(base_out) if base_out is not None else None,
            },
        )
        if responses_differ:
            # the finding node gains independent confirmation
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

    def _curl(self, url: str) -> str | None:
        """Run one curl via the sandbox. None = the run itself failed."""
        result = self._spawn_tool("curl", ["curl", "-sS", "--max-time", "30", url])
        if result is not None and result.exit_code == 56 and url.startswith("http://"):
            # https-only target and EXPLOIT never discovered it (no curl
            # hypothesis ran) — retry over https
            result = self._spawn_tool(
                "curl",
                ["curl", "-sS", "--max-time", "30",
                 "https://" + url[len("http://"):]],
            )
        if result is None or not result.ok:
            return None
        return result.stdout

    def _spawn_tool(self, tool: str, argv: list[str]):
        """One allowlisted sandbox spawn; returns SpawnResult or None."""
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
