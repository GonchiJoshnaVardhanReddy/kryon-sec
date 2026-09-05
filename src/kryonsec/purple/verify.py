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
        url = compose_url(self.target, asset, scheme=self._discovered_scheme())

        probes = _boolean_probe_urls(url)
        if probes is None:
            self.audit.write({
                "event": "verify_skipped",
                "finding_id": finding_id,
                "reason": "no numeric query parameter to probe",
            })
            self.graph.add_node(
                node_type="verify_attempt",
                label=finding_id,
                properties={"verified": False, "method": "n/a",
                            "reason": "no numeric query parameter"},
            )
            return 0

        true_url, false_url = probes
        # run both curls through the sandbox + allowlist (fixed argv)
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

        responses_differ = true_out != false_out
        self.graph.add_node(
            node_type="verify_attempt",
            label=finding_id,
            properties={
                "verified": responses_differ,
                "method": "curl boolean probe",
                "true_len": len(true_out),
                "false_len": len(false_out),
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

    def _curl(self, url: str) -> str | None:
        """Run one curl via the sandbox. None = the run itself failed."""
        result = self._spawn_curl(url)
        if result is not None and result.exit_code == 56 and url.startswith("http://"):
            # https-only target and EXPLOIT never discovered it (no curl
            # hypothesis ran) — retry over https
            result = self._spawn_curl("https://" + url[len("http://"):])
        if result is None or not result.ok:
            return None
        return result.stdout

    def _spawn_curl(self, url: str):
        """One allowlisted sandbox curl; returns SpawnResult or None."""
        argv = ["curl", "-sS", "--max-time", "30", url]
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
            "tool": "curl",
            "argv": argv,
        })
        result = self.sandbox.spawn(argv)
        self.audit.write({
            "event": "tool_result",
            "state": "VERIFY",
            "tool": "curl",
            "ok": result.ok,
            "exit_code": result.exit_code,
            "output_chars": len(result.stdout),
        })
        return result
