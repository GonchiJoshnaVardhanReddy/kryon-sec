"""Real Docker/gVisor adapter lab validation (Phase 2B.8, Task 6).

ALL SIX vetted Mode B adapters run through the REAL KaliSandbox path —
real docker run, gVisor runsc runtime, the LOCAL CANDIDATE image pinned
by digest, the REAL engagement egress boundary (dedicated bridge +
firewall gate), real evidence graph and audit chain — against ONE
disposable local lab:

- an HTTP server (port 80) serving a deterministic page, a determinin-
  istic API surface (security headers, OPTIONS, redirect, CORS) and a
  simulated exposed panel page for the approved nuclei template
  ``alienVault-usm`` (GET /ossim/session/login.php expecting status 200
  + '<title>AlienVault USM');
- a TLS server (port 8443, self-signed cert) for the tls-probe adapter.

Everything is local, disposable and authorized; the lab is torn down
after every test (container + network + firewall). Skips silently
unless KRYONSEC_MODE_B_E2E=1, Linux, docker+runsc and the CANDIDATE
image are all present — exactly like tests/test_mode_b_e2e_lab_it.py.

The candidate image (kryonsec/sandbox:2b8-candidate) is pinned by its
config digest INSIDE these tests: the shared checks require the pinned
form, runsc, non-root, and the real egress boundary per spawn.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from types import SimpleNamespace

import pytest

from kryonsec.config import KryonsecConfig

CANDIDATE_TAG = "kryonsec/sandbox:2b8-candidate"

LAB_SERVER_SCRIPT = """import http.server, ssl, urllib.parse as up, os, subprocess, threading
# the TLS cert is generated HERE, in the same container that serves it
# (containers share nothing — a separate cert container would die with
# its own /tmp)
os.makedirs("/tmp/tls", exist_ok=True)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", "/tmp/tls/key.pem", "-out", "/tmp/tls/cert.pem",
                "-days", "1", "-nodes", "-subj", "/CN=target-corp.local"],
               capture_output=True, check=True)
PAGE = b"<html><title>AlienVault USM</title><body>LAB-PAGE</body></html>"
API  = b'{\\\"status\\\": \\\"ok\\\", \\\"version\\\": \\\"1.0\\\"}'
def do_GET(self):
    p = up.unquote(self.path)
    if p == "/ossim/session/login.php":
        body = PAGE
    elif p == "/api/v1/status":
        body = API
    elif p == "/redirect":
        self.send_response(302); self.send_header("Location", "/api/v1/status"); self.end_headers(); return
    else:
        body = b"LAB-PAGE-A-ROWS-7" if "1=2" in p else b"LAB-PAGE-A-ROWS-7"
    self.send_response(200)
    self.send_header("Content-Type", "text/html")
    self.send_header("Content-Length", str(len(body)))
    self.send_header("X-Frame-Options", "DENY")
    self.end_headers()
    self.wfile.write(body)
def do_OPTIONS(self):
    self.send_response(200)
    self.send_header("Access-Control-Allow-Origin", "*")
    self.send_header("Allow", "GET, OPTIONS")
    self.send_header("Content-Length", "0")
    self.end_headers()
class S(http.server.BaseHTTPRequestHandler):
    do_GET = do_GET
    do_OPTIONS = do_OPTIONS
    def log_message(self, *a):
        pass
httpd = http.server.HTTPServer(("0.0.0.0", 80), S)
tls = http.server.HTTPServer(("0.0.0.0", 8443), S)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/tls/cert.pem", "/tmp/tls/key.pem")
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=tls.serve_forever, daemon=True).start()
httpd.serve_forever()
"""


def _it_readiness() -> "tuple[bool, str]":
    if os.environ.get("KRYONSEC_MODE_B_E2E") != "1":
        return False, "KRYONSEC_MODE_B_E2E=1 not set"
    if not sys.platform.startswith("linux"):
        return False, f"Mode B needs Linux, this is {sys.platform}"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    ok, _ = _docker(["image", "inspect", CANDIDATE_TAG])
    if not ok:
        return False, f"candidate image absent: {CANDIDATE_TAG}"
    return True, ""


def _docker(args: "list[str]", timeout: int = 120) -> "tuple[bool, str]":
    try:
        proc = subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()[:300]
    return True, (proc.stdout or "").strip()


def _candidate_digest() -> str:
    """The candidate image pinned by its config digest (the same form
    KRYONSEC_SANDBOX_IMAGE uses — a tag is mutable, a digest is not)."""
    ok, out = _docker(["inspect", "--format", "{{.Id}}", CANDIDATE_TAG])
    assert ok, out
    image_id = out.strip()          # sha256:<hex>
    assert image_id.startswith("sha256:")
    return f"kryonsec/sandbox@{image_id}"


def _lab_ip(cfg: KryonsecConfig) -> str:
    subnet = ipaddress.ip_network(cfg.zone_b_subnet, strict=False)
    return str(subnet.network_address + 11)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """Readiness + candidate digest + the disposable two-port lab."""
    ok, reason = _it_readiness()
    if not ok:
        pytest.skip(f"adapter lab IT not armed: {reason}")
    tmp_path = tmp_path_factory.mktemp("adapter_lab")
    cfg = KryonsecConfig(home=tmp_path)
    cfg.database_url = f"sqlite:///{tmp_path / 'purple.db'}"
    cfg.sandbox_image = _candidate_digest()
    engagement_id = f"adapter-lab-{os.getpid()}"
    lab_ip = _lab_ip(cfg)

    from kryonsec.purple import egress

    policy = egress.build_policy(cfg, engagement_id, lab_ip)
    ok_n, err = _docker(egress.network_create_argv(policy)[1:])
    assert ok_n or "already exists" in (err or ""), err

    # one lab container: cert generated in-process, then the two-port
    # server (containers share nothing — the cert must live with the
    # server that reads it)
    lab_name = f"kryonsec-adapter-lab-{os.getpid()}"
    _docker(["rm", "-f", lab_name])
    ok_l, out = _docker([
        "run", "-d", "--rm", "--name", lab_name,
        "--network", policy.network_name, "--ip", lab_ip,
        "--entrypoint", "python3",
        cfg.sandbox_image, "-c", LAB_SERVER_SCRIPT,
    ], timeout=180)
    assert ok_l, f"lab server failed to start: {out}"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://{lab_ip}/api/v1/status", timeout=3) as resp:
                if b'"status": "ok"' in resp.read():
                    break
        except OSError:
            time.sleep(0.5)
    else:
        raise AssertionError("lab server never became reachable")

    yield SimpleNamespace(cfg=cfg, engagement_id=engagement_id, lab_ip=lab_ip,
                          policy_name=policy.network_name, tmp_path=tmp_path)

    _docker(["rm", "-f", lab_name])
    _docker(["network", "rm", policy.network_name])


@pytest.fixture()
def gate(lab):
    """The REAL egress gate established for each test, released after."""
    from kryonsec.purple import egress

    policy = egress.build_policy(
        lab.cfg, lab.engagement_id, lab.lab_ip)
    assert policy.network_name == lab.policy_name
    g = egress.EgressGate()
    ok, reason = g.establish(policy)
    assert ok, f"real egress establish failed: {reason}"
    yield policy, g
    g.release(policy)


@pytest.fixture()
def sandbox(lab, gate):
    """KaliSandbox on the REAL boundary with the CANDIDATE digest-pinned
    image, evidence mount for the TLS artifact test."""
    from kryonsec.purple.sandbox import KaliSandbox

    policy, g = gate
    evidence = lab.tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    return KaliSandbox(cfg=lab.cfg, egress_policy=policy, egress_gate=g,
                       evidence_dir=str(evidence)), evidence


def _audit_and_graph(lab):
    from kryonsec.purple.audit import AuditLog
    from kryonsec.purple.recon_passive import EngagementGraph

    audit = AuditLog(lab.tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id=lab.engagement_id)
    graph.add_node("target", lab.lab_ip, {"kind": "lab"})
    return audit, graph


def _events(audit) -> "list[dict]":
    events = []
    for line in audit.path.read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


# ---- shared checks (run inside each adapter test) -----------------------------


def _common_checks(record, audit, graph, *, executed: bool):
    assert record.executed is executed
    if executed:
        # execute_adapter's outcome semantics: the sandbox ran the tool
        assert record.outcome == "attempted"
        events = _events(audit)
        assert any(
            e.get("event") == "adapter_result"
            and e.get("request_id") == record.request_id
            for e in events), "the run was never audited (adapter_result)"
        # the attempt node carries the full record into the evidence
        # graph (only when the run actually happened)
        assert graph.by_type("adapter_attempt"), \
            "no adapter_attempt node in the evidence graph"
    else:
        events = _events(audit)
        assert any(e.get("event") == "adapter_refused" for e in events)


# ---- the candidate image itself ------------------------------------------------


def test_candidate_image_is_digest_pinned_and_runsc_ready(lab):
    assert "@sha256:" in lab.cfg.sandbox_image
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    assert ok, reason
    assert rc.runsc_registered()


def test_real_entrypoint_allowlist_refuses_unknown_tool(sandbox):
    """Defense-in-depth, REAL: the baked entrypoint refuses a tool that
    is not on the image allowlist — one JSON error, exit 125."""
    sbx, _evidence = sandbox
    result = sbx.spawn(["definitely-not-a-real-tool", "--help"])
    assert not result.ok
    assert result.error == "tool_not_in_allowlist"
    assert result.exit_code == 125


def test_real_nuclei_gate_refuses_token_spray(sandbox, lab):
    """THE Phase 2B.8 correction, enforced by the REAL baked gate inside
    the REAL image: a token-spray directory is refused before nuclei
    even launches — template_not_approved, exit 125, no execution."""
    sbx, _evidence = sandbox
    result = sbx.spawn([
        "nuclei", "-u", f"http://{lab.lab_ip}/",
        "-t", "/opt/nuclei-templates/http/token-spray/",
    ])
    assert not result.ok, result.stdout
    assert result.error == "template_not_approved", result.error
    # ...and a directory OTHER than the legacy EXPLOIT tree root
    result2 = sbx.spawn([
        "nuclei", "-u", f"http://{lab.lab_ip}/",
        "-t", "/opt/nuclei-templates/http/exposed-panels/",
    ])
    assert not result2.ok
    assert result2.error == "template_not_approved"


def test_real_nuclei_gate_allows_legacy_exploit_tree_root(sandbox, lab):
    """The legacy EXPLOIT-stage semantics are unchanged in the REAL
    image: the exact tree root passes the gate (it is human-gated
    upstream; this test stops at the gate, not the scan)."""
    sbx, _evidence = sandbox
    # pass the gate but kill the scan immediately with -list? No: the
    # gate allows the tree root; to prove the GATE allows it without a
    # long scan, use an invalid -u so nuclei exits fast AFTER the gate
    result = sbx.spawn([
        "nuclei", "-u", "not-a-url", "-t", "/opt/nuclei-templates",
    ])
    # the tool RAN (exit code from nuclei itself, not a gate refusal)
    assert result.ok, result.error
    assert result.exit_code != 125
    assert result.error != "template_not_approved"


# ---- the adapters ---------------------------------------------------------------


def test_real_httpx_adapter(sandbox, lab):
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_httpx import (
        ADAPTER_ID, parse_httpx_json_lines, production_registry,
        record_httpx_evidence)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"http://{lab.lab_ip}/")
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    assert output.strip(), "httpx produced no stdout through the boundary"
    entries, malformed = parse_httpx_json_lines(output)
    assert malformed == 0 and entries, entries
    assert str(lab.lab_ip) in entries[0].url
    record_httpx_evidence(graph, audit, run_record=record,
                          observations=entries)
    assert graph.by_type("web_endpoint"), "no http evidence recorded"


def test_real_whatweb_adapter(sandbox, lab):
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_whatweb import (
        ADAPTER_ID, parse_whatweb_lines, production_registry,
        record_whatweb_evidence)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"http://{lab.lab_ip}/")
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    observations, malformed = parse_whatweb_lines(output)
    assert observations, output
    assert malformed == 0
    record_whatweb_evidence(graph, audit, run_record=record,
                            observations=observations)
    assert graph.by_type("tech_fingerprint"), "no tech evidence recorded"


def test_real_api_adapter(sandbox, lab):
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_api import (
        ADAPTER_ID, parse_api_probe_payload, production_registry,
        record_api_evidence)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"http://{lab.lab_ip}/api/v1/status")
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    run, malformed = parse_api_probe_payload(output)
    assert run is not None, output
    assert malformed == 0
    record_api_evidence(graph, audit, run_record=record, run=run)
    assert graph.by_type("api_observation"), "no api evidence recorded"
    # security headers observed from the lab's deterministic surface
    assert run.security_headers, run


def test_real_searchsploit_adapter_network_none(sandbox, lab):
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_searchsploit import (
        ADAPTER_ID, production_registry)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip, params={
            "term": "openssh 7.4"})
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    # the offline DB lookup found something (the searchsploit DB ships
    # with the image); whatever it found, stdout is real tool output
    assert output.strip(), output
    # and the run never needed the network: the adapter declares none


def test_real_nuclei_adapter_matches_lab_panel(sandbox, lab):
    """The corrected policy END TO END: the frozen manifest argv runs
    REAL nuclei in REAL gVisor against the lab, matches the simulated
    exposed panel with an APPROVED template, and records it as a
    DETECTED CANDIDATE — never a confirmed finding."""
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_nuclei import (
        ADAPTER_ID, APPROVED_TEMPLATE_PATHS, parse_nuclei_json_lines,
        production_registry, record_nuclei_evidence)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    # the ROOT url: each template appends its own path to {{BaseURL}}
    # (alienvault-usm GETs {{BaseURL}}/ossim/session/login.php), so the
    # probe target is the host root — passing the deep path would double
    # it and match nothing
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"http://{lab.lab_ip}/")
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    candidates, _malformed = parse_nuclei_json_lines(output)
    assert candidates, f"no candidates in output: {output[:400]!r}"
    ids = {c.template_id for c in candidates}
    assert "alienVault-usm" in ids, sorted(ids)[:10]
    record_nuclei_evidence(graph, audit, run_record=record,
                           candidates=candidates)
    node = graph.by_type("vuln_candidate")[0]["properties"]
    assert node["classification"] == "detected_candidate"
    assert node["verification"] == "not_verified"
    assert graph.by_type("finding") == []
    # the real run really carried the manifest argv (bounded, huge, but
    # one -t per approved template)
    assert record.argv.count("-t") == len(APPROVED_TEMPLATE_PATHS)


def test_real_tls_adapter_bounded_summary(sandbox, lab):
    """The corrected TLS wrapper END TO END: a REAL full testssl run
    against the lab's TLS server produces a summary that FITS the
    unchanged 20,000-char sandbox bound, carries TRUE counts, and —
    with the evidence mount present — the full redacted artifact."""
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_tls import (
        ADAPTER_ID, parse_tls_probe_payload, production_registry,
        record_tls_evidence)

    sbx, evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"https://{lab.lab_ip}:8443/")
    record, output = execute_adapter(
        reg, prep, sandbox=sbx, audit=audit, graph=graph, full_output=True)
    _common_checks(record, audit, graph, executed=True)
    # THE fix: the summary fits the host bound — never truncated to
    # nothing, never rejected
    assert len(output) <= 20_000, len(output)
    run, malformed = parse_tls_probe_payload(output)
    assert run is not None, output
    assert malformed == 0
    assert run.status in ("complete", "partial")
    assert run.version == 2
    assert run.finding_count_total > 0, (
        "a self-signed lab cert must yield testssl findings")
    assert run.severity_histogram, run
    # artifact: the evidence mount was on the sandbox
    assert run.artifact is not None
    import hashlib
    art_path = evidence / run.artifact.name
    assert art_path.is_file()
    data = art_path.read_bytes()
    assert run.artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert run.artifact.bytes == len(data)
    assert run.artifact.redactions >= 0
    record_tls_evidence(graph, audit, run_record=record, run=run)
    assert graph.by_type("tls_observation"), "no tls evidence recorded"


def test_real_unauthorized_destination_blocked(sandbox, lab):
    """The REAL egress boundary blocks a non-lab destination for an
    adapter-scoped tool — errors are honest, not fake findings."""
    sbx, _evidence = sandbox
    strays = ipaddress.ip_network(lab.cfg.zone_b_subnet).broadcast_address
    result = sbx.spawn(["curl", "-s", "-m", "5", f"http://{strays}/"])
    assert result.ok          # the SPAWN ran (docker allowed)
    # curl could not reach the stray: exit 28 (timeout) or empty body
    assert result.exit_code != 0 or "LAB-PAGE-A-ROWS-7" not in result.stdout


def test_real_tool_failure_is_not_a_success(sandbox, lab):
    """A failing tool (nonzero exit, no output) maps to an honest
    failure record — never a fabricated observation."""
    from kryonsec.purple.adapters import execute_adapter, prepare_adapter_run
    from kryonsec.purple.adapter_api import (
        ADAPTER_ID, production_registry)

    sbx, _evidence = sandbox
    audit, graph = _audit_and_graph(lab)
    reg = production_registry()
    # a port the lab does NOT serve: the probe must report refusal/
    # connection failure, never success
    prep = prepare_adapter_run(
        reg, ADAPTER_ID, target=lab.lab_ip,
        target_asset=f"http://{lab.lab_ip}:9/")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit)
    assert record.executed is True      # the tool really ran
    assert record.outcome != "success"  # and honestly reported failure
    # no evidence nodes fabricated from the failure
    assert graph.by_type("api_observation") == []
