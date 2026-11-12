"""Phase 2B.6 — REAL gVisor planner lab IT (opt-in).

Genuinely runs the ReconActiveSubagent WITH the tool planner inside REAL
runsc containers (Docker + gVisor) against disposable, self-contained
local labs that this IT starts itself on the engagement's own egress
bridge. This file exists to prove the planner's decisions on REAL
executions:

  1. HTTPS web lab  -> appropriate web + TLS checks really selected AND
     really executed (testssl inside the sandbox).
  2. Plain HTTP lab -> the TLS check is excluded, nothing TLS-shaped
     spawns.
  3. Authorized API lab -> the read-only API probe is selected and
     completes.
  4. Already-covered check -> the second planning decision marks the
     complete prior run ``covered`` and the tool does NOT spawn again.
  5. Missing/disallowed capability -> safe rejection, honest legacy
     fallback, audited.
  6. Out-of-scope destination -> refused before spawn AND blocked by the
     real egress boundary.
  7. Budget exhaustion -> bounded, audited deferral; zero adapter
     spawns.

Opt-in on purpose: run with ``KRYONSEC_PLANNER_IT=1`` on a Linux host
with Docker + runsc + the DIGEST-PINNED sandbox image, and privileges to
program iptables (the REAL egress boundary is armed — this file is
exempted from the conftest fake for exactly that reason). Skipped
silently otherwise.

IMPORTANT image note: the digest-pinned image used here is LOCALLY
BUILT for development (it carries the 2B.4/2B.5 probe scripts). It is
NOT the published GHCR production image; the readiness check prints
which digest is actually under test.

Safety/authorization: the lab targets are throwaway containers this IT
starts itself, on the engagement's own egress bridge, torn down again
afterwards. The egress allowlist contains exactly the lab IP plus the
pinned DNS resolvers, ending in an absolute DROP: nothing beyond the
lab is reachable, and nothing public is ever touched.
"""

from __future__ import annotations

import contextlib
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
from kryonsec.purple.adapters import AdapterRegistry, AdapterScopeRefused, \
    prepare_adapter_run
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import ReconActiveSubagent
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.tool_planner import PlannerBudget, \
    ToolCapabilityCatalog, ToolPlanner, ToolSuggestion

GATE_ENV = "KRYONSEC_PLANNER_IT"

LAB_WEB_SCRIPT = """
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Planner Lab</title></head><body>lab</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
"""

LAB_API_SCRIPT = """
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/swagger.json":
            spec = {"openapi": "3.0.0", "info": {"title": "Lab API",
                    "version": "1.0"},
                    "paths": {"/users": {"get": {}},
                              "/admin/config": {"get": {}}}}
            self._send(200, "application/json", json.dumps(spec).encode())
        elif self.path == "/cors":
            origin = self.headers.get("Origin") or ""
            extra = {}
            if origin:
                extra = {"Access-Control-Allow-Origin": origin,
                         "Access-Control-Allow-Credentials": "true"}
            self._send(200, "application/json", b'{"ok": true}', extra)
        else:
            self._send(200, "application/json", b'{"api": "lab"}',
                       {"X-Content-Type-Options": "nosniff"})
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
"""

#: TLS lab: one container serving BOTH a plain http(80) page and an
#: https(8443) endpoint, so discovery finds two web bases of different
#: schemes in one engagement. The s_server offers ONE cipher on
#: purpose: testssl reports one finding per offered cipher, and a
#: full ~120-cipher offer exceeds the executor's 20k output bound —
#: honestly truncated mid-JSON, but then the run cannot demonstrate a
#: COMPLETE tls observation.
LAB_TLS_SCRIPT = """
import subprocess, threading, time, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Planner TLS Lab</title></head></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", "/tmp/k.pem", "-out", "/tmp/c.pem",
                "-days", "1", "-nodes", "-subj", "/CN=planner-lab"],
               check=True, capture_output=True)
t = threading.Thread(
    target=subprocess.run,
    args=(["openssl", "s_server", "-port", "8443", "-cert", "/tmp/c.pem",
           "-key", "/tmp/k.pem", "-www", "-cipher", "AES128-SHA"],),
    daemon=True)
t.start()
http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
"""


def _it_readiness() -> "tuple[bool, str, str]":
    """(ok, reason, image-under-test) — the pinned LOCAL image must be
    digest-pinned; the digest is reported so the report can say it is
    the locally-built image, not the published one."""
    if os.environ.get(GATE_ENV) != "1":
        return False, f"{GATE_ENV}=1 not set", ""
    if not sys.platform.startswith("linux"):
        return False, f"Mode B needs Linux, this is {sys.platform}", ""
    if shutil.which("docker") is None:
        return False, "docker CLI missing", ""
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}", ""
    if not rc.runsc_registered():
        return False, "runsc runtime not registered", ""
    image = KryonsecConfig().sandbox_image
    if "@sha256:" not in image:
        return False, ("sandbox image is not digest-pinned in this "
                       "environment (rule 7) — set "
                       "KRYONSEC_SANDBOX_IMAGE"), image
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}", image
    return True, "", image


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


def _wait_http(url: str, deadline_s: int = 60) -> "tuple[bool, str]":
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return True, "ok"
        except OSError:
            time.sleep(0.5)
    return False, f"lab never became reachable: {url}"


def _reduced_registry(without: str) -> AdapterRegistry:
    reg = AdapterRegistry()
    for a in recon_registry().list_adapters():
        if a.adapter_id != without:
            reg.register(a)
    return reg


def recon_registry():
    from kryonsec.purple.adapter_whatweb import recon_active_registry
    return recon_active_registry()


@contextlib.contextmanager
def _scenario(tmp_path, script: str, tag: str, *, planner=None,
              registry=None):
    """One lab + one engagement, fully torn down afterwards.

    The lab container joins the engagement's own egress bridge (the
    network is created through the engine's OWN argv builder so the
    gate's DOCKER-USER jumps match it), the REAL gate establishes the
    firewall, and every tool the subagent dispatches runs in a REAL
    runsc container against the lab IP only.
    """
    from kryonsec.purple import egress
    from kryonsec.purple.sandbox import KaliSandbox

    cfg = KryonsecConfig(home=tmp_path)
    engagement_id = f"planner-it-{os.getpid()}-{tag}"
    subnet = ipaddress.ip_network(cfg.zone_b_subnet, strict=False)
    lab_ip = str(subnet.network_address + 10)
    policy = egress.build_policy(cfg, engagement_id, lab_ip)
    ok_n, err = _docker(egress.network_create_argv(policy)[1:])
    assert ok_n or "already exists" in (err or ""), err
    c_name = f"kryonsec-planner-lab-{tag}-{os.getpid()}"
    _docker(["rm", "-f", c_name])
    ok_c, why = _docker([
        "run", "-d", "--rm", "--name", c_name,
        "--network", policy.network_name, "--ip", lab_ip,
        "--entrypoint", "python3", cfg.sandbox_image, "-c", script,
    ])
    assert ok_c, f"lab container failed: {why}"
    try:
        ok_w, reason = _wait_http(f"http://{lab_ip}/")
        assert ok_w, reason
        gate = egress.EgressGate()
        established, est_reason = gate.establish(policy)
        assert established, f"real egress establish: {est_reason}"
        egress.register_active(policy, gate)   # release_active works
        sbx = _RecordingSandbox(
            KaliSandbox(cfg=cfg, egress_policy=policy, egress_gate=gate))
        audit = AuditLog(tmp_path / f"{tag}-audit.jsonl")
        graph = EngagementGraph(engagement_id=engagement_id)
        graph.add_node("target", lab_ip, {})
        sub = ReconActiveSubagent(
            cfg, graph, audit, lab_ip, sbx,
            adapter_registry=(registry if registry is not None
                              else recon_registry()),
            planner=planner,
        )
        yield SimpleNamespace(cfg=cfg, engagement_id=engagement_id,
                              lab_ip=lab_ip, audit=audit, graph=graph,
                              sub=sub, sandbox=sbx, gate=gate,
                              policy=policy)
    finally:
        with contextlib.suppress(Exception):
            egress.release_active(engagement_id)
        _docker(["rm", "-f", c_name])
        time.sleep(2)   # --rm cleanup is async; the network rm races it
        _docker(["network", "rm", policy.network_name])
        _docker(["network", "prune", "-f"])


class _RecordingSandbox:
    """Duck-typed wrapper around the REAL KaliSandbox that records every
    spawn argv for the assertions. The REAL sandbox does the executing —
    this only observes."""

    def __init__(self, real):
        self._real = real
        self.spawned: "list[tuple[list[str], int | None]]" = []

    def spawn(self, tool_argv: "list[str]", timeout_s=None,
              network_mode=None):
        self.spawned.append((list(tool_argv), timeout_s))
        return self._real.spawn(tool_argv, timeout_s=timeout_s,
                                network_mode=network_mode)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _events(audit) -> "list[dict]":
    return [json.loads(line)
            for line in open(audit.path, encoding="utf-8") if line.strip()]


def _named(events, name):
    return [e for e in events if e.get("event") == name]


def _spawned_tools(sandbox) -> "list[str]":
    return [argv[0] for argv, _t in sandbox.spawned]


def _planner(registry=None, **kw):
    return ToolPlanner(
        ToolCapabilityCatalog(registry or recon_registry()), **kw)


@pytest.fixture(scope="module")
def it_ready():
    ok, reason, image = _it_readiness()
    if not ok:
        pytest.skip(f"planner lab IT not armed: {reason}")
    print(f"\n[planner-IT] sandbox image under test: {image}\n"
          "[planner-IT] NOTE: locally-built image, NOT the published "
          "production image")
    return image


# ---- 1. HTTPS web lab: web + TLS checks selected AND executed -----------


def test_https_lab_selects_and_executes_web_and_tls(tmp_path, it_ready):
    with _scenario(tmp_path, LAB_TLS_SCRIPT, "https", planner=_planner()) \
            as env:
        result = env.sub.run()
        assert result.status == "ok"
        events = _events(env.audit)
        decided = _named(events, "planning_decided")[0]
        counts = decided["counts"]
        # two web bases (http 80 + https 8443): 4 checks x 2 selected,
        # tls selected for the https base and REJECTED for the http base
        assert counts["selected"] == 9
        assert counts["rejected"] == 1
        tls_entries = [e for e in decided["entries"]
                       if "tls-probe" in e]
        assert any("rejected" in e for e in tls_entries)
        # REAL execution: the tls probe wrapper really ran in runsc
        tools = _spawned_tools(env.sandbox)
        assert "/opt/kryonsec/tls_probe.py" in tools
        assert tools.count("/opt/kryonsec/tls_probe.py") == 1  # https only
        assert "/opt/kryonsec/api_probe.py" in tools
        assert tools.count("httpx-toolkit") == 2
        # planned vs executed: the comparison is HONEST — in this lab the
        # nuclei check against the self-signed s_server endpoint exceeds
        # its 300s cap and is audited as a real adapter failure, so the
        # report shows exactly that (never a pretend success)
        done = _named(events, "recon_active_done")[0]
        assert done["planned_selected"] == 9
        assert done["planned_executed"] == 8
        assert len(done["planned_not_executed"]) == 1
        assert "nuclei-probe" in done["planned_not_executed"][0]
        failures = _named(events, "recon_active_adapter_failure")
        assert any(f["adapter"] == "nuclei-probe"
                   and "300s" in f["reason"] for f in failures)
        # the TLS observation landed in the REAL evidence graph
        tls_nodes = env.graph.by_type("tls_observation")
        assert tls_nodes, "real tls probe produced no tls_observation node"
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 2. plain HTTP lab: TLS excluded ------------------------------------


def test_http_lab_excludes_tls(tmp_path, it_ready):
    with _scenario(tmp_path, LAB_WEB_SCRIPT, "http", planner=_planner()) \
            as env:
        result = env.sub.run()
        assert result.status == "ok"
        events = _events(env.audit)
        decided = _named(events, "planning_decided")[0]
        assert decided["counts"]["rejected"] == 1  # tls-probe on http
        tools = _spawned_tools(env.sandbox)
        assert "/opt/kryonsec/tls_probe.py" not in tools
        assert "sslscan" not in tools
        assert "testssl.sh" not in tools
        # the eligible checks really ran
        assert tools.count("httpx-toolkit") == 1
        done = _named(events, "recon_active_done")[0]
        assert done["planned_executed"] == done["planned_selected"] == 4
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 3. authorized API lab: api probe selected and complete --------------


def test_api_lab_selects_and_completes_api_probe(tmp_path, it_ready):
    with _scenario(tmp_path, LAB_API_SCRIPT, "api", planner=_planner()) \
            as env:
        result = env.sub.run()
        assert result.status == "ok"
        events = _events(env.audit)
        tools = _spawned_tools(env.sandbox)
        assert tools.count("/opt/kryonsec/api_probe.py") == 1
        # the REAL probe found the REAL swagger doc: the declared
        # operations became path nodes in the REAL evidence graph
        paths = [n["label"] for n in env.graph.by_type("path")]
        assert any(("/users" in p) or ("/admin" in p) for p in paths), \
            paths
        obs = env.graph.by_type("api_observation")
        assert obs and obs[0]["properties"]["status"] == "complete"
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 4. already-covered check: redundant execution avoided ---------------


def test_second_run_avoids_redundant_httpx(tmp_path, it_ready):
    """Same graph, two runs: run 1 executes httpx for real; run 2's
    planner marks it ``covered`` (complete, fresh prior run) and the
    sandbox never spawns it again."""
    reg = recon_registry()
    # two-adapter focus keeps the IT fast: httpx + api only
    small = AdapterRegistry()
    for a in reg.list_adapters():
        if a.adapter_id in ("httpx-probe", "api-probe"):
            small.register(a)
    with _scenario(tmp_path, LAB_WEB_SCRIPT, "covered", registry=small,
                   planner=_planner(small)) as env:
        r1 = env.sub.run()
        assert r1.status == "ok"
        first_tools = _spawned_tools(env.sandbox)
        assert first_tools.count("httpx-toolkit") == 1
        # run 2 on the SAME graph/audit — the planner must dedupe
        r2 = env.sub.run()
        assert r2.status == "ok"
        all_tools = _spawned_tools(env.sandbox)
        assert all_tools.count("httpx-toolkit") == 1, (
            "the covered check spawned AGAIN — dedupe failed on a real "
            "run")
        events = _events(env.audit)
        assert len(_named(events, "planning_decided")) == 2
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 5. missing capability: safe rejection, honest fallback ---------------


def test_missing_capability_rejected_legacy_fallback(tmp_path, it_ready):
    reg = _reduced_registry("api-probe")
    with _scenario(tmp_path, LAB_WEB_SCRIPT, "missing", registry=reg,
                   planner=_planner(reg)) as env:
        result = env.sub.run()
        assert result.status == "ok"
        events = _events(env.audit)
        decided = _named(events, "planning_decided")[0]
        assert all("api-probe" not in e for e in decided["entries"])
        tools = _spawned_tools(env.sandbox)
        # the missing adapter never spawns — and the pre-2B.6 legacy
        # fallback runs exactly as it would have without the planner
        assert "/opt/kryonsec/api_probe.py" not in tools
        assert "/opt/kryonsec/openapi_probe.py" in tools
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 6. out-of-scope destination: refused + boundary blocks ---------------


def test_out_of_scope_refused_and_blocked(tmp_path, it_ready):
    with _scenario(tmp_path, LAB_WEB_SCRIPT, "scope", planner=_planner(
            suggestions=(ToolSuggestion(
                adapter_id="httpx-probe",
                target_asset="https://203.0.113.9/",
                rationale="please also scan this"),))) as env:
        # 1. preparation refuses a non-lab URL in the REAL environment
        with pytest.raises(AdapterScopeRefused):
            prepare_adapter_run(
                recon_registry(), "httpx-probe", target=env.lab_ip,
                target_asset="https://203.0.113.9/")
        result = env.sub.run()
        assert result.status == "ok"
        # 2. the planner recorded the out-of-scope suggestion, never
        #    executed it
        decided = _named(_events(env.audit), "planning_decided")[0]
        assert any("not in the plan's evidence-backed base set" in r
                   for r in decided["suggestion_rejections"])
        tools = _spawned_tools(env.sandbox)
        assert not any("203.0.113.9" in " ".join(argv)
                       for argv, _t in env.sandbox.spawned)
        # 3. the REAL boundary blocks the destination outright
        probe = env.sandbox.spawn(["curl", "-s", "-m", "5",
                                   "https://203.0.113.9/"])
        assert not probe.ok or probe.exit_code != 0, (
            "the REAL egress boundary let an out-of-scope destination "
            "through")
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2


# ---- 7. budget exhaustion: bounded, audited deferral ----------------------


def test_budget_exhaustion_defers_everything(tmp_path, it_ready):
    with _scenario(tmp_path, LAB_WEB_SCRIPT, "budget",
                   planner=_planner(
                       budget=PlannerBudget(max_total_seconds=0))) as env:
        result = env.sub.run()
        assert result.status == "ok"
        events = _events(env.audit)
        applied = _named(events, "planner_plan_applied")[0]
        assert applied["selected"] == 0
        assert applied["counts"]["deferred"] == 4
        tools = _spawned_tools(env.sandbox)
        reg = recon_registry()
        for adapter in reg.list_adapters():
            assert adapter.executable not in tools, adapter.adapter_id
        done = _named(events, "recon_active_done")[0]
        assert done["planned_selected"] == 0
        assert done["planned_executed"] == 0
        assert done["planned_not_executed"] == []
        # the engagement is still honest: discovery + legacy tools ran
        assert "nmap" in tools and "katana" in tools
        ok2, reason2 = env.audit.verify()
        assert ok2, reason2
