"""Tests for RECON_ACTIVE + VERIFY subagents (spec §4.2, Zone B)."""

import json

from kryonsec.config import KryonsecConfig
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_active import (
    ReconActiveSubagent,
    parse_nmap_services,
)
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import SpawnResult
from kryonsec.purple.verify import VerifySubagent, _boolean_probe_urls


# ---- nmap parsing --------------------------------------------------------

NMAP_SAMPLE = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for testasp.vulnweb.com (44.229.226.2)
Host is up (0.045s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 8.5
443/tcp open  https   Microsoft IIS httpd 8.5 (TLS)
Service detection performed. 1 service on 1 host.
"""


def test_parse_nmap_services_extracts_open_ports():
    services = parse_nmap_services(NMAP_SAMPLE)
    assert services == [
        {"port": 80, "proto": "tcp", "service": "http",
         "version": "Microsoft IIS httpd 8.5"},
        {"port": 443, "proto": "tcp", "service": "https",
         "version": "Microsoft IIS httpd 8.5 (TLS)"},
    ]


def test_parse_nmap_ignores_closed_ports():
    out = "80/tcp  open   http\n443/tcp closed https\n"
    services = parse_nmap_services(out)
    assert [s["port"] for s in services] == [80]


# ---- feroxbuster parsing -------------------------------------------------

def test_parse_feroxbuster_reads_real_output():
    """The pattern must match what feroxbuster actually prints.

    Real lines are "status [METHOD] Nl Nw Nc <full-url>". The old pattern
    wanted "<status> <digits> <digits> /path" and so matched nothing real —
    every directory-busting result was dropped without a word.
    """
    from kryonsec.purple.recon_active import parse_feroxbuster

    out = (
        "200      GET       15l       34w      345c http://t.com/admin\n"
        "301      GET        9l       28w      317c http://t.com/backup => http://t.com/backup/\n"
        "403      GET        9l       28w      317c http://t.com/.git/HEAD\n"
        # builds that omit the METHOD column still parse
        "200        10l        212w       38437c http://t.com/index.html\n"
    )
    assert parse_feroxbuster(out) == [
        {"path": "/admin", "status": 200},
        {"path": "/backup", "status": 301},
        {"path": "/.git/HEAD", "status": 403},
        {"path": "/index.html", "status": 200},
    ]


def test_parse_feroxbuster_keeps_query_string():
    from kryonsec.purple.recon_active import parse_feroxbuster

    out = "200      GET        1l        2w        3c http://t.com/s.php?id=1\n"
    assert parse_feroxbuster(out) == [{"path": "/s.php?id=1", "status": 200}]


def test_parse_feroxbuster_skips_404_and_junk():
    from kryonsec.purple.recon_active import parse_feroxbuster

    out = (
        "404      GET        3l        5w       62c http://t.com/nope\n"
        "500      GET        1l        1w       10c http://t.com/boom\n"
        "🦡  feroxbuster v2.10.4\n"          # the banner
        "Scanning: http://t.com/FUZZ\n"      # progress noise
        "\n"
    )
    assert parse_feroxbuster(out) == []


def test_parse_feroxbuster_is_bounded():
    from kryonsec.purple.recon_active import parse_feroxbuster

    out = "".join(
        f"200      GET        1l        1w        1c http://t.com/p{i}\n"
        for i in range(200)
    )
    assert len(parse_feroxbuster(out)) == 50


# ---- RECON_ACTIVE --------------------------------------------------------

class FakeSandbox:
    def __init__(self, result):
        self.result = result
        self.spawned = []

    def spawn(self, argv):
        self.spawned.append(argv)
        return self.result


def _events(audit):
    return [json.loads(l)["event"] for l in open(audit.path, encoding="utf-8")
            if l.strip()]


def test_recon_active_creates_service_nodes(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra")
    fake = FakeSandbox(SpawnResult(ok=True, exit_code=0, stdout=NMAP_SAMPLE))

    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"
    assert fake.spawned[0][0] == "nmap"
    assert "t.com" in fake.spawned[0]

    services = graph.by_type("service")
    assert len(services) == 2
    assert services[0]["label"] == "t.com:80/tcp"
    assert services[0]["properties"]["service"] == "http"
    assert services[0]["properties"]["version"] == "Microsoft IIS httpd 8.5"

    events = _events(audit)
    assert "recon_active_done" in events
    assert "tool_spawn" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_recon_active_failure_fails_state_not_engagement(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra2")
    fake = FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="",
                                   error="sandbox timeout"))

    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "failed"
    assert graph.by_type("service") == []
    assert "recon_active_failed" in _events(audit)


# ---- RECON_ACTIVE: multi-tool plan (tool expansion Phase 1) ---------------

class MultiToolSandbox:
    """Returns a realistic output per tool so every parser gets exercised."""

    OUTPUTS = {
        "nmap": NMAP_SAMPLE,
        "naabu": "t.com:80\nt.com:8080\n",
        "dnsx": "t.com. 300 IN A 1.2.3.4\n",
        "httpx": "http://t.com:80/ [200] [Home] [Nginx,PHP]\n",
        "whatweb": "http://t.com:80/ [200 OK] Nginx[1.18], PHP[7.4]\n",
        "katana": "http://t.com/admin/login\nhttp://t.com/api/v1\n",
        # real feroxbuster shapes: status, optional METHOD, Nl/Nw/Nc, full URL.
        # The fixture used to be "200  15l  345w  /admin" — a format the tool
        # never prints — which is exactly why the parser looked correct.
        "feroxbuster": "200      GET       15l       34w      345c http://t.com/admin\n"
                       "301      GET        9l       28w      317c http://t.com/backup => http://t.com/backup/\n"
                       "403      GET        9l       28w      317c http://t.com/.git/HEAD\n"
                       "200        10l        212w       38437c http://t.com/index.html\n"
                       "404      GET        3l        5w       62c http://t.com/nope\n",
        "sslscan": "TLSv1.0  enabled\n",
        "testssl.sh": "subject: t.com\n",
    }

    def __init__(self):
        self.tools = []

    def spawn(self, argv):
        self.tools.append(argv[0])
        return SpawnResult(ok=True, exit_code=0,
                           stdout=self.OUTPUTS.get(argv[0], ""))


def test_recon_active_multi_tool_plan(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra3")
    fake = MultiToolSandbox()

    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"

    # stage 1 always runs the discovery trio
    for tool in ("nmap", "naabu", "dnsx"):
        assert tool in fake.tools

    # 80+443 found by nmap, 8080 by naabu → web probes on all three
    for tool in ("httpx", "whatweb", "katana", "feroxbuster"):
        assert tool in fake.tools
    # 443 is a TLS port → TLS scanners run
    assert "sslscan" in fake.tools
    assert "testssl.sh" in fake.tools

    # every spawn was allowlist-valid (no rejection events)
    events = _events(audit)
    assert "recon_active_rejected_by_allowlist" not in events
    assert "recon_active_done" in events
    ok, reason = audit.verify()
    assert ok, reason


def test_recon_active_parses_into_graph_nodes(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra4")
    fake = MultiToolSandbox()

    ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()

    # nmap services
    services = graph.by_type("service")
    assert {"t.com:80/tcp", "t.com:443/tcp"} <= {s["label"] for s in services}
    # dnsx resolution
    dns = graph.by_type("dns_resolution")
    assert dns and dns[0]["properties"]["ips"] == ["1.2.3.4"]
    # httpx endpoint with title/tech
    endpoints = graph.by_type("web_endpoint")
    assert any(e["label"] == "http://t.com:80/"
               and e["properties"]["tech"] == "Nginx,PHP" for e in endpoints)
    # katana crawled URLs + feroxbuster paths both land as path nodes
    paths = graph.by_type("path")
    path_labels = {p["label"] for p in paths}
    assert "/admin/login" in path_labels
    assert "/backup" in path_labels
    # whatweb / TLS outputs stored as bounded observations
    assert graph.by_type("tech_fingerprint")
    assert graph.by_type("tls_observation")


def test_recon_active_no_web_ports_still_runs_default_probe(tmp_path):
    """Nothing web-ish discovered → the default port-80 probe still runs
    (many hosts simply don't advertise; the probe is cheap)."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra5")

    class WeirdPorts:
        def __init__(self):
            self.tools = []

        def spawn(self, argv):
            self.tools.append(argv[0])
            if argv[0] == "nmap":
                return SpawnResult(ok=True, exit_code=0,
                                   stdout="5432/tcp open postgresql\n")
            return SpawnResult(ok=True, exit_code=0, stdout="")

    fake = WeirdPorts()
    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"
    assert "httpx" in fake.tools  # default web probe ran anyway
    # 5432 is not a web port — no whatweb/katana/feroxbuster on it
    assert fake.tools.count("whatweb") == 1  # only the port-80 default


# ---- Phase 8: gowitness + openapi_probe in the web plan --------------------

def test_web_plan_includes_openapi_and_gowitness_per_web_port(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    graph = EngagementGraph(engagement_id="e-ra6")
    sub = ReconActiveSubagent(
        cfg, graph, AuditLog(tmp_path / "a.jsonl"), "t.com",
        FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="")))

    plan = sub._web_plan({80, 443, 5432})
    tools = [tool for tool, _ in plan]
    # every web port gets both new probes; 5432 (postgres) gets none
    assert tools.count("openapi_probe") == 2
    assert tools.count("gowitness") == 2

    from kryonsec.purple.allowlist import ToolAllowlist
    allow = ToolAllowlist()
    for tool, argv in plan:
        # argv from the actual plan is always allowlist-valid
        allow.validate(argv[0], argv)
        if tool == "gowitness":
            assert "--screenshot-path" in argv
            assert argv[argv.index("--screenshot-path") + 1] == "/evidence"


def test_web_plan_gowitness_arg_is_exactly_the_template(tmp_path):
    """The argv matches the gowitness allowlist template token-for-token
    (a drifting flag here would silently break every real engagement)."""
    cfg = KryonsecConfig(home=tmp_path)
    graph = EngagementGraph(engagement_id="e-ra7")
    sub = ReconActiveSubagent(
        cfg, graph, AuditLog(tmp_path / "a.jsonl"), "t.com",
        FakeSandbox(SpawnResult(ok=False, exit_code=-1, stdout="")))

    for tool, argv in sub._web_plan({80}):
        if tool == "gowitness":
            assert argv == ["gowitness", "scan", "website",
                            "--url", "http://t.com:80/",
                            "--screenshot-path", "/evidence",
                            "--no-console", "--disable-db"]


def test_recon_active_openapi_endpoints_become_path_nodes(tmp_path):
    import json as _json

    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra8")

    class OpenApiSandbox:
        OUTPUTS = {
            "nmap": "80/tcp open http\n",
            "/opt/kryonsec/openapi_probe.py": _json.dumps({
                "url": "http://t.com:80/",
                "probed": ["/openapi.json"],
                "found": [{
                    "path": "/openapi.json", "status": 200,
                    "spec_version": "3.0.1",
                    "endpoints": ["GET /api/v1/users", "POST /api/v1/login"],
                }],
            }),
        }

        def __init__(self):
            self.tools = []

        def spawn(self, argv):
            self.tools.append(argv[0])
            return SpawnResult(ok=True, exit_code=0,
                               stdout=self.OUTPUTS.get(argv[0], ""))

    fake = OpenApiSandbox()
    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"

    paths = {p["label"] for p in graph.by_type("path")}
    assert "/api/v1/users" in paths
    assert "/api/v1/login" in paths
    api_paths = [p for p in graph.by_type("path")
                 if p["properties"].get("source") == "openapi_probe"]
    assert api_paths[0]["properties"]["doc_path"] == "/openapi.json"
    assert api_paths[0]["properties"]["spec_version"] == "3.0.1"
    # the found doc is audited
    events = _events(audit)
    assert "recon_active_openapi" in events


def test_recon_active_gowitness_creates_screenshot_node(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra9")

    class GowitnessSandbox:
        OUTPUTS = {
            "nmap": "80/tcp open http\n",
            "gowitness": "[info] screenshot saved",
        }

        def __init__(self):
            self.tools = []

        def spawn(self, argv):
            self.tools.append(argv[0])
            return SpawnResult(ok=True, exit_code=0,
                               stdout=self.OUTPUTS.get(argv[0], ""))

    fake = GowitnessSandbox()
    result = ReconActiveSubagent(cfg, graph, audit, "t.com", fake).run()
    assert result.status == "ok"
    assert "gowitness" in fake.tools

    shots = graph.by_type("screenshot")
    assert shots and shots[0]["label"] == "http://t.com:80/"
    assert shots[0]["properties"]["dir"] == "/evidence"


def test_recon_active_openapi_bad_json_is_skipped_not_fatal(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-ra10")

    class BadJsonSandbox:
        def __init__(self):
            self.tools = []

        def spawn(self, argv):
            self.tools.append(argv[0])
            out = "80/tcp open http\n" if argv[0] == "nmap" else "<<not json>>"
            return SpawnResult(ok=True, exit_code=0, stdout=out)

    result = ReconActiveSubagent(
        cfg, graph, audit, "t.com", BadJsonSandbox()).run()
    assert result.status == "ok"  # unparseable output never fails the state
    assert graph.by_type("path") == []



# ---- Phase 8: the baked openapi_probe script -------------------------------

def _load_openapi_probe():
    """Load containers/sandbox/scripts/openapi_probe.py as a module (it's
    baked into the image, not part of the package)."""
    import importlib.util
    from pathlib import Path

    path = (Path(__file__).resolve().parents[1]
            / "containers" / "sandbox" / "scripts" / "openapi_probe.py")
    spec = importlib.util.spec_from_file_location("openapi_probe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_openapi_probe_script_extracts_endpoints():
    mod = _load_openapi_probe()
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/api/v1/users": {"get": {}, "post": {}},
            "/api/v1/login": {"post": {}},
            "not-a-dict": "ignore me",
        },
    }
    eps = mod._endpoints_from_spec(spec)
    assert eps == ["GET,POST /api/v1/users", "POST /api/v1/login"]


def test_openapi_probe_script_bounds_endpoint_list():
    mod = _load_openapi_probe()
    spec = {"paths": {f"/p{i}": {"get": {}} for i in range(100)}}
    eps = mod._endpoints_from_spec(spec)
    assert len(eps) == mod.MAX_ENDPOINTS  # 50 — a verbose spec can't flood
    assert all(len(e) <= mod.MAX_ENDPOINT_LEN for e in eps)


def test_openapi_probe_script_rejects_bad_url(monkeypatch):
    import io
    import contextlib

    mod = _load_openapi_probe()
    monkeypatch.setattr("sys.argv", ["openapi_probe.py", "ftp://nope/"])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mod.main()
    assert rc == 2
    assert "not an http(s) url" in buf.getvalue()


def test_boolean_probe_urls_builds_true_false_pair():
    true_url, false_url = _boolean_probe_urls(
        "http://t.com/showthread.asp?id=1")
    assert "id=1+AND+1%3D1" in true_url or "id=1%20AND%201%3D1" in true_url
    assert "id=1+AND+1%3D2" in false_url or "id=1%20AND%201%3D2" in false_url


def test_boolean_probe_urls_none_without_query():
    assert _boolean_probe_urls("http://t.com/Login.asp") is None


# ---- VERIFY subagent -----------------------------------------------------

def _is_probe(url: str) -> bool:
    """A boolean probe carries the encoded AND 1=1 / AND 1=2 injection;
    the baseline fetch is the original URL untouched."""
    return "1%3D1" in url or "1%3D2" in url



def _finding_graph():
    graph = EngagementGraph(engagement_id="e-v")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "SQLi on thread", "target_asset": "/showthread.asp?id=1",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sqlmap"], "confidence": 0.8, "approved": True,
    })
    graph.add_node("exploit_attempt", "H1:sqlmap", {
        "tool": "sqlmap", "ok": True, "exit_code": 0, "confirmed": True,
        "argv": ["sqlmap"], "output_excerpt": "is vulnerable",
    })
    graph.add_node("finding", "H1", {
        "tool": "sqlmap", "confirmed_by": "sandbox sqlmap output",
        "excerpt": "is vulnerable",
    })
    return graph


def test_verify_confirms_when_responses_differ(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class DiffSandbox:
        def __init__(self):
            self.calls = []

        def spawn(self, argv):
            self.calls.append(argv[-1])
            if not _is_probe(argv[-1]):  # baseline fetch (original URL)
                return SpawnResult(ok=True, exit_code=0,
                                   stdout="full page content")
            is_true = "1%3D1" in argv[-1] or "+AND+1%3D1" in argv[-1]
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="full page content" if is_true else "empty result",
            )

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", DiffSandbox())
    result = sub.run()

    assert result.status == "ok"
    # three fetches: true + false + baseline (no injection)
    assert len(sub.sandbox.calls) == 3
    verify_nodes = graph.by_type("verify_attempt")
    assert len(verify_nodes) == 1
    assert verify_nodes[0]["properties"]["verified"] is True
    # the finding node itself is now marked verified
    assert graph.by_type("finding")[0]["properties"]["verified"] is True
    assert "finding_verified" in _events(audit)
    ok, reason = audit.verify()
    assert ok, reason


def test_verify_rejects_dynamic_pages_as_verified(tmp_path):
    """Rotating content (timestamp/CSRF/ads) makes ANY two fetches differ —
    raw true!=false would false-verify those. The true page must match the
    baseline (1 AND 1=1 is a SQL no-op); a nonce-only difference must not."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class RotatingSandbox:
        def __init__(self):
            self.n = 0

        def spawn(self, argv):
            self.n += 1
            # every fetch differs (nonce), so true != false, but true also
            # != baseline — the injection is NOT what changed the page
            return SpawnResult(ok=True, exit_code=0,
                               stdout=f"page nonce-{self.n}")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", RotatingSandbox())
    sub.run()
    verify_nodes = graph.by_type("verify_attempt")
    assert verify_nodes[0]["properties"]["verified"] is False
    assert "finding_verification_failed" in _events(audit)


def test_verify_fails_when_responses_identical(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class SameSandbox:
        def spawn(self, argv):
            return SpawnResult(ok=True, exit_code=0, stdout="same page")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", SameSandbox())
    sub.run()

    verify_nodes = graph.by_type("verify_attempt")
    assert verify_nodes[0]["properties"]["verified"] is False
    assert "finding_verification_failed" in _events(audit)
    assert graph.by_type("finding")[0]["properties"].get("verified") is not True


def test_verify_retries_http_reset_over_https(tmp_path):
    """https-only target: probes over http get exit 56, the verifier
    retries over https and can still verify the finding."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class HttpResetSandbox:
        def __init__(self):
            self.urls = []

        def spawn(self, argv):
            url = argv[-1]
            self.urls.append(url)
            if url.startswith("http://"):
                return SpawnResult(ok=True, exit_code=56, stdout="")
            if not _is_probe(url):  # baseline fetch (original URL)
                return SpawnResult(ok=True, exit_code=0, stdout="full page")
            is_true = "1%3D1" in url or "+AND+1%3D1" in url
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="full page" if is_true else "empty result",
            )

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", HttpResetSandbox())
    sub.run()
    # 6 fetches total: true + false + baseline, each retried over https
    # after the http 56
    assert len(sub.sandbox.urls) == 6
    # every http probe was immediately followed by an https retry
    for i, u in enumerate(sub.sandbox.urls):
        if u.startswith("http://"):
            assert sub.sandbox.urls[i + 1].startswith("https://")
    assert graph.by_type("finding")[0]["properties"]["verified"] is True


def test_verify_uses_scheme_discovered_by_exploit(tmp_path):
    """An engagement_note scheme=https (EXPLOIT found the reset) makes the
    verifier probe https directly — no dead http round-trip first."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()
    graph.add_node("engagement_note", "scheme", {"scheme": "https", "reason": "reset"})

    class HttpHater:
        def spawn(self, argv):
            assert argv[-1].startswith("https://"), "must probe https directly"
            if not _is_probe(argv[-1]):  # baseline fetch (original URL)
                return SpawnResult(ok=True, exit_code=0, stdout="full page")
            is_true = "1%3D1" in argv[-1] or "+AND+1%3D1" in argv[-1]
            return SpawnResult(
                ok=True, exit_code=0,
                stdout="full page" if is_true else "empty result",
            )

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", HttpHater())
    sub.run()
    assert graph.by_type("finding")[0]["properties"]["verified"] is True


def test_verify_skips_when_probe_fails(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class DeadSandbox:
        def spawn(self, argv):
            return SpawnResult(ok=False, exit_code=-1, stdout="",
                               error="curl failed")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", DeadSandbox())
    result = sub.run()
    assert result.status == "ok"  # does not halt the engagement
    verify_nodes = graph.by_type("verify_attempt")
    assert verify_nodes[0]["properties"]["verified"] is False
    assert "verify_skipped" in _events(audit)


def test_verify_no_findings_is_ok(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-v2")

    class UnusedSandbox:
        def spawn(self, argv):  # pragma: no cover
            raise AssertionError("should not spawn anything")

    result = VerifySubagent(cfg, graph, audit, "t.com", UnusedSandbox()).run()
    assert result.status == "ok"
    assert "verify_done" in _events(audit)


def test_verify_baseline_keeps_query_string(tmp_path):
    """v1.1.1 regression: the baseline stripped the ENTIRE query string,
    fetching a different page (missing-param error), so true_out ==
    base_out could never hold — genuine boolean-SQLi findings
    systematically 'failed' verification. The baseline is the original
    URL with its original query."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = _finding_graph()

    class BaselineSandbox:
        def __init__(self):
            self.urls = []

        def spawn(self, argv):
            url = argv[-1]
            self.urls.append(url)
            if _is_probe(url):
                is_true = "1%3D1" in url
                return SpawnResult(
                    ok=True, exit_code=0,
                    stdout="full page" if is_true else "empty result")
            # the baseline must be the original URL WITH its query string
            assert url == "http://target-corp.com/showthread.asp?id=1", url
            return SpawnResult(ok=True, exit_code=0, stdout="full page")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", BaselineSandbox())
    sub.run()
    assert len(sub.sandbox.urls) == 3  # true + false + baseline
    assert graph.by_type("finding")[0]["properties"]["verified"] is True


# ---- VERIFY: secondary probes (tool expansion Phase 1) --------------------

def test_verify_no_query_param_gathers_secondary_evidence(tmp_path):
    """A finding with no numeric query parameter can't be boolean-probed.
    VERIFY then gathers reachability evidence with OTHER tools (httpie,
    nc, dig — openssl only for https) — recorded as supporting evidence,
    never marking the finding verified on its own."""
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-v3")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "dir listing", "target_asset": "/uploads/",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["nikto"], "confidence": 0.6, "approved": True,
    })
    graph.add_node("exploit_attempt", "H1:nikto", {
        "tool": "nikto", "ok": True, "exit_code": 0, "confirmed": True,
        "argv": ["nikto"], "output_excerpt": "found",
    })
    graph.add_node("finding", "H1", {
        "tool": "nikto", "confirmed_by": "sandbox nikto output",
        "excerpt": "found",
    })

    class ProbeSandbox:
        def __init__(self):
            self.spawned = []

        def spawn(self, argv):
            self.spawned.append(argv)
            return SpawnResult(ok=True, exit_code=0, stdout="x")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", ProbeSandbox())
    result = sub.run()
    assert result.status == "ok"

    tools = [argv[0] for argv in sub.sandbox.spawned]
    assert "http" in tools      # httpie
    assert "nc" in tools
    assert "dig" in tools
    assert "openssl" not in tools  # plain http URL — no TLS handshake probe
    assert "curl" not in tools     # nothing to boolean-probe

    verify_nodes = graph.by_type("verify_attempt")
    assert len(verify_nodes) == 1
    props = verify_nodes[0]["properties"]
    assert props["verified"] is False  # reachability ≠ verification
    assert set(props["secondary_evidence"]) == {"http", "nc", "dig"}
    assert "verify_skipped" in _events(audit)
    ok, reason = audit.verify()
    assert ok, reason


def test_verify_secondary_probes_https_gets_openssl(tmp_path):
    cfg = KryonsecConfig(home=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    graph = EngagementGraph(engagement_id="e-v4")
    graph.add_node("target", "target-corp.com", {})
    graph.add_node("hypothesis", "H1", {
        "title": "old ssl", "target_asset": "https://target-corp.com/old/",
        "rationale": "evidence", "cvss_vector": "",
        "tools": ["sslscan"], "confidence": 0.5, "approved": True,
    })
    graph.add_node("finding", "H1", {
        "tool": "sslscan", "confirmed_by": "sandbox sslscan output",
        "excerpt": "TLSv1.0 enabled",
    })

    class ProbeSandbox:
        def __init__(self):
            self.spawned = []

        def spawn(self, argv):
            self.spawned.append(argv)
            return SpawnResult(ok=True, exit_code=0, stdout="x")

    sub = VerifySubagent(cfg, graph, audit, "target-corp.com", ProbeSandbox())
    sub.run()
    tools = [argv[0] for argv in sub.sandbox.spawned]
    assert "openssl" in tools
    # the openssl probe connects to host:port, not a URL
    openssl_argv = next(a for a in sub.sandbox.spawned if a[0] == "openssl")
    assert openssl_argv[openssl_argv.index("-connect") + 1] == "target-corp.com:443"
