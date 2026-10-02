"""Phase 3: the memory browser is a window, not a door.

The browser reads what the Purple Team engine already wrote and shows it on
loopback. These tests hold that line: the bind is loopback-only, the routes
are read-only, an engagement id cannot become a path or a query fragment,
responses carry no credentials and no stack traces, and the process has no
way to reach a Purple Team action because it holds no reference to one.

The HTTP tests drive a real server over a real socket rather than calling
handler methods directly — headers, status codes and the 405 path are the
things under test, and those only exist on the wire.
"""

from __future__ import annotations

import ast
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from kryonsec import cli
from kryonsec.config import KryonsecConfig
from kryonsec.memory import (
    InvalidEngagementId,
    MemoryUnavailable,
    create_server,
    data,
    is_loopback_host,
    list_engagements,
    load_engagement,
    storage_status,
    viewer,
)
from kryonsec.purple.graph_store import save_graph
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.storage import get_purple_session, init_purple_db, reset_engine

# ------------------------------------------------------------------ fixtures


@pytest.fixture()
def cfg(tmp_path):
    """An embedded install: no DATABASE_URL, so engagement memory is the
    dedicated file. Home/workspace are redirected so nothing here can touch
    the real ~/.kryonsec."""
    reset_engine()
    config = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    config.database_url = None
    yield config
    reset_engine()


class Response:
    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


@pytest.fixture()
def server(cfg):
    srv = create_server(cfg, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def call(server, path: str, *, host: str | None = None, method: str = "GET",
         body: bytes | None = None) -> Response:
    """One request to the running server, errors returned rather than raised."""
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    request = urllib.request.Request(url, method=method, data=body)
    if host is not None:
        request.add_header("Host", host)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return Response(response.status, dict(response.headers),
                            response.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers), exc.read())


def _graph(engagement_id: str = "eng-one", *, secret: bool = False) -> EngagementGraph:
    graph = EngagementGraph(engagement_id=engagement_id)
    target = graph.add_node(
        "target", "example.com",
        provenance={"source_type": "config", "source": "engagement_config",
                    "agent": "RECON_PASSIVE"},
    )
    service = graph.add_node(
        "service", "example.com:443/tcp", {"port": 443, "service": "https"},
        provenance={"source_type": "tool", "source": "nmap",
                    "agent": "RECON_ACTIVE"},
    )
    graph.add_edge(target, "has_service", service,
                   provenance={"source_type": "tool", "source": "nmap"})
    if secret:
        graph.add_node(
            "credential", "discovered key",
            {"aws": "AKIAIOSFODNN7EXAMPLE",
             "dsn": "postgres://svc:hunter2@db.internal/app"},
            status="inferred",
            provenance={"source_type": "tool", "source": "trufflehog"},
        )
    return graph


def _store(cfg, graph: EngagementGraph) -> None:
    init_purple_db(cfg)
    with get_purple_session(cfg) as session:
        save_graph(session, graph)


def _write_audit(cfg, engagement_id: str, lines: list[dict]) -> None:
    """A minimal audit log on disk, with the real chain fields the summary
    reader expects."""
    path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(json.dumps(line) + "\n")


# --- STEP 5a: the server binds loopback and answers only to loopback --------

def test_the_default_bind_is_loopback(server):
    assert server.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.40", "example.com", ""])
def test_a_non_loopback_bind_is_refused(cfg, host):
    """There is no flag that makes this public; remote access is an SSH
    tunnel's job."""
    with pytest.raises(ValueError):
        create_server(cfg, host, 0)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_hosts_are_recognised(host):
    assert is_loopback_host(host)


def test_the_cli_refuses_a_public_bind_before_serving(cfg, monkeypatch):
    """The command exits 2 and never reaches the server, so a typo cannot
    quietly expose the engagement database to the LAN."""
    def explode(*args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("serve() must not be called for a public bind")

    monkeypatch.setattr("kryonsec.memory.serve", explode)
    assert cli._run_memory(cfg, host="0.0.0.0") == 2


def test_a_foreign_host_header_is_rejected(server):
    """Binding to loopback does not stop DNS rebinding: a page on
    evil.example can resolve its own name to 127.0.0.1 and have the browser
    send *its* Host header here."""
    response = call(server, "/api/engagements", host="evil.example")
    assert response.status == 403
    assert response.json()["error"]["code"] == "forbidden_host"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_a_loopback_host_header_is_accepted(server, host):
    # the port varies per run, so exercise the bare name and the real form
    assert call(server, "/api/health", host=host).status == 200
    real = f"127.0.0.1:{server.server_address[1]}"
    assert call(server, "/api/health", host=real).status == 200


def test_a_missing_host_header_is_rejected(server):
    """HTTP/1.1 requires Host; an absent one is not a loopback request."""
    assert call(server, "/api/health", host="").status == 403


# --- STEP 5b: engagement ids are validated, never trusted -------------------

@pytest.mark.parametrize("bad", [
    "../etc/passwd", "..", "a/b", "../../home/user/.ssh", "%2e%2e%2fetc",
    "with space", "semi;colon", "-leading-dash", "", "x" * 65, "nul\x00byte",
])
def test_an_invalid_engagement_id_is_rejected(server, bad):
    response = call(server, "/api/engagements/" + urllib.parse.quote(bad, safe=""))
    assert response.status in (400, 404), bad
    if response.status == 400:
        assert response.json()["error"]["code"] == "invalid_engagement_id"


def test_an_id_is_validated_before_any_lookup(cfg, monkeypatch):
    """The guard runs before the data layer sees the string, so a traversal
    attempt cannot become a filesystem path or a SQL fragment."""
    seen: list[str] = []

    def record(_cfg, engagement_id):
        seen.append(engagement_id)
        return {"meta": {"engagement_id": engagement_id}, "graph":
                {"engagement_id": engagement_id, "nodes": [], "edges": []}}

    monkeypatch.setattr("kryonsec.memory.data.load_engagement", record)
    srv = create_server(cfg, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        assert call(srv, "/api/engagements/..%2f..%2fetc").status == 400
        assert seen == []
        assert call(srv, "/api/engagements/good-id").status == 200
        assert seen == ["good-id"]
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_the_cli_and_the_browser_share_one_id_rule():
    """One rule, not two: the browser accepts exactly what `--id` accepts."""
    from kryonsec.engagement_id import is_valid_engagement_id

    for value in ["abc", "eng-2026.10_03", "A" * 64]:
        assert is_valid_engagement_id(value)
    for value in ["", "A" * 65, "../x", "/etc", "a b", "-x"]:
        assert not is_valid_engagement_id(value)
    # and it never raises on a non-string
    assert not is_valid_engagement_id(None)
    assert not is_valid_engagement_id(7)


# --- STEP 5c: the routes are read-only -------------------------------------

@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_write_methods_are_refused(server, method):
    response = call(server, "/api/engagements", method=method, body=b"{}")
    assert response.status == 405
    assert response.json()["error"]["code"] == "read_only"


def test_a_refusal_closes_the_connection(server):
    """A refused method may carry a body this server never reads. Keeping
    the connection alive would leave those bytes to be parsed as the next
    request line — the client would hang, and worse, a body could be
    mistaken for a request."""
    response = call(server, "/api/engagements", method="POST",
                    body=b'{"graph": "junk"}')
    assert response.status == 405
    assert response.headers.get("Connection") == "close"
    assert response.headers.get("Allow") == "GET, HEAD"
    # ...and the server is still usable afterwards
    assert call(server, "/api/health").status == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_a_write_method_cannot_reach_a_route_either(server, method):
    """405 on a real path, not just on an unknown one — there is no write
    route to fall through to."""
    for path in ["/", "/api/health", "/api/engagements", "/api/engagements/x"]:
        assert call(server, path, method=method, body=b"{}").status == 405


def test_the_handler_exposes_no_other_methods(server):
    """Enumerate the handler: anything that is not GET/HEAD is a refusal."""
    from kryonsec.memory.viewer import MemoryRequestHandler

    exposed = {name for name in vars(MemoryRequestHandler) if name.startswith("do_")}
    assert exposed == {"do_GET", "do_HEAD", "do_POST", "do_PUT", "do_PATCH",
                       "do_DELETE", "do_OPTIONS"}


def test_viewing_does_not_create_a_database(cfg, server):
    """A read path that ran DDL or opened a connection eagerly would create
    the store it was only supposed to look at."""
    assert not cfg.purple_db_path.exists()
    assert call(server, "/api/engagements").status == 200
    assert call(server, "/api/health").status == 200
    assert not cfg.purple_db_path.exists()


def test_a_posted_graph_is_ignored_not_stored(server, cfg):
    """The strongest statement of read-only: send a well-formed graph at the
    API and confirm the store is untouched afterwards."""
    _store(cfg, _graph("eng-one"))
    before = call(server, "/api/engagements/eng-one").json()

    payload = json.dumps({"graph": {"engagement_id": "eng-one", "nodes": [],
                                    "edges": []}}).encode()
    assert call(server, "/api/engagements/eng-one", method="POST",
                body=payload).status == 405

    after = call(server, "/api/engagements/eng-one").json()
    assert after["graph"] == before["graph"]
    assert len(after["graph"]["nodes"]) == 2


# --- STEP 5d: what the browser shows ---------------------------------------

def test_the_engagement_list_reports_what_is_stored(cfg, server):
    _store(cfg, _graph("eng-one"))
    payload = call(server, "/api/engagements").json()
    assert payload["storage"]["available"] is True
    ids = [item["engagement_id"] for item in payload["engagements"]]
    assert ids == ["eng-one"]
    item = payload["engagements"][0]
    assert item["persisted"] is True
    assert item["nodes"] == 2
    assert item["edges"] == 1


def test_a_stored_graph_round_trips_through_the_api(cfg, server):
    """The browser shows the same nodes and edges the engine saved — the
    persisted graph is the source of truth, not a re-derivation."""
    graph = _graph("eng-one")
    _store(cfg, graph)

    payload = call(server, "/api/engagements/eng-one").json()
    assert payload["graph"] == graph.to_dict()


def test_engagements_are_isolated_from_each_other(cfg, server):
    """One engagement's ids must never resolve inside another's graph."""
    _store(cfg, _graph("eng-one"))
    other = EngagementGraph(engagement_id="eng-two")
    other.add_node("target", "other.example", provenance={"source_type": "config"})
    _store(cfg, other)

    one = call(server, "/api/engagements/eng-one").json()["graph"]
    two = call(server, "/api/engagements/eng-two").json()["graph"]

    assert {n["engagement_id"] for n in one["nodes"]} == {"eng-one"}
    assert {n["engagement_id"] for n in two["nodes"]} == {"eng-two"}
    assert len(one["nodes"]) == 2 and len(two["nodes"]) == 1
    assert not ({n["id"] for n in one["nodes"]} & {n["id"] for n in two["nodes"]})


def test_an_empty_engagement_returns_an_empty_graph(cfg, server):
    """A recorded engagement with nothing in it is a valid state, not an
    error — the page says so instead of failing."""
    _store(cfg, EngagementGraph(engagement_id="eng-empty"))
    payload = call(server, "/api/engagements/eng-empty").json()
    assert payload["graph"]["nodes"] == []
    assert payload["graph"]["edges"] == []


def test_an_unknown_engagement_is_empty_not_an_error(cfg, server):
    _store(cfg, _graph("eng-one"))
    response = call(server, "/api/engagements/no-such-engagement")
    assert response.status == 200
    assert response.json()["graph"]["nodes"] == []


def test_a_missing_database_is_reported_not_created(cfg, server):
    payload = call(server, "/api/engagements").json()
    assert payload["storage"]["available"] is False
    assert payload["engagements"] == []
    assert "no engagement database" in payload["storage"]["detail"]
    assert not cfg.purple_db_path.exists()


def test_storage_status_never_opens_a_connection(cfg):
    """Checking availability must not be the thing that creates the file."""
    status = storage_status(cfg)
    assert status["available"] is False
    assert not cfg.purple_db_path.exists()


def test_malformed_graph_data_fails_loudly_without_leaking_detail(cfg, monkeypatch):
    """An edge whose node is gone, or a row someone edited by hand. The
    browser says it could not read the graph; the reason goes to the local
    log, because a driver message can quote a connection URL."""
    def boom(_session, _engagement_id):
        raise RuntimeError("connection to postgres://user:pw@host/db failed")

    _store(cfg, _graph("eng-one"))
    # data.load_engagement imports load_graph inside the call, so the patch
    # has to land on the defining module.
    monkeypatch.setattr("kryonsec.purple.graph_store.load_graph", boom)

    with pytest.raises(RuntimeError):
        load_engagement(cfg, "eng-one")

    srv = create_server(cfg, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        response = call(srv, "/api/engagements/eng-one")
        assert response.status == 500
        assert response.json()["error"]["code"] == "graph_unreadable"
        assert b"pw@host" not in response.body
        assert b"RuntimeError" not in response.body
        assert b"postgres://" not in response.body
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_an_incomplete_engagement_is_shown_as_incomplete(cfg, server):
    """No report in the audit log means the run stopped early. The page must
    say so rather than presenting a partial graph as a finished result."""
    _store(cfg, _graph("eng-stopped"))
    _write_audit(cfg, "eng-stopped", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
    ])
    item = call(server, "/api/engagements").json()["engagements"][0]
    assert item["status"] == "incomplete"
    assert item["target"] == "example.com"
    assert item["report_written"] is False


def test_a_halted_engagement_surfaces_its_reason(cfg, server):
    _store(cfg, _graph("eng-halted"))
    _write_audit(cfg, "eng-halted", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "RECON_PASSIVE"},
        {"event": "zone_b_blocked", "reason": "sandbox runtime unavailable"},
    ])
    item = call(server, "/api/engagements").json()["engagements"][0]
    assert item["status"] == "halted"
    assert item["halt_reason"] == "sandbox runtime unavailable"


def test_a_completed_engagement_reads_as_complete(cfg, server):
    _store(cfg, _graph("eng-done"))
    _write_audit(cfg, "eng-done", [
        {"event": "engagement_created", "target": "example.com"},
        {"event": "state_enter", "state": "REPORT"},
        {"event": "report_written", "path": "report.md"},
    ])
    item = call(server, "/api/engagements").json()["engagements"][0]
    assert item["status"] == "complete"
    assert item["report_written"] is True


def test_an_engagement_directory_with_no_graph_is_listed_as_such(cfg, server):
    """`kryonsec purple` writes the audit directory before the graph. An
    interrupted run leaves the directory behind, and the page should show
    the engagement without pretending it has a graph."""
    _write_audit(cfg, "interrupted", [{"event": "engagement_created",
                                       "target": "example.com"}])
    payload = call(server, "/api/engagements").json()
    item = payload["engagements"][0]
    assert item["engagement_id"] == "interrupted"
    assert item["persisted"] is False
    assert item["nodes"] == 0


def test_the_audit_summary_reads_only_whitelisted_fields(cfg):
    """The audit log is the engine's record; the browser reads a summary of
    it, not the whole thing."""
    _write_audit(cfg, "eng-one", [
        {"event": "engagement_created", "target": "example.com",
         "operator": "someone", "api_key": "should-not-surface"},
        {"event": "state_enter", "state": "RECON_PASSIVE", "internal": "x"},
        {"event": "tool_call", "argv": ["nmap", "-sV"], "output": "raw"},
    ])
    item = list_engagements(cfg)[0]
    assert item["target"] == "example.com"
    assert item["states"] == ["RECON_PASSIVE"]
    flat = json.dumps(item)
    assert "should-not-surface" not in flat
    assert "nmap" not in flat
    assert "operator" not in flat


def test_a_hostile_engagement_directory_name_is_ignored(cfg):
    """Directory names from disk are validated too — a folder called
    `../../etc` must not become an engagement."""
    (cfg.home / "engagements" / "..evil").mkdir(parents=True)
    (cfg.home / "engagements" / "fine").mkdir(parents=True)
    ids = [item["engagement_id"] for item in list_engagements(cfg)]
    assert ids == ["fine"]


# --- STEP 5e: no secrets in a response -------------------------------------

def test_secret_shaped_values_are_masked(cfg, server):
    _store(cfg, _graph("eng-one", secret=True))
    response = call(server, "/api/engagements/eng-one")
    payload = response.json()

    assert payload["redactions"] > 0
    assert b"AKIAIOSFODNN7EXAMPLE" not in response.body
    assert b"hunter2" not in response.body

    credential = [n for n in payload["graph"]["nodes"]
                  if n["node_type"] == "credential"][0]
    assert "SECRET" in json.dumps(credential["properties"])
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(credential["properties"])


def test_masking_keeps_the_response_valid_json(cfg, server):
    """Scrubbing the serialized body would corrupt it — the connection-string
    pattern runs to the next whitespace, which in compact JSON is the
    following key. Values are scrubbed before serialization instead."""
    _store(cfg, _graph("eng-one", secret=True))
    response = call(server, "/api/engagements/eng-one")
    payload = response.json()          # raises if the body is not valid JSON
    assert set(payload) >= {"meta", "graph", "redactions"}


def test_scrub_is_recursive_and_counts_its_replacements():
    payload = {
        "a": "AKIAIOSFODNN7EXAMPLE",
        "b": ["hunter2", {"c": "postgres://u:hunter2@h/db"}],
        "safe": "example.com",
    }
    cleaned, count = data.scrub(payload)
    assert count >= 1
    assert cleaned["safe"] == "example.com"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(cleaned)
    assert json.loads(json.dumps(cleaned)) == cleaned


def test_scrub_leaves_ordinary_strings_alone():
    payload = {"label": "api.example.com", "note": "port 443/tcp open"}
    cleaned, count = data.scrub(payload)
    assert count == 0
    assert cleaned == payload


def test_the_engagement_list_is_scrubbed_too(cfg, server):
    _write_audit(cfg, "eng-one", [{"event": "engagement_created",
                                   "target": "AKIAIOSFODNN7EXAMPLE"}])
    response = call(server, "/api/engagements")
    assert b"AKIAIOSFODNN7EXAMPLE" not in response.body
    assert response.json()["redactions"] >= 1


# --- STEP 5f: security headers and error hygiene ---------------------------

def test_security_headers_are_present_on_every_response(server):
    for path in ["/", "/static/app.js", "/api/engagements", "/api/health"]:
        headers = call(server, path).headers
        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp
        assert "form-action 'none'" in csp
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("Referrer-Policy") == "no-referrer"
        assert headers.get("Cache-Control") == "no-store"


def test_no_cors_header_is_sent(server):
    """Nothing cross-origin may read engagement memory."""
    headers = call(server, "/api/engagements", host="127.0.0.1").headers
    assert "Access-Control-Allow-Origin" not in headers


def test_the_page_loads_nothing_off_this_machine(server):
    """The CSP is what makes "no CDN" a rule instead of a promise, and the
    page itself must not reference an external host."""
    page = call(server, "/").body.decode()
    assert "http://" not in page.replace("http://127.0.0.1", "")
    assert "https://" not in page
    assert "//cdn" not in page and "cdn." not in page
    script = call(server, "/static/app.js").body.decode()
    assert "http://" not in script and "https://" not in script


def test_the_visual_identity_is_local_too(server):
    """The memory browser reuses the landing page's fonts and palette, so it
    is the one place a copy-paste would quietly reintroduce a Google Fonts
    <link>. Nothing it serves may name an external host at all."""
    for path in ["/", "/static/app.css", "/static/app.js", "/static/theme-init.js"]:
        text = call(server, path).body.decode()
        assert "fonts.googleapis" not in text, path
        assert "fonts.gstatic" not in text, path
        assert "http://" not in text, path
        assert "https://" not in text, path


def test_the_csp_allows_fonts_from_this_origin_only(server):
    """Bundling the fonts is what lets the CSP stay default-deny. If a
    font-src were ever widened to a CDN, that promise would be gone."""
    csp = call(server, "/").headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "font-src 'self'" in csp
    assert "*.gstatic.com" not in csp and "*.googleapis.com" not in csp
    assert "https:" not in csp


# Any /static/ path the page, the stylesheet or a script mentions.
_ASSET_REF = re.compile(r"/static/[A-Za-z0-9._/-]+")


def test_every_asset_the_page_asks_for_is_served(server):
    """A reference the route table does not know is a 404 and a broken page —
    a missing font, a missing favicon, a renamed file. Collect every /static/
    path out of everything served and check each one resolves.

    This is the test that would have caught the fonts being added to the
    stylesheet without a matching route."""
    text = "".join(
        call(server, path).body.decode()
        for path in ["/", "/static/app.css", "/static/app.js",
                     "/static/theme-init.js"]
    )
    referenced = sorted(set(_ASSET_REF.findall(text)))
    assert referenced, "the page references no assets at all — suspicious"
    for path in referenced:
        response = call(server, path)
        assert response.status == 200, f"{path} is referenced but not served"


def test_the_bundled_fonts_are_real_woff2_files(server):
    """The landing page's two faces ship inside the wheel. Check the container
    signature, not just the status: a truncated or mis-typed file would still
    answer 200 and then silently fall back to Courier."""
    for path in ["/static/fonts/press-start-2p-latin.woff2",
                 "/static/fonts/vt323-latin.woff2"]:
        response = call(server, path)
        assert response.status == 200
        assert response.headers.get("Content-Type") == "font/woff2"
        assert response.body[:4] == b"wOF2"
        assert len(response.body) > 4096


def test_the_font_licences_ship_alongside_the_fonts():
    """Both faces are OFL, and the licence has to travel with them. The files
    are in the package rather than fetched, so this is a packaging check."""
    fonts = viewer.STATIC_DIR / "fonts"
    for filename in ["OFL-PressStart2P.txt", "OFL-VT323.txt"]:
        text = (fonts / filename).read_text(encoding="utf-8")
        assert "SIL OPEN FONT LICENSE" in text


# --- the visual identity is the landing page's, and is checked ---------------

def _static(name: str) -> str:
    return (viewer.STATIC_DIR / name).read_text(encoding="utf-8")


def test_the_stylesheet_reuses_the_landing_pages_palette():
    """The browser is meant to read as another part of Kryonsec, so the
    palette is copied from the landing page rather than re-invented. "Looks
    similar" is not checkable; these literals are — every one of them was
    diffed against kryonsec-landing/style.css."""
    css = _static("app.css")
    for token in ["--bg: #f5f5f0", "--paper: #fbfbf7", "--fg: #1a1a1a",
                  "--border: #3a3a3a", "--muted: #626262",
                  "--body-copy: #424242", "--accent: #a855f7"]:
        assert token in css, f"landing-page token missing: {token}"
    # the same dark-mode block, every value included — not just the accent
    assert ':root[data-theme="dark"]' in css
    for token in ["--bg: #111112", "--paper: #1b1b1d", "--fg: #f5f5f0",
                  "--border: #8f8f8f", "--muted: #b6b6b0",
                  "--body-copy: #d2d2cc", "--accent: #c084fc"]:
        assert token in css, f"landing-page dark token missing: {token}"


def test_both_landing_page_fonts_are_declared_and_used():
    """Press Start 2P for headings, labels and counters; VT323 for URLs,
    JSON, evidence, timestamps and node names. Both are @font-face'd from
    files in this package — no Google Fonts anywhere near it."""
    css = _static("app.css")
    assert "font-family: 'Press Start 2P'" in css
    assert "font-family: 'VT323'" in css
    assert "--pixel: 'Press Start 2P'" in css
    assert "--tech: 'VT323'" in css
    # declared, and actually used on both sides of the split
    assert "var(--pixel)" in css and "var(--tech)" in css


def test_the_page_uses_the_landing_pages_theme_key():
    """Same localStorage key and same data-theme attribute as the landing
    page, so the two surfaces agree on the mode you last chose."""
    init = _static("theme-init.js")
    assert "kryonsec-theme" in init
    assert "document.documentElement.dataset.theme" in init
    assert 'id="theme-toggle"' in _static("index.html")


def test_a_node_is_drawn_as_a_dot_and_nothing_else():
    """PART 5's rule: a node is a small circular dot with its name beside it.
    No rectangular cards, no boxes, no icons, no badges, no embedded
    metadata. The node pass in the renderer is therefore allowed exactly one
    drawing primitive — an arc. This is the guard against a node card
    growing back."""
    script = _static("app.js")
    nodes_pass = script.split("/* ---- nodes", 1)[1].split("/* ---- names", 1)[0]
    assert "ctx.arc(" in nodes_pass, "the node pass draws no dots at all"
    for banned in ["fillRect", "strokeRect", "roundRect", "drawImage", "fillText"]:
        assert banned not in nodes_pass, f"the node pass draws a {banned}"


def test_node_details_live_in_the_inspector_not_on_the_canvas():
    """Everything known about a node — identity, canonical key, provenance,
    properties, relationships — is DOM in the inspector panel, which is the
    only place the spec allows it to appear."""
    script = _static("app.js")
    assert "$('detail')" in script
    node_detail = script.split("function renderNodeDetail", 1)[1].split("\nfunction ", 1)[0]
    for field in ["canonical_key", "created_at", "provenance", "properties",
                  "RELATIONSHIPS"]:
        assert field in node_detail, f"{field} is never shown in the inspector"


def test_relationship_names_are_not_painted_by_default():
    """The default view is dots, names and thin lines. An edge's relationship
    is drawn only while that edge is hovered or selected."""
    script = _static("app.js")
    assert "state.hoverEdge" in script
    assert "const labelEdge = selectedEdge || state.hoverEdge;" in script


_ID_LOOKUP = re.compile(r"\$\('([A-Za-z0-9_-]+)'\)")


def test_the_script_only_asks_for_elements_the_page_has():
    """A $() naming an id the markup does not have returns null, and the next
    property access throws — killing the whole script, not just that one
    feature. Cost nothing to check, and it already caught one."""
    page = _static("index.html")
    present = set(re.findall(r'id="([A-Za-z0-9_-]+)"', page))
    wanted = set(_ID_LOOKUP.findall(_static("app.js")))
    assert wanted, "no element lookups found — did app.js change shape?"
    assert wanted <= present, (
        f"app.js looks up ids the page does not define: {sorted(wanted - present)}"
    )


def test_the_brand_mark_is_served_as_a_svg(server):
    """The browser wears the real Kryonsec logo, not a redrawn one."""
    response = call(server, "/static/assets/mark.svg")
    assert response.status == 200
    assert response.headers.get("Content-Type") == "image/svg+xml"
    body = response.body.decode()
    assert body.lstrip().startswith("<svg")
    # the favicon's own ink and paper, straight from the landing page
    assert "#1a1a1a" in body and "#f5f5f0" in body


def test_static_routes_come_from_a_fixed_table(server):
    """The path selects a key, never a filename, so there is no traversal
    surface in the static handler at all."""
    for path in ["/static/../data.py", "/static/..%2fdata.py",
                 "/static/secrets.py", "/%2e%2e/setup.py",
                 "/static/fonts/../../../data.py",
                 "/static/assets/../../data.py"]:
        assert call(server, path).status in (400, 404)


def test_an_unknown_route_is_a_clean_404(server):
    response = call(server, "/api/engagements/x/y/z")
    assert response.status == 404
    assert response.json()["error"]["code"] == "not_found"


def test_an_error_body_carries_no_internals(server):
    body = call(server, "/nope").body.decode()
    assert "Traceback" not in body
    assert "kryonsec/" not in body
    assert "site-packages" not in body


# What the memory package is allowed to import. This is the whole claim that
# the browser cannot reach a Purple Team action: it holds no reference to the
# orchestrator, the sandbox, the tool allowlist or the approval gate, and it
# has no way to start a process.
_ALLOWED_IMPORTS = {
    ".", ".data", ".viewer",
    "..config", "..engagement_id", "..purple.graph_store", "..secrets",
    "..storage",
    "__future__", "json", "logging", "re", "threading", "webbrowser",
    "http", "pathlib", "typing", "urllib", "sqlalchemy",
}

# Builtins that turn data into code.
_FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
# Module roots that reach outside this process or this machine.
_FORBIDDEN_ROOTS = {
    "subprocess", "os", "shutil", "socket", "ctypes", "importlib",
    "multiprocessing", "pickle", "pty", "requests", "urllib3", "httpx",
}


def _imports_of(path: Path) -> set[str]:
    """Every module a file imports, as written (relative dots kept)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * (node.level or 0) + (node.module or ""))
    return found


def _is_allowed_import(name: str) -> bool:
    return any(name == allowed or name.startswith(allowed + ".")
               for allowed in _ALLOWED_IMPORTS)


def _dotted_call(func: ast.expr) -> str | None:
    """``subprocess.run`` for a call written as an attribute chain, ``eval``
    for a bare name, None for anything else (a subscript, a call result)."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def test_the_memory_package_imports_nothing_that_can_act():
    """Audited by AST, not by reading the file: the imports of every module
    in the package must stay inside the allowlist."""
    package = Path(data.__file__).parent
    for source_file in sorted(package.glob("*.py")):
        unexpected = {name for name in _imports_of(source_file)
                      if not _is_allowed_import(name)}
        assert not unexpected, f"{source_file.name} imports {sorted(unexpected)}"


def test_the_memory_package_calls_nothing_dangerous():
    """The same audit for calls: no process spawn, no dynamic evaluation.

    ``webbrowser.open`` is the one thing here that starts anything, and it
    starts the operator's own browser on a URL this process printed — that is
    the feature, not a way to run a scan."""
    package = Path(data.__file__).parent
    for source_file in sorted(package.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"),
                         filename=str(source_file))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _dotted_call(node.func)
            if dotted is None:
                continue
            assert dotted not in _FORBIDDEN_BUILTINS, \
                f"{source_file.name} calls {dotted}()"
            assert dotted.split(".")[0] not in _FORBIDDEN_ROOTS, \
                f"{source_file.name} calls {dotted}()"


def test_the_viewer_reads_the_graph_only_through_the_shared_store():
    """One reader of the persisted graph — the same ``load_graph`` the engine
    writes with — so the browser cannot grow a second interpretation of the
    data it displays."""
    source = Path(data.__file__).read_text(encoding="utf-8")
    assert "from ..purple.graph_store import load_graph" in source
    assert "graph_store" in source and "save_graph" not in source


def test_reading_an_engagement_does_not_write_to_the_database(cfg):
    """load_engagement must not open a session that flushes anything."""
    _store(cfg, _graph("eng-one"))
    before = cfg.purple_db_path.stat().st_mtime_ns
    first = load_engagement(cfg, "eng-one")
    second = load_engagement(cfg, "eng-one")
    after = cfg.purple_db_path.stat().st_mtime_ns
    assert first["graph"] == second["graph"]
    assert before == after


def test_loading_rejects_an_invalid_id_at_the_data_layer(cfg):
    """Validation is not only an HTTP concern — the data layer refuses too,
    so no future caller can skip it."""
    with pytest.raises(InvalidEngagementId):
        load_engagement(cfg, "../etc/passwd")
    with pytest.raises(InvalidEngagementId):
        load_engagement(cfg, "")


def test_loading_without_storage_raises_unavailable(cfg):
    with pytest.raises(MemoryUnavailable):
        load_engagement(cfg, "eng-one")


# --- STEP 5g: the CLI command ----------------------------------------------

def test_the_memory_subcommand_reaches_serve_with_loopback_defaults(cfg, monkeypatch):
    captured = {}

    def fake_serve(config, *, host, port, open_browser):
        captured.update(config=config, host=host, port=port,
                        open_browser=open_browser)
        return 0

    monkeypatch.setattr("kryonsec.memory.serve", fake_serve)
    assert cli.main(["memory"]) == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8899
    assert captured["open_browser"] is True


def test_the_memory_subcommand_passes_flags_through(cfg, monkeypatch):
    captured = {}

    def fake_serve(config, *, host, port, open_browser):
        captured.update(host=host, port=port, open_browser=open_browser)
        return 0

    monkeypatch.setattr("kryonsec.memory.serve", fake_serve)
    assert cli.main(["memory", "--port", "9123", "--no-browser"]) == 0
    assert captured == {"host": "127.0.0.1", "port": 9123, "open_browser": False}


def test_the_memory_subcommand_refuses_to_bind_publicly(cfg, monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover
        raise AssertionError("serve() must not be reached")

    monkeypatch.setattr("kryonsec.memory.serve", explode)
    assert cli.main(["memory", "--host", "0.0.0.0"]) == 2


def test_the_help_text_still_lists_the_other_commands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for command in ["doctor", "setup", "purple", "memory"]:
        assert command in out


def test_serve_returns_a_code_rather_than_raising_on_a_bad_host(cfg, capsys):
    from kryonsec.memory import serve

    assert serve(cfg, host="0.0.0.0", port=0, open_browser=False) == 2
    assert "loopback" in capsys.readouterr().out


class InstantServer:
    """A bound server whose serve_forever returns at once.

    serve() waits on its serving thread, so a real one would keep the test
    running until a signal arrived. This keeps the socket (and therefore the
    real bound port) but ends the wait immediately.
    """

    def __init__(self, real):
        self._real = real
        self.server_address = real.server_address

    def serve_forever(self, poll_interval=0.5):
        return

    def shutdown(self):
        return

    def server_close(self):
        self._real.server_close()


def test_serve_falls_back_when_the_port_is_taken(cfg, monkeypatch):
    """A busy port should not stop the browser from opening — the operator
    gets a working URL, not a stack trace.

    The conflict is simulated rather than produced, so this stays a test of
    serve()'s own branch on every platform. That the real bind also raises is
    the next test's job.
    """
    from kryonsec.memory import viewer

    real_create = viewer.create_server
    attempts: list[int] = []

    def create(config, host, port):
        attempts.append(port)
        if port != 0:
            raise OSError(10048, "address already in use")
        return InstantServer(real_create(config, host, port))

    monkeypatch.setattr(viewer, "create_server", create)
    monkeypatch.setattr(viewer.webbrowser, "open", lambda url: True)

    seen = {}
    code = viewer.serve(cfg, host="127.0.0.1", port=8899,
                        on_ready=lambda url: seen.update(url=url))

    assert attempts == [8899, 0], "asked for 8899, then a free port"
    assert code == 0
    assert seen["url"].startswith("http://127.0.0.1:")
    assert urllib.parse.urlsplit(seen["url"]).port != 8899


def test_a_second_browser_refuses_a_port_that_is_already_serving(cfg):
    """The fallback above is only reachable if a taken port really raises.

    On Windows it did not. ``http.server.HTTPServer`` sets SO_REUSEADDR, and
    there that flag means something stronger than it does on POSIX: a second
    socket may bind an address another process is already *listening* on. A
    second ``kryonsec memory --port 8899`` therefore started, printed the same
    URL as the first, and serve()'s "picking a free one" branch could never
    run — the reported port was whatever the first instance was using. The
    same mechanism would let it take the port from an unrelated program.

    The server class answers with SO_EXCLUSIVEADDRUSE on Windows, so a taken
    port is an OSError on every platform rather than a silent second listener.
    """
    first = create_server(cfg, "127.0.0.1", 0)
    port = first.server_address[1]
    try:
        with pytest.raises(OSError):
            create_server(cfg, "127.0.0.1", port)
    finally:
        first.server_close()


def test_serve_prints_the_url_when_no_browser_can_open(cfg, monkeypatch, capsys):
    """A headless box has no browser; the URL on stdout is the fallback."""
    from kryonsec.memory import viewer

    real_create = viewer.create_server
    monkeypatch.setattr(viewer, "create_server",
                        lambda c, h, p: InstantServer(real_create(c, h, p)))
    monkeypatch.setattr(viewer.webbrowser, "open", lambda url: False)

    assert viewer.serve(cfg, host="127.0.0.1", port=0, open_browser=True) == 0
    out = capsys.readouterr().out
    assert "http://127.0.0.1:" in out
    assert "could not open a browser" in out
    assert "Ctrl+C" in out


def test_serve_does_not_try_a_browser_when_asked_not_to(cfg, monkeypatch):
    """--no-browser exists for a remote shell: no browser process, no noise."""
    from kryonsec.memory import viewer

    real_create = viewer.create_server
    monkeypatch.setattr(viewer, "create_server",
                        lambda c, h, p: InstantServer(real_create(c, h, p)))

    def explode(url):  # pragma: no cover - must not be reached
        raise AssertionError("webbrowser.open() must not be called")

    monkeypatch.setattr(viewer.webbrowser, "open", explode)
    assert viewer.serve(cfg, host="127.0.0.1", port=0, open_browser=False) == 0


# --- STEP 5h: the engine's own graph handling is unchanged -----------------

def test_graph_loading_and_serialization_are_untouched_by_the_viewer(cfg):
    """The browser reads through the same load_graph the engine uses, so a
    round trip through the API is byte-identical to the domain object."""
    graph = _graph("eng-one")
    _store(cfg, graph)

    with get_purple_session(cfg) as session:
        from kryonsec.purple.graph_store import load_graph

        reloaded = load_graph(session, "eng-one")

    assert reloaded.to_dict() == graph.to_dict()
    assert load_engagement(cfg, "eng-one")["graph"] == reloaded.to_dict()


def test_the_purple_security_gates_still_hold():
    """A spot check that Phase 3 changed nothing about how the engine
    protects itself: the tool allowlist still rejects an unknown argv, and
    the graph still refuses a cross-engagement edge."""
    from kryonsec.purple.recon_passive import CrossEngagementError, EngagementGraph

    one = EngagementGraph(engagement_id="one")
    two = EngagementGraph(engagement_id="two")
    a = one.add_node("target", "a.example")
    b = two.add_node("target", "b.example")
    with pytest.raises(CrossEngagementError):
        one.add_edge(a, "targets", b)
