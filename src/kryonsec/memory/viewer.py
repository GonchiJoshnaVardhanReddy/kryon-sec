"""The memory browser's localhost server.

A read-only window onto persisted engagement memory. It is deliberately
built out of the standard library: no ASGI framework, no template engine,
no CDN — a single-user loopback viewer does not justify new dependencies,
and everything here is small enough to audit in one sitting.

Read-only is enforced structurally, not by convention
-----------------------------------------------------
There is no route that mutates anything. ``do_POST`` and friends are
answered 405 because they exist; the route table has no write entry to
reach. The data layer never runs DDL, so the viewer cannot create a
database or migrate a schema either. And nothing here imports the
orchestrator, the sandbox, the allowlist or the approval gate — the browser
has no path to a Purple Team action because it holds no reference to one.

Network posture
---------------
* **Loopback only.** A non-loopback ``--host`` is refused outright; there
  is no flag to override it. Remote access is an SSH tunnel's job, not a
  bind address's.
* **Host header checked.** Binding to loopback does not stop DNS
  rebinding: a page on ``evil.example`` can resolve its own name to
  127.0.0.1 and have the browser send *your* requests there with *its*
  Host. Only loopback hostnames are accepted.
* **No CORS header, strict CSP.** Nothing cross-origin can read a
  response, and the page itself can load nothing off this machine — which
  matters for a tool whose whole premise is that engagement data does not
  leave it.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..config import KryonsecConfig
from ..engagement_id import is_valid_engagement_id
from . import data

log = logging.getLogger(__name__)

__all__ = ["create_server", "is_loopback_host", "serve"]

STATIC_DIR = Path(__file__).resolve().parent / "static"

# The only hostnames this server answers to. `localhost` is included so the
# printed URL works if a system resolves it, but the bind address is always
# numeric loopback.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Fixed table: the request path selects a key, never a filename. Every asset
# the page can reach is listed here, so a request cannot name a file that is
# not on this list — no traversal, no new routes appearing at runtime.
#
# The fonts are the landing page's own two faces (Press Start 2P and VT323),
# bundled under their OFL licences instead of linked from Google Fonts: the
# CSP below allows nothing off this origin, and a memory browser should work
# on a machine with no network — or none it is willing to talk to.
_STATIC_ROUTES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/theme-init.js": ("theme-init.js", "text/javascript; charset=utf-8"),
    "/static/assets/mark.svg": ("assets/mark.svg", "image/svg+xml"),
    "/static/fonts/press-start-2p-latin.woff2":
        ("fonts/press-start-2p-latin.woff2", "font/woff2"),
    "/static/fonts/vt323-latin.woff2": ("fonts/vt323-latin.woff2", "font/woff2"),
}

_ENGAGEMENT_ROUTE = re.compile(r"^/api/engagements/([^/]+)$")

_SECURITY_HEADERS = {
    # The page is self-contained: no CDN script, no external font, nothing to
    # call home. `default-src 'none'` makes that a rule rather than a promise;
    # font-src and img-src carve out only our own bundled assets.
    "Content-Security-Policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def is_loopback_host(host: str) -> bool:
    """True only for a loopback bind address."""
    return host in _LOOPBACK_HOSTS


def _host_header_ok(host_header: str) -> bool:
    """Validate a Host header against the loopback allowlist.

    Handles ``127.0.0.1:8899`` and the bracketed IPv6 form ``[::1]:8899``.
    A missing Host is rejected: HTTP/1.1 requires one.
    """
    value = (host_header or "").strip().lower()
    if not value:
        return False
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return False
        return value[1:end] in _LOOPBACK_HOSTS
    hostname = value.rsplit(":", 1)[0] if ":" in value else value
    return hostname in _LOOPBACK_HOSTS


class MemoryRequestHandler(BaseHTTPRequestHandler):
    """Routes for the memory browser. Every route is read-only."""

    server_version = "kryonsec-memory"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # A stalled client must not pin a worker thread forever. Idle keep-alive
    # connections are dropped after this many seconds.
    timeout = 30

    # ---- methods: read-only, explicitly ----

    def do_GET(self) -> None:          # noqa: N802 - http.server's API
        self._dispatch(head_only=False)

    def do_HEAD(self) -> None:         # noqa: N802
        self._dispatch(head_only=True)

    def do_POST(self) -> None:         # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:          # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:        # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:       # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:      # noqa: N802
        self._method_not_allowed()

    # ---- routing ----

    def _dispatch(self, *, head_only: bool) -> None:
        if not _host_header_ok(self.headers.get("Host", "")):
            self._discard_request_body()
            self._json_error(403, "forbidden_host",
                             "this server only answers requests addressed to "
                             "loopback")
            return

        self._discard_request_body()
        path = urlparse(self.path).path

        if path in _STATIC_ROUTES:
            self._serve_static(path, head_only=head_only)
            return

        if path == "/api/health":
            self._api_health(head_only=head_only)
            return

        if path == "/api/engagements":
            self._api_engagements(head_only=head_only)
            return

        match = _ENGAGEMENT_ROUTE.match(path)
        if match:
            self._api_engagement(unquote(match.group(1)), head_only=head_only)
            return

        self._json_error(404, "not_found", f"no such route: {path}")

    # ---- endpoints ----

    def _api_health(self, *, head_only: bool) -> None:
        cfg = self._cfg
        status = data.storage_status(cfg)
        self._send_json(200, {
            "ok": True,
            "storage": status,
            "read_only": True,
        }, head_only=head_only)

    def _api_engagements(self, *, head_only: bool) -> None:
        cfg = self._cfg
        status = data.storage_status(cfg)
        engagements, redactions = data.scrub(data.list_engagements(cfg))
        self._send_json(200, {
            "storage": status,
            "engagements": engagements,
            "redactions": redactions,
        }, head_only=head_only)

    def _api_engagement(self, engagement_id: str, *, head_only: bool) -> None:
        # Validated before it reaches a path, a query or anything else.
        if not is_valid_engagement_id(engagement_id):
            self._json_error(
                400, "invalid_engagement_id",
                "engagement ids are 1-64 characters of letters, digits, "
                "dot, dash or underscore",
            )
            return

        try:
            payload = data.load_engagement(self._cfg, engagement_id)
        except data.MemoryUnavailable as exc:
            self._json_error(503, "storage_unavailable", str(exc))
            return
        except Exception:
            # A malformed row (an edge whose node is gone) or a database
            # that changed under us. The detail goes to the local log, not
            # into the response: an exception string can quote a connection
            # URL, and the browser does not need it to render the failure.
            log.exception("memory: failed to load engagement %s", engagement_id)
            self._json_error(
                500, "graph_unreadable",
                "this engagement's stored graph could not be read — see the "
                "Kryonsec log for details",
            )
            return

        body, redactions = data.scrub(payload)
        body["redactions"] = redactions
        self._send_json(200, body, head_only=head_only)

    # ---- responses ----

    @property
    def _cfg(self) -> KryonsecConfig:
        return self.server.cfg  # type: ignore[attr-defined]

    def _method_not_allowed(self) -> None:
        # Any method but GET/HEAD may arrive with a body this server never
        # reads. Draining it first is what lets the refusal be delivered at
        # all (see _discard_request_body); closing the connection is what
        # keeps a body from being parsed as the next request line.
        self._discard_request_body()
        self._json_error(405, "read_only",
                         "the memory browser is read-only",
                         allow="GET, HEAD", close=True)

    # Bodies are never used, but they still have to leave the socket buffer.
    # Bounded: the point is to leave nothing unread, not to accept an upload.
    _MAX_DRAIN_BYTES = 65536

    def _discard_request_body(self) -> None:
        """Consume and throw away the request body.

        Two reasons, both discovered by a test rather than by reasoning:

        * On a keep-alive connection an unread body is read as the next
          request line, so a refused POST's ``{}`` becomes a malformed
          request and the connection wedges.
        * On Windows, closing a socket that still holds unread data sends an
          RST instead of a FIN — and the RST can arrive before the client has
          read the response, so a clean 405 surfaces as a connection abort.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        remaining = min(max(length, 0), self._MAX_DRAIN_BYTES)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 8192))
            if not chunk:
                break
            remaining -= len(chunk)

    def _serve_static(self, path: str, *, head_only: bool) -> None:
        filename, content_type = _STATIC_ROUTES[path]
        try:
            body = (STATIC_DIR / filename).read_bytes()
        except OSError:
            log.exception("memory: static asset missing: %s", filename)
            self._json_error(500, "asset_missing",
                             "a bundled asset is missing — reinstall kryonsec")
            return
        self._send(200, body, content_type, head_only=head_only)

    def _json_error(self, code: int, kind: str, message: str, *,
                    allow: str | None = None, close: bool = False) -> None:
        body = json.dumps(
            {"error": {"code": kind, "message": message}},
            separators=(",", ":"),
        ).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8",
                   allow=allow, close=close)

    def _send_json(self, code: int, payload: Any, *, head_only: bool) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8",
                   head_only=head_only)

    def _send(self, code: int, body: bytes, content_type: str,
              *, head_only: bool = False, allow: str | None = None,
              close: bool = False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if allow is not None:
            self.send_header("Allow", allow)
        if close:
            # send_header special-cases this: it also sets close_connection,
            # so the connection is not reused. The header just says so.
            self.send_header("Connection", "close")
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        # BaseHTTPRequestHandler writes to stderr by default, which would
        # garble the URL line this command prints. Route it to the logger.
        log.debug("memory: %s", fmt % args)


class _MemoryHTTPServer(ThreadingHTTPServer):
    """A server that refuses to share a port it does not own.

    ``http.server.HTTPServer`` sets ``allow_reuse_address``, which on POSIX
    only means "a socket left in TIME_WAIT is not a reason to refuse". On
    Windows SO_REUSEADDR means something else entirely: a *second* socket may
    bind an address another process is already listening on. That is how this
    was found — a second ``kryonsec memory --port 8899`` started happily,
    printed the same URL as the first, and the "picking a free one" branch in
    :func:`serve` could never run. Worse, it would have done the same to a
    *different* program that happened to hold the port.

    Not setting the flag is what fixes it: with SO_REUSEADDR unset the second
    bind is refused on Windows as well as on POSIX, so a taken port raises
    OSError and the caller's fallback is reachable rather than decorative.
    The trade is that a restart immediately after a stop may find the port in
    TIME_WAIT and move to another one — which it announces, and which is a
    smaller surprise than silently listening on someone else's port.

    No socket import is needed for this, which keeps the package's import
    allowlist (tests/test_memory.py) as tight as it was.
    """

    allow_reuse_address = False
    daemon_threads = True


def create_server(cfg: KryonsecConfig, host: str = "127.0.0.1",
                  port: int = 0) -> ThreadingHTTPServer:
    """Build (but do not start) the memory browser's server.

    Raises ValueError for a non-loopback host, OSError if the port is taken.
    """
    if not is_loopback_host(host):
        raise ValueError(
            f"refusing to bind {host!r}: the memory browser is loopback-only "
            "(use an SSH tunnel for remote access)"
        )
    server = _MemoryHTTPServer((host, port), MemoryRequestHandler)
    server.cfg = cfg  # type: ignore[attr-defined]
    return server


def serve(cfg: KryonsecConfig, *, host: str = "127.0.0.1", port: int = 8899,
          open_browser: bool = True, on_ready=None) -> int:
    """Run the memory browser until interrupted. Returns a process exit code."""
    try:
        server = create_server(cfg, host, port)
    except ValueError as exc:
        log.error("%s", exc)
        print(f"kryonsec memory: {exc}")
        return 2
    except OSError:
        if port == 0:
            raise
        print(f"kryonsec memory: port {port} is in use — picking a free one")
        server = create_server(cfg, host, 0)

    bound_port = server.server_address[1]
    url = f"http://{host}:{bound_port}/"
    print(f"kryonsec memory — read-only engagement browser\n  {url}\n"
          "  loopback only; press Ctrl+C to stop")

    if on_ready is not None:
        on_ready(url)

    if open_browser:
        # Best effort: a headless box has no browser, and the URL above is
        # the fallback. webbrowser.open returns False rather than raising in
        # the common case, so both are handled.
        try:
            opened = webbrowser.open(url)
        except Exception:  # pragma: no cover - platform browser glue
            opened = False
        if not opened:
            print("  (could not open a browser automatically — open the URL above)")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        print("\nkryonsec memory: stopped")
    finally:
        server.shutdown()
        server.server_close()
    return 0
