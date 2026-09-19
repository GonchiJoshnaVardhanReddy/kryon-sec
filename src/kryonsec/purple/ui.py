"""Purple Team console: one live panel instead of a scrolling log.

Presentation only. Nothing in here decides anything, and no subagent imports
it — the console learns what is happening from two existing streams:

- the orchestrator's per-state callback (which state is running), and
- the audit log (which tool is running), via ``AuditLog.add_observer``.

That second one is the reason this module can exist without touching the
security engine: every tool execution in every Zone A and Zone B subagent is
already bracketed by a ``tool_spawn`` / ``tool_result`` audit pair, so the
append-only audit chain doubles as a structured event stream. The console is
just a second reader of it.

Three rules shape the rendering:

1. **Say only what is known.** A percentage of "work done" is not knowable —
   stage 3 of 10 is. The bar is labelled with the stage count so it cannot be
   misread as completion.
2. **The current tool is the loudest thing on screen.** Completed tools stay
   as compact history; pending ones stay quiet.
3. **Failures are summarised, never dumped.** A 403 from a free public API is
   routine. ``on_log`` renders one line and drops the traceback; the full
   record goes to the engagement's debug.log (see ``PurpleLogHandler``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .orchestrator import STATES

# ---- vocabulary ---------------------------------------------------------

# Plain-English action per state. Shown in the pipeline and the current-
# operation panel, so the operator never has to read a state name like
# RECON_PASSIVE and translate it.
STATE_ACTION: dict[str, str] = {
    "INIT": "Validating scope and authorization",
    "RECON_PASSIVE": "Collecting external intelligence",
    "RECON_ACTIVE": "Mapping reachable services",
    "HYPOTHESIZE": "Generating vulnerability hypotheses",
    "HUMAN_REVIEW": "Waiting for operator approval",
    "EXPLOIT": "Testing approved hypotheses",
    "POST_EXPLOIT": "Enumerating approved access",
    "VERIFY": "Independently confirming findings",
    "BLUE_TEAM": "Generating remediation guidance",
    "REPORT": "Compiling evidence and report",
}

# Short label for the pipeline. STATE_ACTION is a sentence and does not fit
# on a 10-item row.
STATE_LABEL: dict[str, str] = {
    "INIT": "INIT",
    "RECON_PASSIVE": "PASSIVE RECON",
    "RECON_ACTIVE": "ACTIVE RECON",
    "HYPOTHESIZE": "HYPOTHESIZE",
    "HUMAN_REVIEW": "HUMAN REVIEW",
    "EXPLOIT": "EXPLOIT",
    "POST_EXPLOIT": "POST-EXPLOIT",
    "VERIFY": "VERIFY",
    "BLUE_TEAM": "BLUE TEAM",
    "REPORT": "REPORT",
}

# What each tool does, for the activity table. Names are kept as well —
# an operator recognises `nmap`, and hiding it would be worse than showing
# a slightly technical word. Unknown tools fall through to the name alone.
TOOL_ACTION: dict[str, str] = {
    # passive recon (Zone A)
    "crt_sh_subdomains": "Certificate transparency search",
    "wayback_subdomains": "Historical URL discovery",
    "otx_passive_dns": "Passive DNS lookup",
    "ripestat_whois": "Registry whois",
    "ripestat_asn": "ASN and prefix lookup",
    "rdap_whois": "RDAP registration data",
    "github_recon": "Code and secret search",
    "hackertarget_hostsearch": "DNS history lookup",
    "shodan_subdomains": "External intelligence",
    "censys_subdomains": "Internet-wide scan data",
    "cloud_asset_notes": "Cloud asset analysis",
    "sandbox_passive": "Sandbox passive enumeration",
    "subfinder": "Passive subdomain enumeration",
    "amass": "Passive subdomain enumeration",
    "assetfinder": "Passive subdomain enumeration",
    # active recon and beyond (Zone B)
    "nmap": "Port and service scan",
    "naabu": "Port discovery",
    "dnsx": "DNS resolution",
    "httpx": "HTTP service discovery",
    "whatweb": "Technology fingerprinting",
    "katana": "Web crawling",
    "feroxbuster": "Content discovery",
    "openapi_probe": "API specification discovery",
    "gowitness": "Screenshot capture",
    "sslscan": "TLS configuration scan",
    "testssl.sh": "TLS configuration scan",
    "sqlmap": "SQL injection testing",
    "nuclei": "Vulnerability template scan",
    "nikto": "Web server scan",
    "ffuf": "Content fuzzing",
    "gobuster": "Content discovery",
    "wfuzz": "Content fuzzing",
    "curl": "HTTP request",
    "wget": "HTTP request",
    "dalfox": "XSS testing",
    "commix": "Command injection testing",
    "ssrfmap": "SSRF testing",
    "arjun": "Parameter discovery",
    "tplmap": "Template injection testing",
    "graphql-cop": "GraphQL security audit",
    # post-exploit, verify, blue team, enrichment
    "linpeas": "Local privilege escalation survey",
    "pspy": "Process monitoring",
    "linux-exploit-suggester": "Kernel exploit matching",
    "semgrep": "Static analysis",
    "bandit": "Python security analysis",
    "gitleaks": "Secret detection",
    "trivy": "Dependency and config scan",
    "checkov": "Infrastructure-as-code scan",
    "hadolint": "Dockerfile lint",
    "syft": "Software bill of materials",
    "osv-scanner": "Dependency vulnerability scan",
    "grype": "Dependency vulnerability scan",
    "searchsploit": "Exploit database lookup",
    "nuclei_meta": "Template metadata lookup",
}

# Log messages that are routine, mapped to one short line. These are the
# free public APIs answering 429/403/404 — expected, not actionable, and
# certainly not worth a traceback. Anything not listed still renders, using
# the logger's own words minus the noise.
LOG_NOTICES: dict[str, str] = {
    "otx passive dns query failed": "Passive DNS lookup failed",
    "ripestat whois query failed": "Registry whois failed",
    "ripestat dns-chain query failed": "DNS chain lookup failed",
    "wayback cdx query failed": "Historical URL lookup failed",
    "shodan dns/domain query failed": "External intelligence failed",
    "censys hosts search failed": "Internet scan data failed",
    "rdap bootstrap fetch failed": "RDAP directory fetch failed",
    "rdap query failed": "Registration lookup failed",
    # Safety-relevant, so it stays — but as a statement of fact rather than
    # a paragraph. The full sentence, with the KRYONSEC_SANDBOX_IMAGE
    # instructions, is in the debug log.
    "is not digest-pinned": "Sandbox image is not digest-pinned (tag is mutable)",
}

# Fallback wording when the message is not in LOG_NOTICES. Matched on a
# substring, longest first, because log messages carry varying suffixes.
_CONTINUING = "continuing"


# Display name per tool. The audit log records Zone A sources by their
# Python function name (`crt_sh_subdomains`), which is an implementation
# detail the operator should never have to read. Only names that actually
# appear in the audit stream need an entry; anything unmapped renders as-is
# rather than being hidden, because a tool the operator cannot see is worse
# than one with an ugly name.
TOOL_LABEL: dict[str, str] = {
    "crt_sh_subdomains": "crt.sh",
    "wayback_subdomains": "Wayback",
    "otx_passive_dns": "OTX",
    "ripestat_whois": "RIPEstat",
    "ripestat_asn": "RIPEstat ASN",
    "rdap_whois": "RDAP",
    "github_recon": "GitHub",
    "hackertarget_hostsearch": "HackerTarget",
    "shodan_subdomains": "Shodan",
    "censys_subdomains": "Censys",
    "cloud_asset_notes": "Cloud assets",
    "sandbox_passive": "sandbox passive",
    "nuclei_meta": "nuclei templates",
    "testssl.sh": "testssl.sh",
}


def tool_label(tool: str) -> str:
    """The name to show an operator. Never empty, never raises."""
    if not tool:
        return ""
    return TOOL_LABEL.get(tool, tool)


def tool_action(tool: str) -> str:
    """What a tool does, in plain words. Never empty, never raises."""
    if not tool:
        return ""
    return TOOL_ACTION.get(tool, tool.replace("_", " "))


def state_action(state: str) -> str:
    return STATE_ACTION.get(state, state.replace("_", " ").title())


def notice_for(message: str) -> str:
    """A log message as a short operator-facing notice.

    Falls back to the message itself, stripped of any trailing target so
    the common case stays readable. Never returns a traceback, because it
    is only ever given ``record.getMessage()``.
    """
    text = (message or "").strip()
    lowered = text.lower()
    for needle, friendly in LOG_NOTICES.items():
        if needle in lowered:
            return f"{friendly} — {_CONTINUING}"
    return text or "unknown warning"


# ---- events -------------------------------------------------------------

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
SKIPPED = "skipped"
FAILED = "failed"

# How many finished tools stay on screen. Long enough to see the shape of
# the stage, short enough that the panel does not scroll away.
TOOL_HISTORY = 12


@dataclass
class PurpleToolEvent:
    """One tool, as the console understands it.

    The security engine may emit these (through the audit log); the renderer
    owns their presentation. ``status`` is one of QUEUED, RUNNING, COMPLETED,
    SKIPPED, FAILED.
    """

    state: str
    tool: str
    status: str
    action: str = ""
    started_at: float | None = None
    duration: float | None = None
    result_summary: str | None = None
    error_summary: str | None = None

    def __post_init__(self) -> None:
        if not self.action:
            self.action = tool_action(self.tool)

    @property
    def settled(self) -> bool:
        return self.status in (COMPLETED, SKIPPED, FAILED)


# ---- colour / glyph language -------------------------------------------

# Legacy code-page consoles (cp1252) raise UnicodeEncodeError on box
# drawing — mid-engagement, which is worse than at startup. Two sets, picked
# once per console the same way cli.py picks its banner. Colors are the same
# either way; only the marks change.
#
# Rich covers the panel borders itself, but only when it recognises the
# console as legacy (``legacy_windows``, which is Windows-without-Windows-
# Terminal). A cp1252 locale on Linux/WSL is not recognised, so the glyph set
# alone is not enough there — the ASCII set therefore also switches the panel
# box, which is why the two travel together in ``_Frame``.
GLYPHS_UTF8: dict[str, str] = {
    "done": "✓", "active": "◉", "pending": "○", "warn": "⚠",
    "bar_full": "█", "bar_empty": "░", "dot": "●",
}
GLYPHS_ASCII: dict[str, str] = {
    "done": "+", "active": ">", "pending": ".", "warn": "!",
    "bar_full": "#", "bar_empty": "-", "dot": "*",
}

STYLE_DONE = "green"
STYLE_ACTIVE = "bold cyan"
STYLE_PENDING = "dim"
STYLE_FAIL = "red"
STYLE_WARN = "yellow"
STYLE_PURPLE = "magenta"

_STATUS_STYLE = {
    COMPLETED: STYLE_DONE,
    RUNNING: STYLE_ACTIVE,
    SKIPPED: STYLE_PENDING,
    FAILED: STYLE_FAIL,
    QUEUED: STYLE_PENDING,
}

# status -> the glyph key it draws
_STATUS_GLYPH_KEY = {
    COMPLETED: "done",
    RUNNING: "active",
    SKIPPED: "pending",
    FAILED: "warn",
    QUEUED: "pending",
}


def _utf8_ok(console: Any, explicit: bool | None) -> bool:
    """Can this console encode the box-drawing glyphs?

    Follows cli.py's rule: probe the stream, and let the caller override.
    An unprobeable console defaults to ASCII — a plain-looking panel beats
    a crash mid-engagement.
    """
    if explicit is not None:
        return explicit
    stream = getattr(console, "file", None)
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        "✓◉○⚠█░".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _clock(seconds: float | None) -> str:
    """mm:ss, or h:mm:ss past an hour. '' when there is nothing to show."""
    if seconds is None or seconds < 0:
        return ""
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


# How wide the dashboard is allowed to get. Wider than this and the panels
# are mostly empty space with content stranded at the left edge; the cap is
# what keeps a 200-column terminal looking deliberate rather than stretched.
DASHBOARD_MAX_WIDTH = 100

# Below these widths a column is dropped rather than crushed to an ellipsis.
# The numbers are the point at which the remaining columns still show their
# own content: below 64 the Action column would steal the tool's own name.
_WIDTH_FOR_ACTION = 64
_WIDTH_FOR_RESULT = 80


def _console_width(console: Any) -> int:
    """The console's width, never raising. 80 is rich's own default."""
    try:
        width = int(console.width)
    except Exception:  # pragma: no cover - exotic console
        return 80
    return width if width > 0 else 80


class _Frame:
    """The one place panel geometry is decided.

    Two problems this solves, both of which showed up as misaligned panels:

    - **Consistent width.** ``Panel(expand=False)`` hugs its content, so the
      header boxed itself at 27 columns while the tool table filled 100 and
      the dashboard looked like four unrelated widgets. Every panel is now
      given the same explicit width.
    - **Honest ASCII.** ``box`` travels with the glyph set, so a console that
      cannot encode ``✓`` also does not get ``┌`` from rich. Passing the
      glyph set alone left the borders to rich's own legacy-Windows
      detection, which does not fire for a cp1252 locale on Linux.
    """

    def __init__(self, console: Any, utf8: bool) -> None:
        self.width = min(_console_width(console), DASHBOARD_MAX_WIDTH)
        self.box = box.ROUNDED if utf8 else box.ASCII

    def panel(self, renderable: Any, **kw: Any) -> Panel:
        # expand=True is what makes `width` authoritative. With expand=False
        # rich measures the content and sizes the box to it — `width` only
        # caps the measurement — so the header boxed itself at 29 columns
        # while the tool table filled 90 and the dashboard looked like four
        # unrelated widgets. With expand=True, `width` fixes the box and the
        # min() inside rich still shrinks it on a narrow terminal.
        return Panel(renderable, box=self.box, width=self.width,
                     expand=True, **kw)


class PurpleUI:
    """Owns the live console for one engagement.

    Lifecycle: construct, ``start()``, feed it events, ``stop()``. Feeding
    it is safe at any time — every entry point is defensive, because a
    rendering bug must never be able to fail an engagement.
    """

    def __init__(
        self,
        console: Any,
        target: str,
        engagement_id: str,
        graph: Any = None,
        clock=time.monotonic,
        utf8: bool | None = None,
    ) -> None:
        self.console = console
        self.target = target
        self.engagement_id = engagement_id
        # Read for live counters. Optional: the console works without it,
        # just showing no counts.
        self.graph = graph
        self._clock = clock
        self.glyphs = GLYPHS_UTF8 if _utf8_ok(console, utf8) else GLYPHS_ASCII
        self.frame = _Frame(console, self.glyphs is GLYPHS_UTF8)
        self.started_at = clock()
        self.current_state = ""
        self.completed_states: list[str] = []
        # Ordered oldest-first; the table renders the tail.
        self.tools: list[PurpleToolEvent] = []
        self._running: dict[str, PurpleToolEvent] = {}
        self.notices: list[str] = []
        self.errors = 0
        self._live: Live | None = None
        self._live_wanted = False
        # No terminal, no live region. A piped or CI run still has to be
        # observable, so on_state falls back to one line per state rather
        # than going silent for the length of the engagement.
        self._terminal = bool(getattr(console, "is_terminal", False))

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> None:
        self._live_wanted = True
        self._start_live()

    def stop(self) -> None:
        self._live_wanted = False
        self._stop_live()

    def _start_live(self) -> None:
        # Non-TTY (pipes, CI, tests): no Live at all. rich would emit
        # control codes into a captured stream and garble test output.
        if self._live is not None or not getattr(
            self.console, "is_terminal", False
        ):
            return
        try:
            self._live = Live(
                self.render(), console=self.console,
                refresh_per_second=8, transient=False,
            )
            self._live.start()
        except Exception:  # pragma: no cover - a terminal we cannot drive
            self._live = None

    def _stop_live(self) -> None:
        if self._live is None:
            return
        try:
            self._live.stop()
        except Exception:  # pragma: no cover
            pass
        self._live = None

    def _refresh(self) -> None:
        if self._live is None:
            return
        try:
            self._live.update(self.render())
        except Exception:  # pragma: no cover - never fail a run over paint
            pass

    def pause(self) -> None:
        """Give the terminal back — an approval prompt is about to run."""
        self._stop_live()

    def resume(self) -> None:
        if self._live_wanted:
            self._start_live()

    # ---- incoming events -------------------------------------------------

    def on_state(self, state: str) -> None:
        """A state is about to run.

        Fired by the orchestrator's progress callback, which happens before
        the state's subagent is built — so pausing here is what keeps the
        Live region from fighting the HUMAN_REVIEW prompt for the terminal.
        """
        if self.current_state and self.current_state != state:
            if self.current_state not in self.completed_states:
                self.completed_states.append(self.current_state)
        self.current_state = state

        if state == "HUMAN_REVIEW":
            self.pause()
            if not self._terminal:
                self._state_line(state)
            return
        if not self._terminal:
            # Piped output: no live region is possible, and printing nothing
            # for a ten-minute engagement is worse than ten lines. One line
            # per state, carrying what the panel would have shown.
            self._state_line(state)
            return
        self.resume()
        self._refresh()

    def _state_line(self, state: str) -> None:
        try:
            self.console.print(
                f"[magenta]{STATE_LABEL.get(state, state)}[/magenta]  "
                f"[dim]{state_action(state)}[/dim]")
        except Exception:  # pragma: no cover - never fail a run over paint
            pass

    def on_audit(self, entry: dict) -> None:
        """Translate one audit entry into tool activity.

        Defensive by contract: this is called from inside AuditLog.write
        while it holds its lock, so anything raised here would surface as a
        mysterious failure elsewhere. Every field is read with a default.
        """
        try:
            self._handle_audit(entry)
        except Exception:  # pragma: no cover - never fail a run over paint
            pass

    def _handle_audit(self, entry: dict) -> None:
        event = entry.get("event")
        state = self.current_state

        if event == "tool_spawn":
            self._begin(entry.get("tool", ""), state)
        elif event == "tool_result":
            self._finish(
                entry.get("tool", ""),
                ok=bool(entry.get("ok")),
                error=entry.get("error") or "",
                summary=self._result_summary(entry),
            )
        elif event == "passive_source_start":
            self._begin(entry.get("source", ""), state)
        elif event == "passive_source_ok":
            self._finish(
                entry.get("source", ""), ok=True,
                error="",
                summary=self._source_summary(entry),
            )
        elif event == "passive_source_failed":
            self._finish(
                entry.get("source", ""), ok=False,
                error=str(entry.get("error") or "")[:120], summary=None,
            )
        elif event == "passive_source_skipped":
            self._skip(entry.get("source", ""),
                       str(entry.get("reason") or "")[:120])
        elif event.endswith("_rejected_by_allowlist") or (
                event == "scanner_rejected_by_allowlist"):
            self._skip(entry.get("tool", ""), "rejected by allowlist")
        elif event == "zone_b_blocked":
            self.on_notice(
                f"Zone B blocked — {entry.get('reason', 'sandbox unavailable')}")

        self._refresh()

    def _result_summary(self, entry: dict) -> str | None:
        if not entry.get("ok"):
            return None
        chars = entry.get("output_chars")
        if isinstance(chars, int) and chars > 0:
            return f"{chars} chars"
        return None

    def _source_summary(self, entry: dict) -> str | None:
        new = entry.get("new")
        found = entry.get("found")
        if isinstance(new, int) and new:
            return f"{new} new"
        if isinstance(found, int) and found:
            return f"{found} found"
        return None

    def _begin(self, tool: str, state: str) -> None:
        if not tool:
            return
        event = PurpleToolEvent(
            state=state, tool=tool, status=RUNNING,
            started_at=self._clock(),
        )
        # A tool re-spawned in the same state (exploit retries curl over
        # https) replaces its row rather than adding a second one — the
        # audit log has one result for it, so the table must too.
        self._running[tool] = event
        self.tools = [t for t in self.tools if not (
            t.tool == tool and t.state == state and not t.settled
        )]
        self.tools.append(event)

    def _finish(self, tool: str, *, ok: bool, error: str,
                summary: str | None) -> None:
        if not tool:
            return
        event = self._take(tool)
        if event.started_at is not None:
            event.duration = max(0.0, self._clock() - event.started_at)
        event.status = COMPLETED if ok else FAILED
        event.result_summary = summary
        if not ok:
            event.error_summary = error or "failed"
            self.errors += 1

    def _skip(self, tool: str, reason: str) -> None:
        if not tool:
            return
        event = self._take(tool)
        event.status = SKIPPED
        event.result_summary = reason or None

    def _take(self, tool: str) -> PurpleToolEvent:
        """The running row for `tool`, or a fresh one if we never saw it start.

        Taking rather than appending is what keeps one tool to one row. A
        skipped source used to leave its own 'running' row on screen forever
        — the source list showed Shodan twice, once running and once
        skipped, and the running one never went away.
        """
        event = self._running.pop(tool, None)
        if event is not None:
            return event
        event = PurpleToolEvent(state=self.current_state, tool=tool,
                                status=RUNNING)
        self.tools.append(event)
        return event

    def on_notice(self, message: str) -> None:
        """One concise line about something that did not go to plan."""
        text = (message or "").strip()
        if not text:
            return
        self.notices.append(text)
        self._refresh()

    def on_log(self, record: logging.LogRecord) -> None:
        """A log record, rendered as one line.

        ``record.getMessage()`` only — never ``exc_info``, never
        ``record.exc_text``. The traceback is not lost: PurpleLogHandler
        sends the untouched record to the engagement's debug.log. This is
        the whole point of the separation, so do not "improve" it by
        appending exception detail.
        """
        if record.levelno < logging.WARNING:
            return
        logger = record.name.rsplit(".", 1)[-1]
        self.on_notice(f"{logger}: {notice_for(record.getMessage())}")

    # ---- counters --------------------------------------------------------

    def counts(self) -> dict[str, int]:
        """Live totals, straight from the engagement graph.

        Read fresh on every render rather than tallied from events, so the
        numbers cannot drift from what the engagement actually found.
        """
        counts = {
            "subdomains": 0, "endpoints": 0, "technologies": 0,
            "hypotheses": 0, "findings": 0, "errors": self.errors,
        }
        graph = self.graph
        if graph is None:
            return counts
        try:
            counts["subdomains"] = len(graph.by_type("subdomain"))
            counts["endpoints"] = (
                len(graph.by_type("web_endpoint")) + len(graph.by_type("path"))
            )
            counts["technologies"] = len(graph.by_type("tech_fingerprint"))
            counts["hypotheses"] = len(graph.by_type("hypothesis"))
            counts["findings"] = len(graph.by_type("finding"))
        except Exception:  # pragma: no cover - graph is ours, be safe anyway
            pass
        return counts

    # ---- rendering -------------------------------------------------------

    def stage_number(self) -> int:
        """1-based stage index, or 0 before the loop starts."""
        if self.current_state in STATES:
            return STATES.index(self.current_state) + 1
        return 0

    def render(self) -> Group:
        return Group(
            self._header(),
            Text(""),
            self._pipeline(),
            Text(""),
            self._current_operation(),
            Text(""),
            self._tools_table(),
            Text(""),
            self._counters(),
            Text(""),
            self._progress(),
        )

    def _header(self) -> Panel:
        elapsed = _clock(self._clock() - self.started_at)
        table = Table.grid(padding=(0, 2))
        table.add_column(style=STYLE_PENDING, justify="right")
        table.add_column()
        table.add_row("Target", f"[bold]{self.target}[/bold]")
        table.add_row("Engagement", self.engagement_id)
        table.add_row("Elapsed", elapsed)
        dot = self.glyphs["dot"]
        status = (f"[bold cyan]{dot} RUNNING[/bold cyan]"
                  if self._live is not None
                  else f"[dim]{dot} STOPPED[/dim]")
        return self.frame.panel(
            table, title="[bold magenta]KRYONSEC PURPLE TEAM[/bold magenta]",
            subtitle=status, border_style=STYLE_PURPLE,
        )

    def _pipeline(self) -> Panel:
        """The 10 states, marked from the orchestrator's own list.

        ✓ done, ◉ running, ○ not yet reached — a vertical list rather than
        a horizontal one, because 10 labels do not fit across a narrow
        terminal and a wrapped pipeline is unreadable.
        """
        parts: list[str] = []
        for state in STATES:
            label = STATE_LABEL.get(state, state)
            if state == self.current_state:
                mark = self.glyphs["active"]
                parts.append(f"[{STYLE_ACTIVE}]{mark} {label}[/{STYLE_ACTIVE}]")
            elif state in self.completed_states:
                mark = self.glyphs["done"]
                parts.append(f"[{STYLE_DONE}]{mark} {label}[/{STYLE_DONE}]")
            else:
                mark = self.glyphs["pending"]
                parts.append(f"[{STYLE_PENDING}]{mark} {label}[/{STYLE_PENDING}]")
        return self.frame.panel(
            Text.from_markup("\n".join(parts)),
            title="[bold]ENGAGEMENT PIPELINE[/bold]",
            border_style="dim",
        )

    def _current_operation(self) -> Panel:
        state = self.current_state
        action = state_action(state) if state else "starting"
        running = [t for t in self.tools if t.status == RUNNING]

        lines = Text()
        lines.append(f"{action}\n", style="bold white")
        lines.append("\n")

        if running:
            event = running[-1]
            lines.append(f"{self.glyphs['active']} ", style=STYLE_ACTIVE)
            lines.append(f"{tool_label(event.tool)}\n", style="bold cyan")
            lines.append(f"   {event.action}\n", style="dim")
        else:
            lines.append(
                f"{self.glyphs['active']} "
                f"{STATE_LABEL.get(state, state) or 'idle'}\n",
                style=STYLE_ACTIVE)
            lines.append("   working\n", style="dim")

        started = running[-1].started_at if running else self.started_at
        elapsed = _clock(self._clock() - started) if started else ""
        lines.append("\n")
        lines.append(f"State     {STATE_LABEL.get(state, state) or '—'}\n",
                     style="dim")
        lines.append(f"Target    {self.target}\n", style="dim")
        lines.append(f"Running   {elapsed}", style="dim")

        return self.frame.panel(
            lines, title="[bold cyan]CURRENT OPERATION[/bold cyan]",
            border_style="cyan",
        )

    def _tools_table(self) -> Panel:
        # Columns are dropped, not crushed, as the terminal narrows. At 60
        # columns an Action column would take the width the tool's own name
        # needs, and a table of four ellipses tells the operator nothing —
        # so Result goes first, then Action, leaving name and time, which are
        # the two facts that survive any width.
        #
        # expand=True so the columns share the panel's width instead of each
        # sizing to its longest cell — without it the Action column wraps to
        # three lines and the table becomes the wall of text this redesign
        # exists to remove.
        width = self.frame.width
        show_action = width >= _WIDTH_FOR_ACTION
        show_result = width >= _WIDTH_FOR_RESULT

        table = Table(
            box=None, padding=(0, 2, 0, 0), expand=True,
            show_header=True, header_style="bold dim",
        )
        table.add_column("", width=1)
        table.add_column("Tool", width=18, no_wrap=True, overflow="ellipsis")
        if show_action:
            table.add_column("Action", ratio=3, no_wrap=True,
                             overflow="ellipsis")
        table.add_column("Time", justify="right", width=7, no_wrap=True)
        if show_result:
            table.add_column("Result", ratio=2, no_wrap=True,
                             overflow="ellipsis")

        rows = self._visible_tools()
        if not rows:
            # A plain line, not a table row: rich cannot span a cell across
            # columns, so putting this in the Tool column truncated it to
            # "no tool activ…" — which reads as a tool by that name. With
            # nothing to list, the header row is noise anyway.
            return self.frame.panel(
                Text("no tool activity yet", style="dim"),
                title="[bold]TOOL ACTIVITY[/bold]", border_style="dim",
            )
        for event in rows:
            glyph = self.glyphs[_STATUS_GLYPH_KEY.get(event.status, "pending")]
            style = _STATUS_STYLE.get(event.status, "")
            if event.duration is not None:
                when = _clock(event.duration)
            elif event.status == RUNNING:
                when = "running"
            elif event.status == QUEUED:
                when = "waiting"
            else:
                # Settled with no start time — an event we were told about
                # without seeing it begin. A dash says "not measured",
                # where "waiting" would be a plain lie.
                when = "—"
            detail = event.result_summary or event.error_summary or ""
            if event.status == QUEUED:
                detail = ""
            cells: list[Any] = [
                Text(glyph, style=style),
                Text(tool_label(event.tool),
                     style="bold" if event.status == RUNNING else ""),
            ]
            if show_action:
                cells.append(Text(event.action, style="dim"))
            cells.append(when)
            if show_result:
                cells.append(Text(
                    detail, style=STYLE_FAIL if event.status == FAILED else "dim"))
            table.add_row(*cells)

        return self.frame.panel(
            table, title="[bold]TOOL ACTIVITY[/bold]", border_style="dim",
        )

    def _visible_tools(self) -> list[PurpleToolEvent]:
        """Settled history (capped) plus everything still in flight."""
        settled = [t for t in self.tools if t.settled]
        live = [t for t in self.tools if not t.settled]
        return settled[-TOOL_HISTORY:] + live

    def _counters(self) -> Panel:
        counts = self.counts()
        table = Table.grid(padding=(0, 3))
        for _ in range(3):
            table.add_column(style=STYLE_PENDING, justify="right")
            table.add_column()
        items = [
            ("Subdomains", counts["subdomains"]),
            ("Endpoints", counts["endpoints"]),
            ("Technologies", counts["technologies"]),
            ("Hypotheses", counts["hypotheses"]),
            ("Findings", counts["findings"]),
            ("Errors", counts["errors"]),
        ]
        for i in range(0, len(items), 3):
            row: list[str] = []
            for label, value in items[i:i + 3]:
                style = ""
                if label == "Errors" and value:
                    style = f"[{STYLE_WARN}]"
                elif label == "Findings" and value:
                    style = f"[{STYLE_FAIL}]"
                row.append(label)
                row.append(f"{style}{value}[/]" if style else str(value))
            while len(row) < 6:
                row.append("")
            table.add_row(*row)

        body: list[Any] = [table]
        if self.notices:
            body.append(Text(""))
            for note in self.notices[-4:]:
                body.append(Text(f"{self.glyphs['warn']} {note}",
                                 style=STYLE_WARN))

        return self.frame.panel(
            Group(*body), title="[bold]RESULTS[/bold]", border_style="dim",
        )

    def _progress(self) -> Text:
        """Stage progress, never a bare percentage.

        The bar is honest because the label says what it measures: stage 3
        of 10. A percentage of the *work* is not something the orchestrator
        knows, so it is not something the console may imply.
        """
        total = len(STATES)
        stage = self.stage_number()
        filled = stage if stage else 0
        bar = (self.glyphs["bar_full"] * filled
               + self.glyphs["bar_empty"] * max(0, total - filled))
        label = (STATE_LABEL.get(self.current_state, self.current_state)
                 if self.current_state else "not started")
        text = Text()
        text.append(f"[{bar}] ", style=STYLE_PURPLE)
        text.append(f"Stage {stage or 0} of {total}", style="bold")
        text.append(f"  {label}")
        return text


# ---- logging ------------------------------------------------------------


class PurpleLogHandler(logging.Handler):
    """Screen gets one line; the file gets everything.

    Why this exists: eight ``log.warning(..., exc_info=True)`` calls in
    zonea.py dump full tracebacks for HTTP 429/403/404 on free public APIs.
    Those are the APIs' normal behaviour, not operator-actionable failures,
    and a wall of traceback trains people to ignore warnings.

    So the record is split. ``ui.on_log`` renders ``getMessage()`` and
    nothing else; this handler cannot leak a traceback even by accident,
    because it never passes one. The same handler, given a file, writes the
    untouched record with ``exc_info`` intact — the evidence is relocated,
    not discarded.
    """

    def __init__(self, ui: PurpleUI | None = None,
                 file_handler: logging.Handler | None = None) -> None:
        super().__init__(level=logging.DEBUG)
        self.ui = ui
        self.file_handler = file_handler
        # Recorded by attach_purple_logging so detach can put the logging
        # system back exactly as it found it.
        self.previous_levels: list[tuple[logging.Handler, int]] = []
        self.previous_root_level: int = logging.WARNING
        self.log_path: Any = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if self.file_handler is not None:
                self.file_handler.handle(record)
            if self.ui is not None and record.levelno >= logging.WARNING:
                self.ui.on_log(record)
        except Exception:  # pragma: no cover - logging must never raise
            pass


# Level that keeps a handler installed but emitting nothing.
_SILENCED = logging.CRITICAL + 1


def attach_purple_logging(
    home: Any, engagement_id: str, ui: PurpleUI | None
) -> tuple[PurpleLogHandler, Any]:
    """Route purple logs to the console and to <engagement>/debug.log.

    Returns (handler, log_path) so the caller can detach and report the path.

    Getting DEBUG detail into the file *without* putting it on the screen
    needs two moves, because the level check happens on the logger before
    any handler runs:

    1. the root logger is dropped to DEBUG, so debug records are emitted;
    2. every handler that was already installed is silenced, so the stderr
       handler basicConfig() created neither prints DEBUG nor prints the
       WARNING lines the console is already showing as notices.

    Both are recorded and restored by detach_purple_logging, so copilot
    mode's logging is exactly as it was.
    """
    from pathlib import Path

    log_path = Path(home) / "engagements" / engagement_id / "debug.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))

    root = logging.getLogger()
    handler = PurpleLogHandler(ui=ui, file_handler=file_handler)
    handler.setLevel(logging.WARNING)  # the console half; the file is DEBUG

    handler.previous_levels = [(h, h.level) for h in root.handlers]
    handler.previous_root_level = root.level
    handler.log_path = log_path

    for existing, _ in handler.previous_levels:
        # Silenced, not merely left at WARNING. cli.py calls basicConfig()
        # with level=WARNING, so the stderr handler is *already* at WARNING —
        # pinning it there changed nothing, and the raw line went to stderr
        # with its traceback beside the console's clean one-line notice.
        # That is the exact noise this redesign exists to remove, so it is
        # asserted against real stderr in the tests.
        #
        # Above CRITICAL is the only level that leaves the handler installed
        # (so detach can restore it) while guaranteeing it emits nothing.
        # With no UI attached the notices would go nowhere, so the handlers
        # are left alone — silence is only acceptable when something else
        # is carrying the message.
        existing.setLevel(_SILENCED if ui is not None else logging.WARNING)
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    return handler, log_path


def detach_purple_logging(handler: PurpleLogHandler) -> None:
    """Undo attach_purple_logging. Safe to call twice."""
    root = logging.getLogger()
    try:
        root.removeHandler(handler)
    except ValueError:  # pragma: no cover - already gone
        pass
    for existing, level in handler.previous_levels:
        existing.setLevel(level)
    root.setLevel(handler.previous_root_level)
    file_handler = handler.file_handler
    if file_handler is not None:
        try:
            file_handler.close()
        except Exception:  # pragma: no cover
            pass
