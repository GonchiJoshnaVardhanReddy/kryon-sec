"""Purple Team engagement runner (spec v2.1.1 §4).

Two-tier gating:
- Zone A states (RECON_PASSIVE) run anywhere — they are third-party API
  calls only (zero packets to the target).
- Zone B states (RECON_ACTIVE onward) need the sandbox: Linux + Docker +
  gVisor. On other systems the engagement HALTs after RECON_PASSIVE with
  a clear reason instead of silently running un-sandboxed tools.
"""

from __future__ import annotations

import json
import logging
import platform
import uuid

from ..config import KryonsecConfig
from ..secrets import redact
from . import runtime_checks
from .audit import AuditLog
from .orchestrator import HALT, PurpleOrchestrator, SubagentResult

log = logging.getLogger(__name__)

# States that can run without the Kali sandbox (host-side, Zone A)
SANDBOX_FREE_STATES = {"INIT", "RECON_PASSIVE", "HYPOTHESIZE", "HUMAN_REVIEW"}

# What each state does + which tools it may use (spec §4.2 state table).
# Display info only — the authoritative tool check is the allowlist.
STATE_INFO: dict[str, dict[str, str]] = {
    "INIT": {
        "agent": "init",
        "does": "load config, validate scope",
        "tools": "none",
        "zone": "—",
    },
    "RECON_PASSIVE": {
        "agent": "passive-recon",
        "does": "third-party lookups — zero packets to target",
        "tools": "crt.sh (+ issuer/validity), Wayback, OTX, RIPEstat "
                 "(whois/ASN), Shodan, Censys (keys), RDAP WHOIS, GitHub "
                 "recon (optional token), HackerTarget DNS history, "
                 "cloud-asset analysis (local pass); "
                 "subfinder/amass/assetfinder -passive in sandbox",
        "zone": "A",
    },
    "RECON_ACTIVE": {
        "agent": "active-recon",
        "does": "scan the target (packets to target)",
        "tools": "nmap, naabu, dnsx, httpx, whatweb, katana, feroxbuster, "
                 "openapi_probe, gowitness (screenshots → /evidence), "
                 "sslscan, testssl.sh",
        "zone": "B (sandbox)",
    },
    "HYPOTHESIZE": {
        "agent": "hypothesizer (LLM)",
        "does": "propose vulnerability hypotheses from recon data, then "
                "enrich with public risk data",
        "tools": "LLM proposes only; enrichment: NVD/CPE/CWE, CISA KEV, "
                 "EPSS, OSV, GitHub Advisory (free APIs) + searchsploit "
                 "and nuclei-template lookup in sandbox",
        "zone": "A (third-party APIs) + B for searchsploit",
    },
    "HUMAN_REVIEW": {
        "agent": "operator (you)",
        "does": "approve or reject each hypothesis",
        "tools": "none — blocking approval gate",
        "zone": "—",
    },
    "EXPLOIT": {
        "agent": "exploit",
        "does": "execute approved hypotheses only",
        "tools": "sqlmap, nuclei, nikto, ffuf, gobuster, wfuzz, curl, wget, "
                 "dalfox, commix, ssrfmap, arjun, tplmap, graphql-cop",
        "zone": "B (sandbox)",
    },
    "POST_EXPLOIT": {
        "agent": "post-exploit",
        "does": "enumerate inside an obtained shell (separate approval; "
                "dormant — no current tool yields a shell)",
        "tools": "linpeas, pspy, linux-exploit-suggester, baked enum "
                 "scripts + cloud metadata probe (evidence collection "
                 "only, never destructive; impacket/bloodhound-python "
                 "allowlisted but dormant)",
        "zone": "B (sandbox)",
    },
    "VERIFY": {
        "agent": "verifier",
        "does": "independently confirm findings",
        "tools": "curl, httpie, nc, openssl, dig, baked probe script",
        "zone": "B (sandbox)",
    },
    "BLUE_TEAM": {
        "agent": "blue-team (LLM)",
        "does": "generate fixes and detection rules, grounded in scanner "
                "evidence when a --code folder is provided",
        "tools": "semgrep, bandit, gitleaks, trivy, checkov, hadolint, "
                 "syft (SBOM), osv-scanner, grype "
                 "(read-only /code mount) + LLM",
        "zone": "B for scanners (sandbox), LLM is host-side",
    },
    "REPORT": {
        "agent": "reporter",
        "does": "compile the engagement report",
        "tools": "Jinja2 templates",
        "zone": "—",
    },
}


def sandbox_available(image: str = "kryonsec/sandbox:latest") -> tuple[bool, str]:
    """Check Zone B prerequisites. Returns (ok, reason-if-not).

    Probes, in order: Linux platform, docker CLI + daemon, runsc runtime
    registered, and the pinned sandbox image present locally (spec §8.5/§8.6).
    The probes themselves live in purple/runtime_checks.py (shared with
    `kryonsec doctor`).
    """
    if platform.system() != "Linux":
        return False, (
            "Zone B (sandboxed tools) requires Linux — you are on "
            f"{platform.system()}. Use WSL2 or a Linux VM."
        )

    runtimes = runtime_checks.docker_runtimes()
    if runtimes is None:
        return False, "docker CLI not found or daemon unreachable"

    if "runsc" not in runtimes:
        # the notice line is a single line in the prompt, so the how-to-fix
        # detail belongs in doctor, not here — point at it
        return False, (
            "gVisor (runsc) runtime not registered with Docker — "
            "run `kryonsec doctor` for the fix"
        )

    if not runtime_checks.image_present(image):
        return False, f"sandbox image not found locally: {image}"

    return True, "ok"


def start_engagement(
    cfg: KryonsecConfig,
    engagement_id: str,
    target: str = "",
    progress: "Callable[[str], None] | None" = None,
    status_factory: "Callable[[str], object] | None" = None,
    code_folder: str | None = None,
) -> tuple[PurpleOrchestrator, AuditLog, "object"]:
    """Wire up an engagement. Returns (orchestrator, audit, graph).

    The engagement starts on every OS. When the sandbox is unavailable,
    the orchestrator HALTs (with an audited reason) as soon as a state
    needs Zone B.

    code_folder: absolute path to a user-provided code folder
    (--code). Blue-team static analyzers scan it through a read-only
    sandbox mount; without it (or without a sandbox) BLUE_TEAM stays
    pure LLM.

    progress: optional callback invoked with each state name before it
    runs (CLI uses it to show which agent is working).

    status_factory: optional — called with the state name, must return a
    context manager that is entered while the state's subagent runs (the
    CLI returns a spinner status line). Never wraps HUMAN_REVIEW: that
    state is interactive and owns the terminal.
    """
    from .recon_passive import EngagementGraph, ReconPassiveSubagent

    audit_path = cfg.home / "engagements" / engagement_id / "audit.jsonl"
    audit = AuditLog(audit_path)
    audit.write({
        "event": _CREATED_EVENT,
        "engagement_id": engagement_id,
        "target": target,
        "code_scan": bool(code_folder),
        # Phase 4.5B: the *execution's* identity, distinct from the
        # engagement id it runs under. An id can be reused (--id) and every
        # run appends its own creation event, so this is what lets the
        # terminal event — and a reader — tell one run from the next.
        "run_id": new_run_id(),
    })
    graph = EngagementGraph(engagement_id=engagement_id)

    sandbox_ok, sandbox_reason = sandbox_available(cfg.sandbox_image)
    audit.write({
        "event": "sandbox_check",
        "available": sandbox_ok,
        "reason": sandbox_reason,
    })

    # Evidence capture (Phase 8): screenshots and other artifacts land in
    # the engagement folder, mounted rw at the fixed /evidence in every
    # sandbox that produces evidence (active recon, exploit, post-exploit,
    # verify). The path is host-side Python — never from the LLM or argv.
    evidence_dir = cfg.home / "engagements" / engagement_id / "evidence"
    if sandbox_ok:
        evidence_dir.mkdir(parents=True, exist_ok=True)

    # ONE sandbox per engagement (M5): a config holder, so per-state mount
    # variants come from copy_with() — one construction also means one
    # image-pin warning, not one per state
    sandbox = None
    if sandbox_ok:
        from .sandbox import KaliSandbox

        sandbox = KaliSandbox(cfg=cfg)

    def resolve(state: str):
        """State name -> subagent run callable (or None for stubs)."""
        if state == "RECON_PASSIVE":
            from .recon_passive import (
                ReconPassiveSubagent,
                sandbox_passive_fetcher,
                zone_a_fetchers,
            )

            fetchers = zone_a_fetchers(cfg)
            if sandbox is not None:
                # passive subdomain tools in the sandbox (-passive flags;
                # zero packets to the target) — skipped cleanly elsewhere
                fetchers.append(
                    sandbox_passive_fetcher(sandbox, audit))
            sub = ReconPassiveSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                fetchers=fetchers,
            )
            return sub.run

        if state == "HYPOTHESIZE":
            from .hypothesize import HypothesizeSubagent

            # the sandbox (when present) powers ExploitDB searchsploit
            # enrichment; without it enrichment runs API-only and skips
            # searchsploit with an audited notice
            sub = HypothesizeSubagent(
                cfg=cfg, graph=graph, audit=audit, budget=orch.budget,
                sandbox=sandbox,
            )
            return sub.run

        if state == "HUMAN_REVIEW":
            from .human_review import HumanReviewSubagent

            sub = HumanReviewSubagent(graph=graph, audit=audit)
            return sub.run

        if state == "BLUE_TEAM":
            from .blue_team import BlueTeamSubagent

            # sandbox with the read-only /code mount for the static
            # analyzers; without a code folder (or sandbox) BLUE_TEAM
            # stays pure LLM
            bt_sandbox = (
                sandbox.copy_with(code_dir=code_folder)
                if sandbox is not None and code_folder else None
            )
            sub = BlueTeamSubagent(
                cfg=cfg, graph=graph, audit=audit, budget=orch.budget,
                sandbox=bt_sandbox, code_folder=code_folder,
            )
            return sub.run

        if state == "REPORT":
            from .report import ReportSubagent

            sub = ReportSubagent(
                cfg=cfg, graph=graph, audit=audit, engagement_id=engagement_id,
            )

            def run_report() -> SubagentResult:
                # the report records how far the engagement actually got
                sub.completed_states = orch.completed
                sub.halt_reason = orch.halt_reason
                return sub.run()

            return run_report

        if state == "RECON_ACTIVE" and sandbox is not None:
            from .recon_active import ReconActiveSubagent

            sub = ReconActiveSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox.copy_with(evidence_dir=str(evidence_dir)),
            )
            return sub.run

        if state == "EXPLOIT" and sandbox is not None:
            from .exploit import ExploitSubagent

            sub = ExploitSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox.copy_with(evidence_dir=str(evidence_dir)),
                progress=progress,
            )
            return sub.run

        if state == "POST_EXPLOIT" and sandbox is not None:
            from .post_exploit import PostExploitSubagent

            sub = PostExploitSubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox.copy_with(evidence_dir=str(evidence_dir)),
            )
            return sub.run

        if state == "VERIFY" and sandbox is not None:
            from .verify import VerifySubagent

            sub = VerifySubagent(
                cfg=cfg, graph=graph, audit=audit, target=target,
                sandbox=sandbox.copy_with(evidence_dir=str(evidence_dir)),
            )
            return sub.run

        if state in SANDBOX_FREE_STATES:
            return subagent_stub(state)

        # Zone B state without a sandbox: halt with a clear reason rather
        # than running un-sandboxed tools on the host.
        if not sandbox_ok:
            def blocked() -> SubagentResult:
                audit.write({
                    "event": "zone_b_blocked",
                    "state": state,
                    "reason": sandbox_reason,
                })
                log.warning("Zone B blocked in state %s: %s", state, sandbox_reason)
                return SubagentResult(status="halted", halt_reason=sandbox_reason)
            return blocked

        return subagent_stub(state)

    def loader(state: str):
        if progress is not None:
            # The action, not the inventory. The tool list used to be
            # pasted in here, which printed eight lines of tool names for
            # every state — including states whose tools never ran. What
            # is actually running is reported per-tool as it starts, so
            # this line only has to say what the state is doing.
            from .ui import state_action

            progress(state_action(state))

        run_fn = resolve(state)

        if status_factory is not None and state != "HUMAN_REVIEW":
            def wrapped() -> SubagentResult:
                with status_factory(state):
                    return run_fn()
            return wrapped
        return run_fn

    orch = PurpleOrchestrator(
        engagement_id=engagement_id,
        execution_allowed=True,
        subagent_loader=loader,
    )
    # Durable checkpoint (Phase 4.3). The graph is written to engagement
    # storage after every state, so an interruption costs at most the state
    # that was running instead of the whole engagement. Wired here rather
    # than in the CLI because durability is a property of running an
    # engagement, not of how it is presented — and because the graph, the
    # chain and the config are all built here. It runs on the same
    # single-threaded loop as everything else, so the snapshot cannot race a
    # subagent still writing to the graph.
    orch.on_state_complete = lambda state: checkpoint_graph(
        cfg, engagement_id, graph, audit, state)

    return orch, audit, graph


def _safe_error(exc: BaseException, cfg: KryonsecConfig) -> str:
    """An exception as a short audit field that names no local path.

    The message is kept — "disk is full" is most of what the event is worth —
    but two things a permanent, append-only record must not hold are removed
    first: the local home directory, which names the machine's user, and
    anything the secret detector recognises (a PostgreSQL failure can quote
    the connection URL, and a URL carries the password).

    The home prefix is stripped before redaction, not after: redaction could
    rewrite part of a path into a placeholder, and the prefix would then no
    longer match as a literal.

    Shared by ``graph_persist_failed`` and ``checkpoint_failed`` so the two
    descriptions of the same kind of failure cannot drift apart.
    """
    detail = f"{type(exc).__name__}: {exc}"
    home = str(cfg.home)
    if home:
        # The three forms a path reaches an exception message in: plain, with
        # escaped separators (a repr), and with forward slashes.
        for form in (home, home.replace("\\", "\\\\"), home.replace("\\", "/")):
            detail = detail.replace(form, "<home>")
    return redact(detail)[0][:200]


def persist_graph(
    cfg: KryonsecConfig,
    engagement_id: str,
    graph: EngagementGraph,
    audit: AuditLog,
) -> bool:
    """Write the engagement's Security Graph to engagement storage.

    Called once, after the loop reaches HALT (whether the engagement ran to
    REPORT or stopped early — a halted engagement's graph is still the
    record of what was observed, and is exactly the one an operator wants
    to inspect afterwards). Since Phase 4.3 the same graph is written after
    every state by ``checkpoint_graph``; this is the write that records the
    engagement reached the end of the loop, and ``graph_persisted`` is the
    event that says so.

    Failure policy: **reported, never fatal, never silent.** By the time
    this runs the engagement is over — the audit chain, the evidence
    directory and the report are already on disk — so a storage problem
    here cannot undo or invalidate any of it, and failing the command would
    only hide a successful engagement behind an unrelated error. But it
    must not vanish either: the failure is written to the audit chain as
    ``graph_persist_failed`` (the chain is append-only, so it stays
    visible), logged with the traceback, and returned so the CLI can tell
    the operator. ``save_graph`` commits once, at the end, so a failure
    leaves the previously saved state of that engagement intact rather
    than a half-written graph.

    Returns True when the graph was stored.
    """
    from ..storage import get_purple_session, init_purple_db
    from .graph_store import save_graph

    try:
        init_purple_db(cfg)
        with get_purple_session(cfg) as session:
            nodes, edges = save_graph(session, graph)
    except Exception as exc:
        # Deliberately broad: anything at all going wrong here is the same
        # outcome (no graph memory) and the same handling. It is caught so
        # that it can be *reported* — audit event, log, return value — not
        # so that it can be ignored.
        detail = f"{type(exc).__name__}: {exc}"
        audit.write({
            "event": "graph_persist_failed",
            "engagement_id": engagement_id,
            # The chain gets the sanitised wording; the log below gets the
            # whole message, because it stays on this machine and the
            # traceback already carries the path.
            "error": _safe_error(exc, cfg),
        })
        log.warning(
            "engagement %s: graph not persisted: %s", engagement_id, detail,
            exc_info=True,
        )
        return False

    audit.write({
        "event": "graph_persisted",
        "engagement_id": engagement_id,
        "nodes": nodes,
        "edges": edges,
    })
    log.info(
        "engagement %s: graph persisted (%d nodes, %d edges)",
        engagement_id, nodes, edges,
    )
    return True


# ---- durable checkpoint (Phase 4.3) ---------------------------------------


def _announce(audit: AuditLog, entry: dict) -> None:
    """Best-effort audit write for a checkpoint.

    Kept separate from the checkpoint itself on purpose: the snapshot is the
    durable record and the announcement is the annotation. Sharing one
    try/except with the storage write would let a damaged chain — which is
    what makes ``AuditLog.write`` raise — report a checkpoint that actually
    succeeded as one that failed, sending an operator after a storage
    problem that isn't there.
    """
    try:
        audit.write(entry)
    except Exception:
        log.warning("checkpoint announcement could not be audited", exc_info=True)


def checkpoint_graph(
    cfg: KryonsecConfig,
    engagement_id: str,
    graph: EngagementGraph,
    audit: AuditLog,
    state: str,
) -> bool:
    """Write the graph to engagement storage mid-run (Phase 4.3).

    Before this, the graph lived only in RAM until the loop reached HALT,
    so an interruption destroyed every observation the engagement had made.
    Now it is written after each state — the boundary where the graph is
    quiescent — and an interruption costs at most the state that was
    running when it happened.

    The write is ``graph_store.save_graph``, which replaces the
    engagement's rows in a single transaction: a crash part-way through
    leaves the previous checkpoint intact rather than half of a new one.
    Secrets are redacted on the way in by that same function, so the
    boundary checkpoints — the copy most likely to outlive an interrupted
    run — carry no credentials either.

    This is not resume: nothing reads a checkpoint back to continue an
    engagement. It exists so the data survives, not so the run continues.

    Failure policy: **reported, never fatal, never silent** — the same
    shape as ``persist_graph``, for a stronger reason. This runs from
    inside the state loop, so an exception escaping here would abort an
    engagement over a storage problem. Instead it is written to the audit
    chain as ``checkpoint_failed`` (append-only, so it stays), logged with
    its traceback — which the Purple console renders as a notice, so it is
    visible on screen during the run — and returned as False.

    It cannot weaken a safety control. Nothing consults the result; the
    decision to continue or to halt is ``next_state``'s alone; and the loop
    notifies a listener rather than asking it anything.

    Returns True when the checkpoint was written.
    """
    from ..storage import get_purple_session, init_purple_db
    from .graph_store import save_graph

    try:
        init_purple_db(cfg)
        with get_purple_session(cfg) as session:
            nodes, edges = save_graph(session, graph)
    except Exception as exc:
        # Deliberately broad, like persist_graph's: everything that can go
        # wrong here has the same outcome (no checkpoint) and the same
        # handling (say so).
        detail = f"{type(exc).__name__}: {exc}"
        _announce(audit, {
            "event": "checkpoint_failed",
            "engagement_id": engagement_id,
            "state": state,
            "error": _safe_error(exc, cfg),
        })
        log.warning(
            "engagement %s: checkpoint after %s failed: %s",
            engagement_id, state, detail, exc_info=True,
        )
        return False

    _announce(audit, {
        "event": "checkpoint_written",
        "engagement_id": engagement_id,
        "state": state,
        "nodes": nodes,
        "edges": edges,
    })
    return True


# ---- engagement lifecycle (Phase 4.2) -------------------------------------

# The outcomes an engagement can be recorded with. A closed set, because the
# value lands in an append-only chain: an unrecognised word would be
# permanent. There is no "created" outcome — an engagement only reaches the
# writer once the runner has it.
OUTCOMES = frozenset({"completed", "halted", "failed", "interrupted"})

# The two events that bracket one execution. The creation event opens a run
# (and carries its run id, Phase 4.5B); the terminal event closes it.
_CREATED_EVENT = "engagement_created"
_TERMINAL_EVENT = "engagement_finished"

# halt_reason is assigned in exactly three places — orchestrator.py:110,
# orchestrator.py:114, and the zone_b_blocked closure below — and only the
# first two are literals. Everything else is a sandbox probe message, which
# quotes an image reference ("sandbox image not found locally: ...") and
# names missing tools. That is free text, so the terminal event records a
# code and the detailed reason stays in the zone_b_blocked entry that caused
# the halt, which is already in the chain. A new halt_reason needs a code
# added to this table.
_HALT_CODES = {
    "budget_exhausted": "budget_exhausted",
    "purple_team_requires_profile2 (Linux + Docker + gVisor)": "profile2_required",
}
_HALT_FALLBACK = "zone_b_blocked"


def safe_halt_code(reason: str | None) -> str | None:
    """The code for a halt reason, or None when nothing halted.

    Pure and total: an unrecognised reason becomes ``zone_b_blocked`` rather
    than being passed through, because the caller's string can name a
    filesystem path or an image reference and the chain is permanent.
    """
    if not reason:
        return None
    return _HALT_CODES.get(reason, _HALT_FALLBACK)


def safe_exception_type(exc: BaseException | None) -> str | None:
    """The exception's class name, when it is a plain identifier.

    A class name is not a message: it carries no path, no credential and no
    tool output, and it is what makes a `failed` engagement diagnosable. The
    check is here anyway because a class can be built dynamically and named
    anything at all, and this value is written once and never revised.
    """
    if exc is None:
        return None
    name = type(exc).__name__
    return name if len(name) <= 64 and name.isidentifier() else None


def new_run_id() -> str:
    """A fresh identity for one execution (Phase 4.5B).

    ``run_`` plus 16 hex characters: an identifier by construction, so it
    survives the same narrow reading the browser applies to every other
    chain field, and short enough to sit in a status cell.
    """
    return f"run_{uuid.uuid4().hex[:16]}"


def _run_id_of(entry: dict) -> str | None:
    """The ``run_id`` a chain entry claims, if it claims a usable one.

    A chain is data, and a run id read back out of one is copied into the
    entry this module writes. The same rule as :func:`safe_exception_type`
    therefore applies: a bare word or nothing, never free text.
    """
    value = entry.get("run_id")
    if isinstance(value, str) and value.isidentifier() and len(value) <= 64:
        return value
    return None


def _current_run(path) -> tuple[str | None, bool]:
    """The run this chain is currently on, and whether it already has an ending.

    An engagement id names a *directory* and can be reused (``--id``), so a
    chain can hold several runs one after another. Each run opens with its
    own ``engagement_created``, which makes the **last** creation event the
    run now ending — and an ending only counts as "already recorded" when it
    belongs to *that* run. Before Phase 4.5B the question was "does this
    file contain any ending", which let a second run inherit the first run's
    terminal status by being refused a new one.

    Read from the chain rather than handed in by the caller, for the same
    reason the guard reads the file at all: the run that failed is exactly
    the run whose ``engagement_created`` is already on disk and whose
    orchestrator was never returned (``start_engagement`` can raise after
    opening the chain, and the CLI then has no run object left to ask).

    A chain written before run ids existed has a creation event with no
    ``run_id``. That reads as ``None``, and an ending with no ``run_id``
    matches it — so a single legacy run is refused a second ending exactly
    as it was before this phase.

    Returns ``(run_id, has_ending)``.
    """
    run_id: str | None = None
    has_ending = False
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                # A damaged line is AuditLog's to report, loudly. Skipping it
                # here only means this scan cannot answer the question, and
                # the write below will refuse for the same reason.
                continue
            if not isinstance(entry, dict):
                continue
            event = entry.get("event")
            if event == _CREATED_EVENT:
                # A new run starts here. It cannot have ended yet, and any
                # ending seen above belongs to the run before it.
                run_id = _run_id_of(entry)
                has_ending = False
            elif event == _TERMINAL_EVENT and entry.get("run_id") == run_id:
                has_ending = True
    return run_id, has_ending


def record_engagement_ending(
    cfg: KryonsecConfig,
    engagement_id: str,
    *,
    outcome: str,
    reason: str | None = None,
    last_state: str | None = None,
    states_entered: int = 0,
    exception_type: str | None = None,
) -> bool:
    """Append the engagement's single terminal lifecycle event (Phase 4.2).

    Before this, an engagement had no recorded ending. Two endings were
    visible only by inference — ``report_written`` meant it finished,
    ``zone_b_blocked`` meant it stopped — and a budget stop or a Ctrl+C
    wrote neither, so a reader could not tell a run that had crashed from
    one that was still going. One event, written once, closes that: the
    outcome, the code for why, and how far it got.

    Contract: **never raises and never masks.** It is called from a
    ``finally``, usually while an exception is already propagating, so a
    failure here must cost one missing audit entry and nothing else — a
    second KeyboardInterrupt arriving during the write included. The broad
    catch is what makes that true; the return value is what keeps it from
    being silent.

    The ending is stamped with the run id of the run it closes, so a second
    execution under the same engagement id appends its *own* ending rather
    than being refused the first one's (Phase 4.5B). A chain old enough to
    have no run id produces an ending shaped exactly as it was before this
    phase — the key is omitted rather than written as null.

    Returns True when the event was written.
    """
    if outcome not in OUTCOMES:
        # A caller bug must not put an unrecognised word in the chain.
        log.warning("engagement %s: unknown outcome %r", engagement_id, outcome)
        outcome = "failed"

    path = cfg.home / "engagements" / engagement_id / "audit.jsonl"

    try:
        # No engagement_created means no engagement: the id failed
        # validation, or the run died before the chain was opened. Writing
        # an ending into a file that does not exist would create an
        # engagement directory whose only content is a death certificate.
        if not path.is_file():
            return False

        run_id, has_ending = _current_run(path)
        if has_ending:
            return False

        entry: dict = {
            "event": _TERMINAL_EVENT,
            "engagement_id": engagement_id,
            "outcome": outcome,
            "states_entered": states_entered,
        }
        if run_id is not None:
            entry["run_id"] = run_id
        if reason is not None:
            entry["reason"] = reason
        if last_state is not None:
            entry["last_state"] = last_state
        if exception_type is not None:
            entry["exception_type"] = exception_type

        # A fresh AuditLog rather than the run's, for two reasons: this
        # instance carries no observers, so the terminal entry is never
        # handed to a console that has already been torn down; and it
        # re-reads the head hash from disk instead of trusting an object
        # that may never have been built, since the run can fail inside
        # start_engagement before returning one.
        AuditLog(path).write(entry)
        return True
    except BaseException:
        # Deliberately broad, and the only place in this module that is:
        # this runs from a `finally` with an exception in flight, so
        # anything escaping here would replace that exception and change
        # how the command exits. A damaged chain, a read-only directory or
        # a second interrupt costs one audit entry and is logged, never
        # raised.
        log.warning(
            "engagement %s: could not record the engagement ending",
            engagement_id, exc_info=True,
        )
        return False


def subagent_stub(state: str):
    """Placeholder subagent factory: every state reports 'not implemented'.

    Real subagents (Zone A recon modules, sandboxed Zone B tools,
    LLM HYPOTHESIZE/BLUE_TEAM, Jinja2 REPORT) replace these as they land.
    """

    def run() -> SubagentResult:
        log.info("subagent %s: stub (not implemented yet)", state)
        return SubagentResult(status="failed")

    return run
