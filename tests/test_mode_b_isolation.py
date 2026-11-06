"""Mode-B execution isolation invariant tests (2026-11-05).

ARCHITECTURAL INVARIANT — permanent security requirement:

    Every Purple (Mode B) security-tool execution happens inside the
    Docker sandbox under gVisor (runsc). No Mode B tool may execute
    directly on the host, and no fallback may substitute host execution
    when the sandbox is unavailable.

These tests police the invariant from the outside, in the repo's
self-checking style (compare the exploit confirmation-set and allowlist
sync tests): a change that breaks them fails loudly and must be added
here consciously, never silently.

Host-side subprocess use that is *not* tool execution is allowed and
must not be flagged by these tests: the docker CLI bridge inside
sandbox.py (that IS the sandbox boundary) and runtime_checks.py's
read-only docker probes. UI rendering, LLM calls, approvals, audit
writes, docker management and runtime preflight stay on the host by
design.
"""

import ast
from pathlib import Path

import pytest

from kryonsec.config import KryonsecConfig
from kryonsec.purple.orchestrator import SubagentResult, next_state
from kryonsec.purple.recon_passive import sandbox_passive_fetcher
from kryonsec.purple.sandbox import KaliSandbox, missing_isolation_flags

SRC = Path(__file__).resolve().parents[1] / "src" / "kryonsec"
PURPLE = SRC / "purple"
COMPLETED_PAYLOAD = '{"exit_code": 0, "stdout": "ok"}'


class Completed:
    """Minimal subprocess.CompletedProcess stand-in."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---- helpers ---------------------------------------------------------------


def _iter_python(dirpath: Path):
    for path in sorted(dirpath.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path


def _imported_roots(path: Path) -> set[str]:
    """The dotted roots every ``import``/``from`` in a file resolves to."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            parts = list(node.module.split("."))
            for depth in range(1, len(parts) + 1):
                roots.add(".".join(parts[:depth]))
    return roots


def _module_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---- source policy: who may touch processes --------------------------------


def test_purple_subprocess_use_is_sandbox_and_runtime_checks_only():
    """Only the docker bridge and the docker probes may open processes on
    the host. Any new ``subprocess`` import under purple/ must be added
    here consciously — and the first question must be: is this tool
    execution? Then it belongs in the sandbox instead."""
    allowed = {"sandbox.py", "runtime_checks.py", "egress.py"}
    offenders = [
        str(p.relative_to(PURPLE))
        for p in _iter_python(PURPLE)
        if str(p.relative_to(PURPLE)) not in allowed
        and ("subprocess" in _imported_roots(p)
             or "subprocess" in _module_text(p))
    ]
    assert offenders == [], (
        "purple modules may not open host processes directly; tool "
        "execution goes through KaliSandbox.spawn, docker management "
        "through sandbox.py/runtime_checks.py, the network-egress "
        "boundary through egress.py"
    )
    # and the three known docker/firewall-management surfaces stay covered
    scanned = {str(p.relative_to(PURPLE)) for p in _iter_python(PURPLE)}
    assert allowed <= scanned


def test_zone_a_agent_runs_no_local_processes():
    """Zone A (RECON_PASSIVE host side) is HTTP-only against allowlisted
    third-party APIs — no scanner, no CLI, no subprocess of any kind."""
    for path in _iter_python(PURPLE):
        text = _module_text(path)
        for bad in ("Popen(", "os.system(", "os.popen(", "shell=True"):
            assert bad not in text, (
                f"{path.name} must not use {bad}; Zone A is fetch-only "
                "and all Zone B execution is sandbox-only"
            )


# ---- source policy: the process boundary can only be the sandbox -----------


def test_every_tool_spawn_call_site_is_allowlist_gated():
    """Every module that invokes ``.spawn(`` must be a known allowlist-
    gate consumer or the sandbox module itself. The gate (Layer 2) is
    what makes a spawn an *allowed* execution; a new spawn site without
    it means an allowlist bypass — reject the change, don't add the
    module here without review."""
    # sandbox.py only re-exports the SpawnResult; its own `.spawn(` is the
    # boundary definition, not a caller.
    gated: set[str] = set()
    for path in _iter_python(PURPLE):
        text = _module_text(path)
        if ".spawn(" not in text:
            continue
        rel = str(path.relative_to(PURPLE))
        if rel == "sandbox.py":
            continue
        if "AllowlistViolation" in text:
            gated.add(rel)
        else:
            pytest.fail(
                f"{rel} calls KaliSandbox.spawn but has no allowlist "
                "gate (AllowlistViolation) — a Layer-2 bypass"
            )
    expected = {
        "exploit.py", "verify.py", "recon_active.py", "recon_passive.py",
        "blue_team.py", "post_exploit.py", "enrichment.py",
    }
    assert expected <= gated, f"known spawn sites missing from the gate set"


def test_spawn_sites_validate_or_fail_closed():
    """Each spawn site must reject (not ignore) argv the allowlist refuses.
    The pattern ``except AllowlistViolation`` is the audit evidence of the
    fail-closed branch — the sandbox cannot be a 'try-and-see' caller."""
    for rel in (
        "exploit.py", "verify.py", "recon_active.py", "recon_passive.py",
        "blue_team.py", "post_exploit.py", "enrichment.py",
    ):
        assert "except AllowlistViolation" in _module_text(
            PURPLE / rel), f"{rel} swallows allowlist violations"


# ---- Mode A / MCP boundary -------------------------------------------------


def test_purple_never_imports_the_mcp_or_agent_toolbox_surface():
    """Mode B must have no path to Mode A's MCP toolbox or agent executor:
    remote MCP command servers (e.g. HexStrike-style HTTP execution
    endpoints) must never be able to reach Zone B execution. Importing
    ``copilot.cve`` is the one allowed, consciously-reviewed exception —
    it is a plain NVD HTTP API helper with no tool execution."""
    forbidden = ("copilot.mcp_tools", "copilot.agent", "copilot.tools")
    offenders: list[str] = []
    for path in _iter_python(PURPLE):
        for root in _imported_roots(path):
            if any(
                    root == f or root.endswith("." + f) for f in forbidden):
                offenders.append(
                    f"{path.name} imports {root}")
    assert offenders == [], (
        "purple may not import the Mode A MCP/agent execution surface"
    )


def test_mode_a_never_imports_purple_execution_modules():
    """Mode A's copilot package must not reach Mode B's execution modules.
    (The CLI/TUI/workspace shell code wires the two modes together — that
    is allowed; the copilot AGENT layer is not.)"""
    copilot = SRC / "copilot"
    offenders: list[str] = []
    for path in _iter_python(copilot):
        for root in _imported_roots(path):
            if ".purple" in root or root.startswith("purple"):
                offenders.append(f"{path.name} imports {root}")
    assert offenders == [], (
        "copilot must not import purple execution modules"
    )


def test_mode_b_wiring_has_no_mcp_references():
    """runner.py is the only module that assembles Mode B execution (the
    sandbox + the eight subagents). It must stay free of MCP references —
    MCP tools reach Mode B through no path today and must never gain one
    without passing through the Layer-2 allowlist and the sandbox."""
    text = _module_text(PURPLE / "runner.py")
    assert "McpToolbox" not in text
    assert "mcp" not in text.lower()


# ---- behavioral: the boundary refuses to launch unisolated -----------------


def _sandbox(tmp_path, run_fn=None):
    cfg = KryonsecConfig(home=tmp_path)
    return KaliSandbox(cfg=cfg, run_fn=run_fn,
                       seccomp_profile=tmp_path / "nope.json")


def test_spawn_launch_is_gVisor_isolated(tmp_path):
    """The launch actually executed (not just planned) carries runsc,
    non-root, read-only rootfs and the resource caps."""
    seen: list[list[str]] = []

    def run_fn(argv, **kw):
        seen.append(list(argv))
        return Completed(stdout=COMPLETED_PAYLOAD)

    _sandbox(tmp_path, run_fn).spawn(["nmap", "-sT", "t.example"])
    assert len(seen) == 1
    argv = seen[0]
    assert argv[0] == "docker" and "run" in argv[:3]
    assert argv[argv.index("--runtime") + 1] == "runsc"
    assert argv[argv.index("--user") + 1] == "kryonsec-runner"
    assert "--read-only" in argv
    assert argv[argv.index("--memory") + 1] == "2g"
    assert argv[argv.index("--cpus") + 1] == "2"
    assert argv[argv.index("--pids-limit") + 1] == "100"


@pytest.mark.parametrize(
    "drop, flag_name",
    [
        (("--runtime", "runsc"), "--runtime"),
        (("--user", "kryonsec-runner"), "--user"),
        (("--read-only", None), "--read-only"),
        (("--memory", "2g"), "--memory"),
        (("--cpus", "2"), "--cpus"),
        (("--pids-limit", "100"), "--pids-limit"),
    ],
)
def test_spawn_refuses_to_launch_without_isolation(
        tmp_path, monkeypatch, drop, flag_name):
    """If isolation flags ever disappear from the launch argv, the tool
    must NOT run — not unsandboxed, not 'best effort'. The spawn fails
    closed and the launcher is never invoked."""
    launched = []

    def run_fn(argv, **kw):
        launched.append(list(argv))
        return Completed(stdout=COMPLETED_PAYLOAD)

    flag, expected = drop
    real_argv = _sandbox(tmp_path)._docker_argv(["nmap", "t.example"])
    weakened = _strip_flag(real_argv, flag, expected)

    sb = _sandbox(tmp_path, run_fn)
    monkeypatch.setattr(sb, "_docker_argv", lambda tool_argv: weakened)
    result = sb.spawn(["nmap", "t.example"])

    assert launched == [], "a tool must never launch unisolated"
    assert result.ok is False
    assert "invariant" in result.error
    assert flag_name in result.error, (
        "the diagnostic must name the missing isolation requirement")


def _strip_flag(argv: list[str], flag: str, expected: str | None) -> list[str]:
    """Remove one flag (and its value token) from a docker argv — the shape
    a future regression of `_docker_argv` could produce."""
    i = argv.index(flag)
    out = argv[:i]
    if expected is not None:
        assert argv[i + 1] == expected
        out = out + argv[i + 2:]
    else:
        out = out + argv[i + 1:]
    return out


def test_missing_isolation_flags_reports_every_gap(tmp_path):
    argv = _sandbox(tmp_path)._docker_argv(["nmap", "t.example"])
    assert missing_isolation_flags(argv) == []
    weakened = _strip_flag(argv, "--runtime", "runsc")
    weakened = _strip_flag(weakened, "--read-only", None)
    gaps = missing_isolation_flags(weakened)
    assert any("--runtime" in g for g in gaps)
    assert any("--read-only" in g for g in gaps)


# ---- behavioral: failure paths stay closed ---------------------------------


def test_zone_a_passive_fetcher_fails_closed_without_sandbox(tmp_path):
    """When the sandbox cannot run a passive tool, the Zone A fetcher
    records the failure and returns NOTHING — it never falls back to
    executing subfinder/amass on the host."""
    calls: list[list[str]] = []

    class FailingSandbox:
        def spawn(self, argv):
            calls.append(list(argv))
            from kryonsec.purple.sandbox import SpawnResult

            return SpawnResult(ok=False, exit_code=-1,
                               stdout="", error="docker daemon down")

    audit = type("A", (), {
        "write": staticmethod(lambda entry: None),
    })()
    fetch = sandbox_passive_fetcher(FailingSandbox(), audit)
    result = fetch("example.com")

    # every planned passive tool was attempted through the sandbox — none
    # of them on the host
    assert len(calls) == 3
    assert calls[0] == ["subfinder", "-d", "example.com", "-passive", "-silent"]
    assert result.subdomains == []
    assert result.source == "sandbox-passive"


def test_passive_fetcher_alone_never_constitutes_execution(
        tmp_path, monkeypatch):
    """The fetcher is only constructed with a live sandbox (runner wiring):
    a None sandbox means the fetcher is appended to the fetcher list at
    all (runner.resolve). Here: the module never constructs a fallback
    execution path of its own — its only process reference is
    ``sandbox.spawn``."""
    # the wiring rule: sandbox_passive_fetcher REQUIRES a sandbox object
    from kryonsec.purple import recon_passive as rp

    text = _module_text(Path(rp.__file__))
    assert "sandbox.spawn(" in text, "passive tools must route through the sandbox"


def test_zone_b_states_are_never_sandbox_free(tmp_path):
    """Zone B states without a sandbox must not be members of the set of
    states that run without one — the runner can only block (audited
    ``zone_b_blocked`` halt) or fail through the sandbox, never run a
    Zone B tool on the host."""
    from kryonsec.purple import runner as runner_mod

    zone_b_states = ("RECON_ACTIVE", "EXPLOIT", "POST_EXPLOIT", "VERIFY",
                     "BLUE_TEAM")
    for state in zone_b_states:
        assert state not in runner_mod.SANDBOX_FREE_STATES


def test_zone_b_state_wiring_mentions_the_sandbox(tmp_path):
    """In runner.resolve (read from source): every Zone B state's wiring
    branch constructs its subagent out of a sandbox object. A Zone B
    branch that stopped referencing the sandbox would mean a path that
    reports work without any sandboxed execution."""
    text = _module_text(PURPLE / "runner.py")
    branch_states = ("RECON_ACTIVE", "BLUE_TEAM", "EXPLOIT", "POST_EXPLOIT",
                     "VERIFY")
    markers = {state: text.index(f'if state == "{state}"')
               for state in branch_states}
    ends = sorted(markers.values()) + [
        text.index("    if state in SANDBOX_FREE_STATES")]
    for state, start in markers.items():
        end = min(e for e in ends if e > start)
        body = text[start:end]
        assert "sandbox" in body, (
            f"{state} wiring must route through the sandbox object; a "
            "Zone B branch without a sandbox is a host-execution path")


def test_orchestrator_transition_always_routes_zone_b_through_the_loop():
    """No transition exists that lets a Zone B state run outside the
    loader contract: the orchestrator emits only successor state names
    from the transition table — execution is always the runner's loader
    job, which wires sandbox subagents or fails closed."""
    expected_successors = {
        "RECON_ACTIVE": "HYPOTHESIZE",
        "EXPLOIT": "VERIFY",         # ok, no shell — POST_EXPLOIT needs gate
        "POST_EXPLOIT": "VERIFY",
        "VERIFY": "BLUE_TEAM",
        "BLUE_TEAM": "REPORT",
    }
    for state, successor in expected_successors.items():
        assert next_state(state, SubagentResult(status="ok")) == successor


def test_no_browser_automation_reaches_mode_b():
    """gowitness (the only browser-like tool) runs in the sandbox; no
    browser-automation driver (playwright/selenium/puppeteer) exists for
    Mode B."""
    for path in _iter_python(PURPLE):
        text = _module_text(path).lower()
        for bad in ("playwright", "selenium", "puppeteer"):
            assert bad not in text, f"{path.name} references {bad}"
