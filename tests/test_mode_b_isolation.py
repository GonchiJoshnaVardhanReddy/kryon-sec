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
import json
import os
import shutil
import sys
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
    monkeypatch.setattr(sb, "_docker_argv",
                        lambda tool_argv, network_mode=None: weakened)
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


# ---- network-none adapter isolation (Phase 2B.4.1) --------------------------
#
# INVARIANT: a tool whose contract declares network="none" (e.g. the
# searchsploit-term adapter) must be PROVABLY disconnected. A missing
# egress policy used to mean the Docker DEFAULT bridge (full NAT
# connectivity) — that silent fallback is now impossible: none-runs
# launch with --network none and the invariant is verified on the exact
# launch argv, fail closed.

from kryonsec.purple.adapters import (
    AdapterRegistry,
    ModeBToolAdapter,
    execute_adapter,
    prepare_adapter_run,
    spawn_supports_network_mode,
)
from kryonsec.purple.audit import AuditLog
from kryonsec.purple.recon_passive import EngagementGraph
from kryonsec.purple.sandbox import (
    SpawnResult,
    missing_network_none_flags,
)


class _FakePolicy:
    """Duck-typed egress policy for _docker_argv (network_name +
    dns_resolvers is all it reads)."""

    network_name = "eng-net-abc"
    dns_resolvers = ["10.9.9.9"]


class _GenSandbox:
    """A spawn double that ACCEPTS network_mode (the contract a real
    KaliSandbox now exposes) and records what it received."""

    def __init__(self, result=None, *, egress_policy=None):
        self._result = result or SpawnResult(
            ok=True, exit_code=0, stdout='{"exit_code": 0, "stdout": "ok"}')
        self.spawned = []
        self.network_modes = []
        self.egress_policy = egress_policy

    def spawn(self, argv, timeout_s=None, network_mode=None):
        self.spawned.append(list(argv))
        self.network_modes.append(network_mode)
        return self._result


class _OldSansbox:
    """A legacy double whose spawn does NOT know network_mode — the
    shape that cannot prove a run would be disconnected."""

    def __init__(self, result=None):
        self._result = result or SpawnResult(
            ok=True, exit_code=0, stdout="ok")
        self.spawned = []

    def spawn(self, argv, timeout_s=None):
        self.spawned.append(list(argv))
        return self._result


def _audit(tmp_path):
    return AuditLog(Path(tmp_path) / "audit.jsonl")


def _reg_none_adapter():
    reg = AdapterRegistry()
    reg.register(ModeBToolAdapter(
        adapter_id="local-only-probe",
        title="local database probe",
        purpose="A network-none local lookup used by the tests.",
        category="recon",
        stages=("HYPOTHESIZE",),
        executable="searchsploit",
        command_template=("-j", "-t", "{term}"),
        target_kind="term",
        max_seconds=60,
        output_bound_chars=4096,
        approvals=(),
        network="none",
        risk="informational",
        evidence_kind="json_report",
    ))
    return reg


def test_default_bridge_fallback_never_happens_for_none_adapters(tmp_path):
    """The executor hands NONE adapters to the sandbox with
    network_mode='none' — the launch is a verifiable disconnect, not a
    silent default-bridge fallthrough."""
    reg = _reg_none_adapter()
    sbx = _GenSandbox()
    audit = _audit(tmp_path)
    prep = prepare_adapter_run(
        reg, "local-only-probe", target="t.example",
        params={"term": "openssl"}, request_id="requestid0001")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=audit)
    assert sbx.network_modes == ["none"]
    assert bool(record.executed)
    # the REAL docker argv builder for none mode carries the flag even
    # when NO egress policy exists (the old silent-default-bridge case)
    from kryonsec.config import KryonsecConfig

    real = KaliSandbox(
        cfg=KryonsecConfig(home=tmp_path),
        run_fn=lambda argv, **kw: Completed(stdout=COMPLETED_PAYLOAD),
        seccomp_profile=tmp_path / "nope.json")
    argv = real._docker_argv(["searchsploit", "-j", "-t", "x"],
                             network_mode="none")
    assert argv[argv.index("--network") + 1] == "none"
    assert argv.index("--network") < argv.index(real.image)
    assert "--dns" not in argv[:argv.index(real.image)]


def test_none_adapter_stays_disconnected_on_an_egressed_sandbox(tmp_path):
    """Network Policy mismatch: an egress policy on the sandbox exists
    for CONTEXT-tier tools — it must NOT turn a none-adapter into an
    engagement-network run. The none contract wins and is checked."""
    reg = _reg_none_adapter()
    sbx = _GenSandbox(egress_policy=_FakePolicy())
    prep = prepare_adapter_run(
        reg, "local-only-probe", target="t.example",
        params={"term": "openssl"}, request_id="requestid0001")
    record = execute_adapter(reg, prep, sandbox=sbx, audit=_audit(tmp_path))
    assert record.executed
    assert sbx.network_modes == ["none"]   # NOT the engagement network
    # sandbox side: a none-mode launch never carries the engagement
    # network or DNS overrides even when a policy is attached
    from kryonsec.config import KryonsecConfig

    real = KaliSandbox(
        cfg=KryonsecConfig(home=tmp_path),
        run_fn=lambda argv, **kw: Completed(stdout=COMPLETED_PAYLOAD),
        seccomp_profile=tmp_path / "nope.json")
    real.egress_policy = _FakePolicy()
    real.egress_gate = None
    argv = real._docker_argv(["searchsploit", "-j", "-t", "x"],
                             network_mode="none")
    networks = [argv[i + 1] for i, a in enumerate(argv)
                if a == "--network" and i + 1 < argv.index(real.image)]
    assert networks == ["none"]
    assert "eng-net-abc" not in argv
    from kryonsec.purple.sandbox import missing_isolation_flags

    assert missing_isolation_flags(argv) == []
    assert missing_network_none_flags(argv, image=real.image) == []


def test_isolation_flag_tampering_still_fails_closed(tmp_path):
    """If a regression strips the --network none pair from the launch
    argv, the invariant catches it and the docker run NEVER executes."""
    launched = []

    def run_fn(argv, **kw):
        launched.append(list(argv))
        return Completed(stdout=COMPLETED_PAYLOAD)

    from kryonsec.config import KryonsecConfig

    real = KaliSandbox(
        cfg=KryonsecConfig(home=tmp_path), run_fn=run_fn,
        seccomp_profile=tmp_path / "nope.json")
    good = real._docker_argv(["searchsploit", "-j", "-t", "x"],
                             network_mode="none")
    tampered = _strip_flag(good, "--network", "none")
    real._docker_argv = lambda tool_argv, network_mode=None: tampered
    result = real.spawn(["searchsploit", "-j", "-t", "x"],
                        network_mode="none")
    assert launched == [], "a disconnected run must never launch disconnected-adjacent"
    assert result.ok is False
    assert "network-none invariant" in result.error
    # same for an argv that smuggles a SECOND --network back in
    smuggled = good[:good.index(real.image)] + ["--network", "bridge"] \
        + good[good.index(real.image):]
    real._docker_argv = lambda tool_argv, network_mode=None: smuggled
    result2 = real.spawn(["searchsploit", "-j", "-t", "x"],
                         network_mode="none")
    assert launched == []
    assert result2.ok is False and "network" in result2.error


def test_missing_sandbox_refuses_none_adapter(tmp_path):
    """No sandbox object at all: the adapter is audited-refused and
    nothing runs — host-side execution is never a fallback."""
    reg = _reg_none_adapter()
    audit = _audit(tmp_path)
    prep = prepare_adapter_run(
        reg, "local-only-probe", target="t.example",
        params={"term": "openssl"}, request_id="requestid0001")
    record = execute_adapter(reg, prep, sandbox=None, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert "no sandbox" in record.error_excerpt
    events = [json.loads(line) for line in open(audit.path,
                                                encoding="utf-8")
              if line.strip()]
    assert events[-1]["event"] == "adapter_refused"


def test_fail_closed_when_sandbox_cannot_prove_disconnection(tmp_path):
    """A sandbox whose spawn() lacks network_mode CANNOT prove the run
    would be disconnected — the executor refuses the run, it never
    launches unproven on the default bridge."""
    reg = _reg_none_adapter()
    old = _OldSansbox()
    audit = _audit(tmp_path)
    prep = prepare_adapter_run(
        reg, "local-only-probe", target="t.example",
        params={"term": "openssl"}, request_id="requestid0001")
    record = execute_adapter(reg, prep, sandbox=old, audit=audit)
    assert record.executed is False and record.outcome == "refused"
    assert old.spawned == []      # never handed to the old double
    assert "network_mode" in record.error_excerpt
    assert "default-bridge" in record.error_excerpt
    assert not spawn_supports_network_mode(old)


def test_network_none_isolation_invariant_pure_function():
    from kryonsec.config import KryonsecConfig

    real = KaliSandbox(
        cfg=KryonsecConfig(home=Path("nothing")),
        run_fn=lambda argv, **kw: Completed(),
        seccomp_profile=None)
    good = real._docker_argv(["searchsploit", "-j"], network_mode="none")
    assert missing_network_none_flags(good) == []
    for wrong in (_strip_flag(good, "--network", "none"),
                  good + ["--dns", "1.1.1.1"]):
        assert missing_network_none_flags(wrong) != []


def _none_net_it_readiness():
    """Real Docker + runsc + pinned image + an operator lab endpoint."""
    lab = os.environ.get("KRYONSEC_NONE_NET_LAB_URL", "").strip()
    if not lab.lower().startswith(("http://", "https://")):
        return False, "KRYONSEC_NONE_NET_LAB_URL must be an http(s) lab URL"
    if not sys.platform.startswith("linux"):
        return False, "Mode B needs Linux"
    if shutil.which("docker") is None:
        return False, "docker CLI missing"
    if os.environ.get("KRYONSEC_NONE_NET_IT") != "1":
        return False, "KRYONSEC_NONE_NET_IT=1 not set"
    from kryonsec.purple import runtime_checks as rc

    ok, reason = rc.docker_server_ok()
    if not ok:
        return False, f"docker daemon: {reason}"
    if not rc.runsc_registered():
        return False, "runsc runtime not registered"
    from kryonsec.config import KryonsecConfig

    image = KryonsecConfig().sandbox_image
    if "@sha256:" not in image:
        return False, ("sandbox image is not digest-pinned in this "
                       "environment (rule 7) — set KRYONSEC_SANDBOX_IMAGE")
    if not rc.image_present(image):
        return False, f"pinned sandbox image absent: {image}"
    return True, ""


def test_real_network_none_blocks_lab_packets_it(tmp_path):
    """GENUINE isolation IT (opt-in): the real gVisor sandbox runs
    `curl` against the operator's LOCAL lab endpoint twice — once with
    default networking (the positive control; the lab must be
    REACHABLE), once with network_mode='none'. The none run MUST fail
    to reach the lab: same command, same lab, only the verified
    --network none isolation differs. Skipped silently otherwise.

        KRYONSEC_NONE_NET_IT=1 KRYONSEC_NONE_NET_LAB_URL=http://<your-lab> \
            .venv/bin/python -m pytest tests/test_mode_b_isolation.py
    """
    ok, reason = _none_net_it_readiness()
    if not ok:
        pytest.skip(f"opt-in IT not armed: {reason}")

    from kryonsec.config import KryonsecConfig

    lab = os.environ["KRYONSEC_NONE_NET_LAB_URL"].strip()
    sbx = KaliSandbox(
        cfg=KryonsecConfig(),
        seccomp_profile=None,
    )
    probe = ["curl", "-m", "6", "-sS", "-o", "/dev/null", lab]
    control = sbx.spawn(probe)
    if control.exit_code != 0 or not control.ok:
        pytest.skip(
            f"lab endpoint {lab} not reachable even with default "
            f"networking (curl exit {control.exit_code}) — operator "
            "environment, not an isolation answer")
    # the none run: identical command, only the isolation flag differs
    argv = sbx._docker_argv(probe, network_mode="none")
    assert argv[argv.index("--network") + 1] == "none"
    assert argv.index("--network") < argv.index(sbx.image)
    disconnected = sbx.spawn(probe, network_mode="none")
    assert disconnected.exit_code != 0, (
        "network-none run reached the lab — the isolation flag did not "
        "take effect on this image/runtime")
    # audit trail of the proof (the file stays local to the repo)
    audit = AuditLog(tmp_path / "none_net_it.jsonl")
    audit.write({
        "event": "network_none_block_it",
        "lab": lab,
        "control_exit": control.exit_code,
        "none_exit": disconnected.exit_code,
    })
    ok2, reason2 = audit.verify()
    assert ok2, reason2
