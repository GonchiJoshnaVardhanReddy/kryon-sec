"""Phase 2B.1 tests: the vetted ``docsafe`` MCP provider, end to end.

Every execution test here runs the REAL stdio transport: the actual
``python -m kryonsec.copilot.mcp_servers.docsafe`` server process,
driven through ``McpToolbox`` and governed by the real
``McpRegistry`` policy stack (startup gate, allowlist, schema
validation, path scope, approval, redaction, bounds, audit). The
provider is read-only: reads of operator-approved roots, no network,
no subprocess features, no scanning/exploitation of any kind.
"""

import json
import sys
from pathlib import Path

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.mcp_registry import UNTRUSTED_MARKER, McpRegistry
from kryonsec.copilot.mcp_tools import McpToolbox

DOCSAFE_MODULE = "kryonsec.copilot.mcp_servers.docsafe"
FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"
FAKE_TOKEN = "sk-BBBB2222CCCC3333DDDD4444EEEE5555"


def _make_root(tmp_path):
    """An operator-approved scope plus deliberately dangerous
    neighbors: a secret-bearing file (to prove redaction), protected
    credential files (to prove the deny-list), a symlink escaping the
    root (to prove canonical refusal), and a benign in-root symlink."""
    root = tmp_path / "docs_roots"
    docs = root / "docs"
    (docs / "nested").mkdir(parents=True)
    (docs / "a.txt").write_text("hello docsafe")
    (docs / "nested" / "b.md").write_text("# nested documentation")
    # a legit content file whose TEXT contains secret-shaped material
    (docs / "leak.txt").write_text(
        f"note: {FAKE_SECRET} and {FAKE_TOKEN} are required by the docs")
    # protected credential files under the SAME root — must be denied
    (docs / "api_key.pem").write_text("FAKE KEY MATERIAL, NEVER REAL")
    (docs / ".env").write_text("DB_PASSWORD=example")
    (docs / "id_rsa").write_text("FAKE RSA KEY MATERIAL, NEVER REAL")
    (docs / "team_token.txt").write_text("x")
    (docs / ".ssh").mkdir()
    (docs / ".ssh" / "config").write_text("x")
    # an in-root symlink (allowed) and an escaping symlink (refused)
    (docs / "alias.txt").symlink_to(docs / "a.txt")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside the approved scope")
    (docs / "esc.link").symlink_to(outside)
    return root, outside


def _row(root, **over):
    row = {
        "name": "docsafe",
        "command": sys.executable,
        "args": ["-m", DOCSAFE_MODULE, str(root)],
        "trust": "allow",
        "allow_tools": ["list_directory", "read_file"],
        "path_roots": [str(root)],
        "path_arguments": ["path"],
        "call_timeout_s": 30,
    }
    row.update(over)
    return row


def _connect(tmp_path, root, **over):
    """A REAL toolbox + registry over the real docsafe server."""
    cfg = KryonsecConfig(home=tmp_path, mcp_servers=[_row(root, **over)])
    box = McpToolbox(cfg)
    reg = McpRegistry(cfg, box)
    entries = box.connect_all(allow_start=reg.startup_allowance())
    return cfg, box, reg, entries


# ---- 1. disabled provider never launches --------------------------------------

def test_disabled_provider_never_launches_a_process(tmp_path):
    """The provider's row without explicit authorization: the built-in
    conservative startup gate (and the registry gate alike) refuses —
    no process, status visible as 'blocked', execution refused."""
    root, _ = _make_root(tmp_path)
    cfg = KryonsecConfig(home=tmp_path, mcp_servers=[_row(
        root, trust="disabled", allow_tools=["read_file", "list_directory"],
        path_roots=[str(root)], path_arguments=["path"])])
    box = McpToolbox(cfg)
    reg = McpRegistry(cfg, box)
    try:
        entries = box.connect_all(allow_start=reg.startup_allowance())
        assert entries == {}
        status = {s["name"]: s for s in box.statuses()}["docsafe"]
        assert status["status"] == "blocked"
        assert "not authorized" not in json.dumps(status)  # honest text
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/a.txt"})
        assert "not authorized" in out
        assert "mcp_tool_refused" in [e["event"] for e in _events(reg)]
    finally:
        box.close()


def test_no_policy_row_never_starts(tmp_path):
    """The docsafe row WITHOUT any trust keys: never a process."""
    root, _ = _make_root(tmp_path)
    bare = {"name": "docsafe", "command": sys.executable,
            "args": ["-m", DOCSAFE_MODULE, str(root)]}
    cfg = KryonsecConfig(home=tmp_path, mcp_servers=[bare])
    box = McpToolbox(cfg)
    try:
        assert box.connect_all() == {}
        assert {s["name"]: s for s in box.statuses()}["docsafe"] \
            ["status"] == "blocked"
    finally:
        box.close()


# ---- 2. explicit authorization permits startup ---------------------------------

def test_explicit_authorization_starts_and_lists(tmp_path):
    """Authorized row: the real docsafe process starts, connects, and
    its exact allowlisted tools are discoverable."""
    root, _ = _make_root(tmp_path)
    cfg, box, reg, entries = _connect(tmp_path, root)
    try:
        assert sorted(k.replace("mcp_", "") for k in entries) == \
            ["list_directory", "read_file"]
        listed = json.loads(reg.list_mcp_connections())
        assert listed["connections"][0]["status"] == "connected"
        assert listed["connections"][0]["call_trust"] == "allow"
        described = json.loads(reg.describe_mcp_connection("docsafe"))
        assert described["path_scope"] == [str(root)]
        ok, reason = reg.audit.verify()
        assert ok, reason
    finally:
        box.close()


# ---- 3./8. allowed read-only operations work; results are untrusted data -------

def test_allowed_read_operations_return_untrusted_data(tmp_path):
    root, _ = _make_root(tmp_path)
    cfg, box, reg, entries = _connect(tmp_path, root)
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/a.txt"})
        assert "hello docsafe" in out
        assert UNTRUSTED_MARKER in out        # framed as data, not truth
        # nested relative path
        out = reg.call_mcp_tool(
            "docsafe", "read_file", {"path": "docs/nested/b.md"})
        assert "# nested documentation" in out
        # an in-root symlink resolves INSIDE the scope and may be read
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/alias.txt"})
        assert "hello docsafe" in out
        listing = reg.call_mcp_tool("docsafe", "list_directory",
                                    {"path": "docs"})
        assert "a.txt" in listing and "nested/" in listing
        assert UNTRUSTED_MARKER in listing
        names = _event_names(reg)
        assert names.count("mcp_tool_invoked") == 4
    finally:
        box.close()


# ---- 4. unapproved operations fail closed --------------------------------------

def test_tool_outside_the_allowlist_fails_closed(tmp_path):
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(
        tmp_path, root, allow_tools=["list_directory"])
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/a.txt"})
        assert "not authorized" in out
        assert "mcp_tool_refused" in _event_names(reg)
    finally:
        box.close()


def test_trust_allow_without_allow_list_never_starts(tmp_path):
    """trust='allow' WITHOUT allow_tools: the Phase 2A.1 startup
    allowance still refuses (no bounded tool set is governed) —
    no process, status 'blocked'."""
    root, _ = _make_root(tmp_path)
    row = _row(root)
    del row["allow_tools"]
    cfg = KryonsecConfig(home=tmp_path, mcp_servers=[row])
    box = McpToolbox(cfg)
    reg = McpRegistry(cfg, box)
    try:
        entries = box.connect_all(allow_start=reg.startup_allowance())
        assert entries == {}
        assert {s["name"]: s for s in box.statuses()}["docsafe"] \
            ["status"] == "blocked"
    finally:
        box.close()


# ---- 5./6. scope violations, symlink escape, traversal --------------------------

def test_out_of_scope_absolute_path_is_refused_before_dispatch(tmp_path):
    """Registry-side canonical check: an absolute path whose realpath
    lands outside the approved roots is refused BEFORE the tool runs
    (audited)."""
    root, outside = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": str(outside)})
        assert "outside the approved resource scope" in out
        refused = [e for e in _events(reg)
                   if e["event"] == "mcp_tool_refused"]
        assert refused and "resource scope" in refused[-1]["reason"]
    finally:
        box.close()


def test_traversal_is_refused_by_registry_and_provider(tmp_path):
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/../../etc/passwd"})
        assert "traversal" in out
        assert "mcp_tool_refused" in _event_names(reg)
    finally:
        box.close()


def test_symlink_escape_is_refused(tmp_path):
    """A symlink INSIDE the root pointing outside: resolved canonically
    (by the provider here, by the registry for absolute paths) — the
    escape lands OUTSIDE and is refused as a tool error, not executed
    as a read."""
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/esc.link"})
        assert "outside" in out and "resource scope" in out
        assert "outside the approved scope" not in out
    finally:
        box.close()


def test_registry_refuses_symlink_escape_for_absolute_paths(tmp_path):
    """Defense in depth: the same escape via an ABSOLUTE symlink path
    is refused by the registry (realpath resolves the final symlink
    out of the roots) even before the provider."""
    root, outside = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        link = root / "docs" / "esc.link"
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": str(link)})
        assert "outside the approved resource scope" in out
    finally:
        box.close()


# ---- 7. invalid typed/nested arguments rejected ---------------------------------

def test_invalid_arguments_are_rejected(tmp_path):
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        assert "must be string" in reg.call_mcp_tool(
            "docsafe", "read_file", {"path": 42})
        assert "must be a non-empty path string" in reg.call_mcp_tool(
            "docsafe", "read_file", {"path": "   "})
        assert "unexpected argument" in reg.call_mcp_tool(
            "docsafe", "read_file", {"path": "docs/a.txt", "extra": 1})
    finally:
        box.close()


# ---- 9. secrets and protected material are unreachable/redacted -----------------

def test_secret_content_is_redacted_in_results_and_audit(tmp_path):
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/leak.txt"})
        assert FAKE_SECRET not in out
        assert FAKE_TOKEN not in out
        assert "SECRET" in out and ("«" in out or "redacted" in out
                                    or "…" in out)
        # the audit never carries raw results
        raw = open(reg.audit.path, encoding="utf-8").read()
        assert FAKE_SECRET not in raw and FAKE_TOKEN not in raw
        ok, reason = reg.audit.verify()
        assert ok, reason
    finally:
        box.close()


def test_protected_credential_files_are_denied_hidden(tmp_path):
    """The provider deny-list: key/env/id_rsa/token-named files under
    the approved root are unreachable and invisible in listings."""
    root, _ = _make_root(tmp_path)
    cfg, box, reg, _entries = _connect(tmp_path, root)
    try:
        for denied in ("docs/api_key.pem", "docs/.env", "docs/id_rsa",
                       "docs/team_token.txt", "docs/.ssh/config"):
            out = reg.call_mcp_tool("docsafe", "read_file",
                                    {"path": denied})
            assert "protected credential/secret material" in out \
                or "denied by the provider" in out, denied
        listing = reg.call_mcp_tool("docsafe", "list_directory",
                                    {"path": "docs"})
        assert "a.txt" in listing
        for forbidden in ("api_key.pem", ".env", "id_rsa",
                          "team_token.txt", ".ssh"):
            assert forbidden not in listing
        assert "protected/credential item(s) hidden" in listing
    finally:
        box.close()


def test_ask_approval_preview_redacts_secret_shaped_argument(tmp_path):
    """trust='ask': the human gate shows identity/origin/operation and
    a bounded preview of arguments — secret-shaped VALUES are redacted
    in the preview and never reach the audit."""
    root, _ = _make_root(tmp_path)
    seen = []
    cfg, box, reg, _entries = _connect(tmp_path, root, trust="ask",
                                       allow_tools=["read_file"])
    try:
        reg.approver = lambda req: seen.append(req) or False
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": f"docs/a.txt?{FAKE_SECRET}"})
        assert "not approved" in out
        request = seen[-1]
        assert request.tool == "read_file"
        assert FAKE_SECRET not in json.dumps(request.arguments_preview)
        assert "SECRET" in request.arguments_preview["path"]
        assert FAKE_SECRET not in open(reg.audit.path,
                                       encoding="utf-8").read()
        assert "mcp_tool_invoked" not in _event_names(reg)
        # the read never executed
    finally:
        box.close()


def test_ask_approval_gate_receives_scope_context(tmp_path):
    """With the real terminal-shaped gate (captured), the approval
    request carries identity, the bounded path preview, and origin."""
    root, _ = _make_root(tmp_path)
    seen = []
    cfg, box, reg, _entries = _connect(
        tmp_path, root, trust="ask",
        allow_tools=["read_file"])
    try:
        reg.approver = lambda req: seen.append(req) or True
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/a.txt"})
        request = seen[-1]
        assert out.startswith("path:")
        assert request.connection == "docsafe"
        assert request.tool == "read_file"
        assert request.resource == "docs/a.txt"
        assert "read-only" in request.description.casefold() or \
            "approved" in request.description.casefold()
        assert request.arguments_preview["path"] == "docs/a.txt"
        assert "mcp_tool_approved" in _event_names(reg)
    finally:
        box.close()


# ---- 10. connection failure cleanup ---------------------------------------------

def test_connection_failure_fails_closed_and_cleans_up(tmp_path):
    """An authorized row whose command cannot start: connect is honest
    (nothing exposed), close() cleans up, and execution is refused."""
    root, _ = _make_root(tmp_path)
    row = _row(root, command="kryonsec-no-such-bin-2b1")
    cfg = KryonsecConfig(home=tmp_path, mcp_servers=[row])
    box = McpToolbox(cfg)
    reg = McpRegistry(cfg, box)
    try:
        entries = box.connect_all(allow_start=reg.startup_allowance())
        assert entries == {}
        assert {s["name"]: s for s in box.statuses()}["docsafe"] \
            ["status"] == "disconnected"
        out = reg.call_mcp_tool("docsafe", "read_file",
                                {"path": "docs/a.txt"})
        assert ("not usable" in out) or ("disconnected" in out)
        described = json.loads(reg.describe_mcp_connection("docsafe"))
        assert described["status"] == "disconnected"
        assert described["healthy"] is False
    finally:
        box.close()                                   # must not raise
        assert box.connections == []


def test_registry_refuses_scope_misconfiguration(tmp_path):
    """An operator row naming path_arguments without path_roots is
    refused at policy construction (fail loud, fail early)."""
    import pytest
    from kryonsec.copilot.mcp_registry import McpPolicyError
    root, _ = _make_root(tmp_path)
    bad = _row(root)
    del bad["path_roots"]
    with pytest.raises(McpPolicyError):
        McpRegistry(KryonsecConfig(home=tmp_path, mcp_servers=[bad]),
                    None)


# ---- 11. shipped wiring cannot bypass --------------------------------------------

def test_shipped_wiring_cannot_bypass(tmp_path):
    """Re-run the bypass scan against the CURRENT tree: cli and UI must
    expose only the registry's five operations and must gate startup
    (covered in detail by test_mcp_registry.test_no_legacy_* — asserted
    here for this phase's file too)."""
    src = Path(__file__).parent.parent / "src" / "kryonsec"
    cli = (src / "cli.py").read_text(encoding="utf-8")
    assert "mcp_extra = (mcp_registry.llm_tools()" in cli.replace(
        "\n", " ") or "mcp_registry.llm_tools()" in cli
    assert "startup_allowance()" in cli
    assert "mcp_toolbox.snapshot" not in cli
    ui_workspace = (src / "ui" / "workspace.py").read_text(encoding="utf-8")
    assert "mcp_toolbox.snapshot" not in ui_workspace


# ---- 12. Mode B never sees the provider ------------------------------------------

def test_mode_b_sources_never_reference_the_provider():
    """The provider is Mode A host-side assistance. No purple module may
    even name it (and existing isolation tests keep runner.py MCP-free)."""
    purple = Path(__file__).parent.parent / "src" / "kryonsec" / "purple"
    offenders = []
    for path in purple.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "docsafe" in text or "mcp_servers" in text:
            offenders.append(path.name)
    assert offenders == []


# ---- helpers ----------------------------------------------------------------------

def _events(reg):
    return [json.loads(line) for line in
            open(reg.audit.path, encoding="utf-8") if line.strip()]


def _event_names(reg):
    return [e["event"] for e in _events(reg)]
