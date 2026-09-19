"""Tests for copilot file tools (spec §3.7 + v1.1): scoping and approval.

v1.1 rule change: writes outside the workspace are no longer blocked —
they follow the same approval gate as reads (user decision:
"anywhere, with approval")."""

import pytest

from pathlib import Path

from kryonsec.config import KryonsecConfig
from kryonsec.copilot.tools import ApprovalRequest, FileAccessDenied, FileTools


@pytest.fixture()
def env(tmp_path):
    cfg = KryonsecConfig(home=tmp_path / "home", workspace=tmp_path / "ws")
    cfg.ensure_dirs()
    (cfg.workspace / "notes.txt").write_text("workspace content")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret outside file")
    return cfg, outside


def test_workspace_read_no_approval(env):
    cfg, _ = env
    tools = FileTools(cfg, approver=lambda req: pytest.fail("should not ask"))
    assert "workspace content" in tools.read_file(str(cfg.workspace / "notes.txt"))


def test_outside_read_denied_without_approval(env):
    cfg, outside = env
    tools = FileTools(cfg, approver=lambda req: False)
    with pytest.raises(FileAccessDenied):
        tools.read_file(str(outside))


def test_outside_read_allowed_with_approval(env):
    cfg, outside = env
    tools = FileTools(cfg, approver=lambda req: True)
    assert "secret outside file" in tools.read_file(str(outside))


def test_outside_write_denied_without_approval(env):
    cfg, _ = env
    tools = FileTools(cfg, approver=lambda req: False)
    with pytest.raises(FileAccessDenied):
        tools.write_file(str(cfg.home / "evil.txt"), "nope")


def test_outside_write_allowed_with_approval(env):
    cfg, _ = env
    seen: list[ApprovalRequest] = []

    def approver(req: ApprovalRequest) -> bool:
        seen.append(req)
        return True

    tools = FileTools(cfg, approver=approver)
    p = tools.write_file(str(cfg.home / "ok.txt"), "approved content")
    assert p.read_text() == "approved content"
    assert seen[0].action == "write"  # request says write, not read


def test_write_inside_workspace_ok(env):
    cfg, _ = env
    tools = FileTools(cfg, approver=lambda req: pytest.fail("should not ask"))
    p = tools.write_file(str(cfg.workspace / "new" / "file.txt"), "hello")
    assert p.read_text() == "hello"


def test_traversal_write_still_gated(env):
    """../-escape from the workspace resolves outside it — must hit the
    approval gate, not silently write."""
    cfg, _ = env
    tools = FileTools(cfg, approver=lambda req: False)
    with pytest.raises(FileAccessDenied):
        tools.write_file(str(cfg.workspace / ".." / "escape.txt"), "nope")


def test_traversal_write_allowed_when_approved(env):
    cfg, _ = env
    tools = FileTools(cfg, approver=lambda req: True)
    p = tools.write_file(str(cfg.workspace / ".." / "approved-escape.txt"), "ok")
    assert p.is_file()


# --- symlinks out of the workspace (prompt must name the real target) -------

def test_workspace_symlink_to_outside_still_asks(env):
    """The gate is right to fire — don't regress that while fixing the prompt."""
    cfg, outside = env
    link = cfg.workspace / "innocent.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - needs privilege
        pytest.skip("symlinks not permitted on this platform")

    asked = []

    def approver(req: ApprovalRequest) -> bool:
        asked.append(req)
        return False

    tools = FileTools(cfg, approver=approver)
    with pytest.raises(FileAccessDenied):
        tools.read_file(str(link))
    assert len(asked) == 1


def test_symlink_approval_request_names_the_real_target(env):
    """Approving "read /ws/innocent.txt" must not secretly read /etc/shadow.

    _needs_approval() judges the RESOLVED path, but the prompt showed the
    unresolved one — so a workspace symlink pointing anywhere on the host was
    approved under a harmless-looking workspace name.
    """
    cfg, outside = env
    link = cfg.workspace / "innocent.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks not permitted on this platform")

    seen = {}

    def approver(req: ApprovalRequest) -> bool:
        seen["req"] = req
        return True

    tools = FileTools(cfg, approver=approver)
    assert tools.read_file(str(link)) == "secret outside file"

    req = seen["req"]
    assert req.path == outside.resolve()            # the real target
    assert req.requested_path == link.absolute()    # what the agent named
    assert req.requested_path != req.path           # and they differ, visibly


def test_no_false_alarm_for_ordinary_paths(env):
    """A plain relative path resolves to itself — no scary two-line prompt."""
    cfg, outside = env
    seen = {}

    def approver(req: ApprovalRequest) -> bool:
        seen["req"] = req
        return True

    tools = FileTools(cfg, approver=approver)
    tools.read_file(str(outside))
    assert seen["req"].requested_path is None


def test_always_approved_is_keyed_on_the_resolved_path(env):
    """"always" must not be reusable by a different file with the same name."""
    cfg, outside = env
    link = cfg.workspace / "innocent.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks not permitted on this platform")

    # a second symlink with a DIFFERENT workspace name, same target
    other_link = cfg.workspace / "other.txt"
    other_link.symlink_to(outside)

    asked = []

    class Always:
        def __call__(self, req):
            asked.append(req)
            return True

    tools = FileTools(cfg, approver=Always())
    # simulate the "[Y] always" path by recording the resolved path
    tools._always_approved.add(link.resolve())
    tools.read_file(str(other_link))
    # same resolved target → legitimately no second prompt
    assert len(asked) == 0
    assert link.resolve() == other_link.resolve()


def test_request_marks_a_differing_resolution(env, monkeypatch):
    """Platform-independent version of the symlink case above.

    Real symlinks need a privilege on Windows, so this pins the behaviour of
    _request() directly: when the resolved target differs from the name the
    agent used, the request must carry both.
    """
    cfg, outside = env
    tools = FileTools(cfg, approver=lambda req: True)

    # resolve() BEFORE patching, or the patched version recurses into itself
    real_target = outside.resolve()
    named = cfg.workspace / "innocent.txt"
    monkeypatch.setattr(Path, "resolve", lambda self, **kw: real_target)

    req = tools._request(named, "Agent file read", "read")
    assert req.path == real_target
    assert req.requested_path == named.absolute()
    assert req.requested_path != req.path


def test_request_has_no_requested_path_when_they_agree(env, monkeypatch):
    """A plain absolute path resolves to itself — one clean line in the prompt."""
    cfg, outside = env
    tools = FileTools(cfg, approver=lambda req: True)
    real_target = outside.resolve()
    monkeypatch.setattr(Path, "resolve", lambda self, **kw: real_target)

    req = tools._request(outside.absolute(), "Agent file read", "read")
    assert req.requested_path is None


def test_prompt_approve_shows_the_real_target(env, monkeypatch):
    """End-to-end: the [A]/[Y]/[D] prompt must name the resolved file."""
    cfg, outside = env
    tools = FileTools(cfg)  # default _prompt_approve

    real_target = outside.resolve()
    named = cfg.workspace / "innocent.txt"
    monkeypatch.setattr(Path, "resolve", lambda self, **kw: real_target)

    # input() is what PRINTS the prompt, so a stub has to capture its argument
    prompts: list[str] = []
    monkeypatch.setattr(
        "builtins.input", lambda prompt="", *a, **kw: (prompts.append(prompt), "a")[1]
    )

    assert tools._prompt_approve(tools._request(named, "why", "read")) is True
    text = "".join(prompts)
    assert str(real_target) in text        # the real target is shown
    assert str(named.absolute()) in text   # and what the agent asked for
