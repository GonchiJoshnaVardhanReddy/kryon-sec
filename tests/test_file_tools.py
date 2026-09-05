"""Tests for copilot file tools (spec §3.7 + v1.1): scoping and approval.

v1.1 rule change: writes outside the workspace are no longer blocked —
they follow the same approval gate as reads (user decision:
"anywhere, with approval")."""

import pytest

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
