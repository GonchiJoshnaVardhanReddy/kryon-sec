"""Ensure the package source is on sys.path for test runs (works even when
the package is not installed editable). The package lives at src/kryonsec —
inserting the repo root alone would not make `import kryonsec` work."""

import sys
from pathlib import Path

import pytest

src = Path(__file__).resolve().parents[1] / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))


@pytest.fixture(autouse=True)
def _member(request, monkeypatch):
    """Purple Team is a paid feature, and this suite drives it with no key.

    Every test that runs an engagement would otherwise stop at the membership
    gate and assert against a refusal instead of the behaviour it names. The
    gate is stood down for the suite and kept standing in test_license.py,
    which is the file that exists to prove it refuses — patching it there
    would leave those tests checking the stub.

    NB: patched on `kryonsec.license`, not `kryonsec.cli`. cli._run_purple
    imports the name inside the function body, so it looks it up on the
    module at call time — patching the module is what takes effect.
    """
    if Path(str(request.node.fspath)).name == "test_license.py":
        return
    from kryonsec import license

    monkeypatch.setattr(
        license, "ensure_purple_allowed",
        lambda cfg: license.VerifyResult(status=license.VALID, message="test member"),
    )

