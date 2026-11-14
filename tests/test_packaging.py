"""Wheel packaging invariants.

The v1.3.11 preflight caught a silent packaging bug: pyproject.toml
declared ``nuclei_manifest.json`` under the ``kryonsec`` package-data key,
but the file lives in the ``kryonsec.purple`` subpackage (the adapter
resolves it next to itself via ``__file__``) — so the pattern matched
nothing, the wheel shipped without the manifest, and a wheel-installed
RECON_ACTIVE raised NucleiPolicyError at registry build (fail-closed, but
Mode B was dead on arrival for wheel installs; tests run from the repo
never saw it because the real file was present on disk).

These tests guard the CLASS of mistake: every declared package-data glob
must resolve to at least one real file in the source tree, and the
manifest specifically must be covered under its real subpackage.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: the reviewed nuclei template manifest — the file whose packaging the
#: v1.3.11 preflight caught missing from the wheel
NUCLEI_MANIFEST_REL = Path("kryonsec/purple/nuclei_manifest.json")


def _package_data() -> dict[str, list[str]]:
    with PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    return data["tool"]["setuptools"]["package-data"]


def test_every_package_data_pattern_matches_a_real_file():
    """A pattern that matches nothing ships nothing — and never loudly.

    v1.3.10's wheel shipped without the nuclei manifest for exactly this
    reason (wrong package key), because the source-tree copy kept tests
    green. Every glob must be proven to match >= 1 file under src/.
    """
    patterns = _package_data()
    assert patterns, "package-data table missing from pyproject.toml"

    unmatched: list[str] = []
    for package, globs in patterns.items():
        package_dir = SRC_ROOT / package.replace(".", "/")
        if not package_dir.is_dir():
            unmatched.append(f"{package}: package directory does not exist")
            continue
        for pattern in globs:
            if not list(package_dir.glob(pattern)):
                unmatched.append(f"{package}: pattern {pattern!r} matches nothing")
    assert not unmatched, (
        "package-data entries that would silently ship nothing "
        f"(wheel omits the files): {unmatched}"
    )


def test_nuclei_manifest_ships_from_the_purple_subpackage():
    """The exact regression: the manifest is declared with its DIRECTORY
    (purple/...) because the adapter loads it from the purple subpackage
    via __file__ — a bare name resolves against src/kryonsec/ and ships
    nothing."""
    package_data = _package_data()
    kryonsec_globs = package_data.get("kryonsec")
    assert kryonsec_globs, (
        "pyproject.toml declares no package-data for kryonsec"
    )
    manifest = SRC_ROOT / NUCLEI_MANIFEST_REL
    assert manifest.exists(), (
        f"{NUCLEI_MANIFEST_REL} missing from the source tree"
    )

    # one of the declared globs must actually match the manifest file,
    # so a later move or rename of the file cannot re-break packaging
    # silently (the parent test catches never-matching patterns, but
    # this names the one file Mode B dies without)
    matched = any(
        str(p.resolve()) == str(manifest.resolve())
        for pattern in kryonsec_globs
        for p in (SRC_ROOT / "kryonsec").glob(pattern)
    )
    assert matched, (
        f"{NUCLEI_MANIFEST_REL} is not matched by any kryonsec "
        f"package-data glob {kryonsec_globs} — the wheel would ship "
        "without it and wheel-installed RECON_ACTIVE would fail closed"
    )


def test_nuclei_manifest_not_orphaned_under_the_parent_key():
    """A BARE manifest entry under the ``kryonsec`` key is exactly the
    v1.3.10 bug (resolves against src/kryonsec/, matches nothing)."""
    package_data = _package_data()
    orphaned = [p for p in package_data.get("kryonsec", [])
                if p == "nuclei_manifest.json"]
    assert not orphaned, (
        "nuclei_manifest.json declared bare under the `kryonsec` "
        "package-data key resolves against src/kryonsec/ and matches "
        "nothing (the file lives in the purple subpackage); declare it "
        "as 'purple/nuclei_manifest.json'"
    )
    assert not (SRC_ROOT / "kryonsec" / "nuclei_manifest.json").exists(), (
        "a stale nuclei_manifest.json copy sits at src/kryonsec/ — the "
        "adapter would still load the purple one and the parent copy "
        "would ship needlessly"
    )
