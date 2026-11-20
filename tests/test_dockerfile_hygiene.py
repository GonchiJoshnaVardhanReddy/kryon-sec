"""Source-level guards for the Zone B sandbox image build.

These are NOT a build (a cold build is ~45 minutes and needs the network).
They pin the invariants the 2026-11-18 image optimization introduced, so a
later edit cannot silently undo them: a moving base tag, an apt layer that
re-downloads its lists because the cache was wiped, or a docs trim that drops
the licence texts from a distributable image.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "containers" / "sandbox" / "Dockerfile.kali"


def _text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _code() -> str:
    """Dockerfile text without full-line comments (which discuss the rules)."""
    return "\n".join(
        line for line in _text().splitlines()
        if not line.lstrip().startswith("#")
    )


def test_base_image_is_pinned_by_digest():
    from_lines = [line for line in _text().splitlines()
                  if line.startswith("FROM ")]
    assert from_lines, "Dockerfile has no FROM line"
    for line in from_lines:
        assert "@sha256:" in line, (
            f"base image is not digest-pinned: {line!r} — a moving tag makes "
            "the same Dockerfile build different images over time")
        assert ":latest" not in line, (
            f"base image still tracks a mutable tag: {line!r}")


def _run_blocks() -> list[str]:
    """Logical RUN instructions (backslash continuations joined)."""
    blocks: list[str] = []
    current: list[str] = []
    for line in _code().splitlines():
        if current:
            current.append(line)
            if not line.rstrip().endswith("\\"):
                blocks.append("\n".join(current))
                current = []
        elif line.startswith("RUN "):
            current = [line]
            if not line.rstrip().endswith("\\"):
                blocks.append(line)
                current = []
    return blocks


def test_every_apt_install_uses_the_shared_cache_mounts():
    apt_blocks = [block for block in _run_blocks()
                  if "apt-get install" in block]
    assert len(apt_blocks) == 4, (
        "expected the four deliberate apt blocks (core, seclists, extended, "
        f"Phase 4); found {len(apt_blocks)}")
    for block in apt_blocks:
        assert "--mount=type=cache,target=/var/lib/apt/lists" in block, (
            "apt-get install without an APT lists cache mount — the layer "
            "re-downloads package lists on every build")
        assert "--mount=type=cache,target=/var/cache/apt" in block, (
            "apt-get install without an APT archive cache mount — every "
            "rebuild re-downloads the .debs")


def test_apt_lists_are_not_deleted_from_the_cache_mount():
    # With the cache mount the lists live outside the image layer. Deleting
    # them inside the RUN wipes the cache that makes rebuilds cheap.
    assert "rm -rf /var/lib/apt/lists" not in _code(), (
        "the APT lists cache mount is being wiped by an rm in the same RUN")


def test_pip_uses_a_cache_mount_instead_of_no_cache_dir():
    code = _code()
    assert "target=/root/.cache/pip" in code, (
        "pip installs have no BuildKit cache mount — every rebuild "
        "re-downloads the wheels")
    assert "--no-cache-dir" not in code, (
        "--no-cache-dir defeats the pip cache mount (the mount already keeps "
        "wheels out of the image layer)")


def test_docs_trim_keeps_the_licence_texts():
    code = _code()
    assert "path-exclude=/usr/share/doc/*" in code
    assert "path-include=/usr/share/doc/*/copyright" in code, (
        "the docs trim must keep copyright files: this image is distributed "
        "and the licences have to travel with the binaries")


def test_manifest_copy_runs_after_the_tool_install_layers():
    # A COPY invalidates every later layer. The manifest is edited whenever
    # templates are re-reviewed, so it must sit after the ~6.6 GB of apt/pip/
    # GitHub tool layers, not in the middle of them.
    code = _code()
    manifest = code.index("COPY src/kryonsec/purple/nuclei_manifest.json")
    assert manifest > code.rindex("EXTENDED_TOOLS"), (
        "nuclei_manifest.json is COPYed before the tool-install layers — "
        "every template review would re-download the whole toolset")
    assert manifest > code.rindex("pip install"), (
        "nuclei_manifest.json is COPYed before the pip tool layers")


def test_every_registered_recon_adapter_executable_is_required_by_the_build():
    """A registered adapter whose binary can vanish is a dead lane.

    The REQUIRED-tool block is what makes a release image fail closed. Adding
    an adapter without adding its executable here would let a digest look
    valid while the lane cannot run at all.
    """
    from kryonsec.purple.adapter_whatweb import recon_active_registry

    code = _code()
    missing = []
    for adapter in recon_active_registry().list_adapters():
        executable = adapter.executable
        needle = (
            f"check_file {executable}"
            if executable.startswith("/")
            else f"check_cmd {executable}"
        )
        if needle not in code:
            missing.append(needle)
    assert not missing, (
        "registered RECON_ACTIVE adapter executables are not checked by the "
        f"image build guard: {missing}")