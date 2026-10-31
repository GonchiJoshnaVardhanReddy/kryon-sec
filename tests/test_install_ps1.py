"""Regression tests for the Windows installer's wheel integrity checks.

The release endpoint sends the wheel's SHA-256 in
``X-Kryonsec-Wheel-SHA256``. A downloaded wheel without that metadata must not
be installed: a proxy, a misconfigured deployment, or an older server must not
be able to turn integrity verification off silently.

PowerShell is not a declared test dependency on every platform, so the
execution tests skip when neither ``pwsh`` nor ``powershell`` is available.
The source assertion always runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = ROOT / "install.ps1"
WHEEL_BYTES = b"\x01\x02\x03"
WHEEL_SHA256 = hashlib.sha256(WHEEL_BYTES).hexdigest()


def _powershell() -> str | None:
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _extract_function(source: str, name: str) -> str:
    start = source.index(f"function {name}")
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function {name}")


def _run_verify(
    tmp_path: Path,
    *,
    header_sha: str | None = None,
    env_sha: str | None = None,
    require_metadata: bool = True,
) -> str:
    shell = _powershell()
    assert shell, "PowerShell is required for this test"

    function = _extract_function(
        INSTALL_PS1.read_text(encoding="utf-8"), "Verify-WheelHash"
    )
    (tmp_path / "wheel.whl").write_bytes(WHEEL_BYTES)
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "\n".join(
            [
                '$ErrorActionPreference = "Stop"',
                'function Die($msg) { throw "DIE: $msg" }',
                'function Say($msg) { Write-Output $msg }',
                function,
                '$wheel = Join-Path $env:KRYO_TEST_DIR "wheel.whl"',
                "$headers = $null",
                'if ($env:KRYO_HEADER_SHA) {',
                "  $headers = [System.Collections.Generic.Dictionary[string,string]]::new()",
                '  $headers["X-Kryonsec-Wheel-SHA256"] = $env:KRYO_HEADER_SHA',
                "}",
                "try {",
                '  if ($env:KRYO_REQUIRE -eq "1") {',
                "    Verify-WheelHash $wheel $headers -RequireMetadata",
                "  } else {",
                "    Verify-WheelHash $wheel $headers",
                "  }",
                '  "PROCEEDED"',
                "} catch {",
                '  "REFUSED: " + $_.Exception.Message',
                "}",
            ]
        ),
        encoding="utf-8",
    )

    env = {key: value for key, value in os.environ.items() if key != "KRYONSEC_WHEEL_SHA256"}
    env["KRYO_TEST_DIR"] = str(tmp_path)
    env["KRYO_REQUIRE"] = "1" if require_metadata else "0"
    if header_sha is not None:
        env["KRYO_HEADER_SHA"] = header_sha
    if env_sha is not None:
        env["KRYONSEC_WHEEL_SHA256"] = env_sha

    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_installer_does_not_use_an_unsupported_response_header_parameter():
    source = INSTALL_PS1.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )

    assert "-ResponseHeadersVariable" not in code
    assert "-PassThru" in code


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_download_without_hash_metadata_is_refused(tmp_path: Path):
    output = _run_verify(tmp_path)
    assert "REFUSED" in output
    assert "verification metadata" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_matching_response_header_is_accepted(tmp_path: Path):
    output = _run_verify(tmp_path, header_sha=WHEEL_SHA256)
    assert "PROCEEDED" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_mismatched_response_header_is_refused(tmp_path: Path):
    output = _run_verify(tmp_path, header_sha="0" * 64)
    assert "REFUSED" in output
    assert "does not match" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_explicit_environment_hash_is_accepted(tmp_path: Path):
    output = _run_verify(tmp_path, env_sha=WHEEL_SHA256)
    assert "PROCEEDED" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_local_wheel_override_without_metadata_still_works(tmp_path: Path):
    # The documented air-gapped/support path passes a local .whl and no
    # headers. It remains usable, but the script says the artifact was not
    # verified instead of implying that it was.
    output = _run_verify(tmp_path, require_metadata=False)
    assert "PROCEEDED" in output
    assert "without release metadata" in output


# --- the Windows installer's browser approval ---------------------------------


def _function_source(name: str) -> str:
    source = INSTALL_PS1.read_text(encoding="utf-8")
    assert f"function {name}" in source, f"{name} is not implemented"
    return _extract_function(source, name)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        self._respond()

    def do_POST(self):  # noqa: N802
        self._respond()

    def _respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw) if raw else None
        self.server.seen.append({"method": self.command, "path": self.path, "body": body})
        status, payload, headers = self.server.replies.pop(0)
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


@contextmanager
def _serve(replies):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.replies = list(replies)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()


def _run_ps(tmp_path: Path, functions: list[str], body: str, *, site: str) -> str:
    shell = _powershell()
    assert shell, "PowerShell is required for this test"
    harness = tmp_path / "device-harness.ps1"
    harness.write_text(
        "\n".join(
            [
                '$ErrorActionPreference = "Stop"',
                'function Die($msg) { throw "DIE: $msg" }',
                'function Say($msg) { Write-Output $msg }',
                *[_function_source(name) for name in functions],
                body,
            ]
        ),
        encoding="utf-8",
    )
    env = {key: value for key, value in os.environ.items() if key != "KRYONSEC_WHEEL_SHA256"}
    env["KRYO_SITE"] = site
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _run_ps_real_die(tmp_path: Path, functions: list[str], body: str, *, site: str):
    """Run the harness with the installer's own Die, so exit-1 is under test.

    The other harnesses redefine Die to `throw` so a refusal can be read from
    the output; that redefinition cannot prove the script actually stops.
    """
    shell = _powershell()
    assert shell, "PowerShell is required for this test"
    harness = tmp_path / "stop-harness.ps1"
    harness.write_text(
        "\n".join(
            [
                '$ErrorActionPreference = "Stop"',
                _function_source("Die"),
                *[_function_source(name) for name in functions],
                body,
            ]
        ),
        encoding="utf-8",
    )
    env = {key: value for key, value in os.environ.items() if key != "KRYONSEC_WHEEL_SHA256"}
    env["KRYO_SITE"] = site
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return result.returncode, result.stdout


def _closed_site() -> str:
    """A port nothing listens on — what an unreachable site looks like here."""
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}"


def test_installer_obtains_a_fresh_download_token_without_embedding_one():
    source = INSTALL_PS1.read_text(encoding="utf-8")
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))

    assert "function Start-BetaDevice" in code
    assert "function Wait-BetaDownloadUrl" in code
    assert re.search(r"purpose\s*=\s*\"download\"", code)
    assert "download_url" in code
    assert not re.search(r"\bdl_[0-9a-f]{64}\b", code)
    assert not re.search(r"\bs_[0-9a-f]{64}\b", code)
    assert "Invoke-Expression" not in code


def test_installer_binds_server_urls_to_the_configured_site():
    start = _function_source("Start-BetaDevice")
    poll = _function_source("Wait-BetaDownloadUrl")

    # The approval link is opened and the download link is fetched; both must be
    # checked against $Site before either happens.
    assert start.index("Same-SiteOrigin $Site") < start.index("Start-Process $started.url")
    assert poll.index("Same-SiteOrigin $Site") < poll.index("return $url")


def test_installer_separates_a_refusal_from_an_absent_route():
    start = _function_source("Start-BetaDevice")

    # Only "this deployment has no sign-in" may fall back to the key prompt; a
    # refusal, a broken answer, or an unreachable site says what it was.
    assert "404, 503" in start
    assert "does not offer browser sign-in" in start
    assert "return $null" in start
    assert start.count("return $null") == 2
    assert "could not reach" in start
    assert "does not understand" in start


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_sends_the_installer_identity_and_hides_the_secret(tmp_path: Path):
    secret = "a" * 64
    with _serve([]) as (site, server):
        server.replies[:] = [
            (
                200,
                {
                    "url": f"{site}/beta/device?code=AB12-CD34",
                    "code": "AB12-CD34",
                    "device_code": secret,
                    "expires_in_min": 15,
                },
                {},
            )
        ]
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
$device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
"DEVICE_STARTED"
"URL=" + $device.url
"CODE=" + $device.code
""",
            site=site,
        )

    assert "DEVICE_STARTED" in output
    assert "AB12-CD34" in output
    assert secret not in output, "the device_code is a secret and must never be printed"
    assert server.seen[0]["path"] == "/api/beta/device/start"
    assert server.seen[0]["body"]["os"] == "Windows"
    assert server.seen[0]["body"]["version"] == "installer"


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_reports_an_unconfigured_site(tmp_path: Path):
    with _serve([(503, {"error": "login is not configured"}, {})]) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
$device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
if ($null -eq $device) { "NO_DEVICE" } else { "DEVICE_STARTED" }
""",
            site=site,
        )

    assert "NO_DEVICE" in output
    assert "does not offer browser sign-in" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_refuses_an_approval_link_for_another_site(tmp_path: Path):
    # The approval link is the thing a person opens and the download link is
    # the thing that carries the credential. Neither is allowed to point
    # somewhere else, because whoever answers the request also chooses the
    # bytes and the hash the installer would then match against.
    other = "http://elsewhere.example"
    with _serve(
        [
            (
                200,
                {
                    "url": f"{other}/beta/device?code=AB12-CD34",
                    "code": "AB12-CD34",
                    "device_code": "a" * 64,
                    "expires_in_min": 15,
                },
                {},
            )
        ]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
try {
  $device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
  if ($null -eq $device) { "NO_DEVICE" } else { "DEVICE_STARTED" }
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "different site" in output
    assert "DEVICE_STARTED" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_same_site_origin_accepts_only_the_configured_authority(tmp_path: Path):
    output = _run_ps(
        tmp_path,
        ["Same-SiteOrigin"],
        """
$cases = @(
  @{ name = "same host"; url = "https://kryonsec.in/beta/device?code=AB"; want = "yes" }
  @{ name = "trailing slash"; url = "https://kryonsec.in"; want = "yes" }
  @{ name = "other host"; url = "https://elsewhere.example/download"; want = "no" }
  @{ name = "other scheme"; url = "http://kryonsec.in/download"; want = "no" }
  @{ name = "other port"; url = "https://kryonsec.in:8443/download"; want = "no" }
  @{ name = "trusted-looking prefix"; url = "https://kryonsec.in@elsewhere.example/d"; want = "no" }
  @{ name = "relative"; url = "/api/beta/download?t=dl_abc"; want = "no" }
  @{ name = "empty"; url = ""; want = "no" }
)
foreach ($case in $cases) {
  $got = if (Same-SiteOrigin $env:KRYO_SITE $case.url) { "yes" } else { "no" }
  $case.name + " => " + $got + " (want " + $case.want + ")"
}
""",
        site="https://kryonsec.in",
    )

    verdicts = {}
    for line in output.splitlines():
        if "=>" not in line:
            continue
        left, want = line.split("(")
        name, got = left.split("=>")
        verdicts[name.strip()] = (got.strip(), want.removeprefix("want ").rstrip(")"))
        assert verdicts[name.strip()][0] == verdicts[name.strip()][1], line

    assert len(verdicts) == 8
    assert verdicts["same host"][0] == "yes"
    assert verdicts["other host"][0] == "no"
    assert verdicts["trusted-looking prefix"][0] == "no"


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_refuses_a_link_that_only_looks_like_the_site(tmp_path: Path):
    # A person reads the front of a URL. "https://kryonsec.in@elsewhere" opens
    # elsewhere while showing the name they trust, so credentials in the link
    # are refused even though the host itself would match.
    with _serve([]) as (site, server):
        host_and_port = site.split("//", 1)[1]
        server.replies[:] = [
            (
                200,
                {
                    "url": f"http://kryonsec.in@{host_and_port}/beta/device?code=AB12-CD34",
                    "code": "AB12-CD34",
                    "device_code": "a" * 64,
                    "expires_in_min": 15,
                },
                {},
            )
        ]
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
try {
  $device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
  if ($null -eq $device) { "NO_DEVICE" } else { "DEVICE_STARTED" }
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "different site" in output
    assert "DEVICE_STARTED" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_names_a_refusal_instead_of_calling_it_absent(tmp_path: Path):
    with _serve([(429, {"error": "too many sign-in attempts just now"}, {})]) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
try {
  $device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
  if ($null -eq $device) { "FELL_BACK" } else { "DEVICE_STARTED" }
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "429" in output
    # A rate-limited site is not a site without beta login, and telling someone
    # who has no membership key to go find one sends them to the wrong door.
    assert "FELL_BACK" not in output
    assert "membership key" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_says_an_unreachable_site_is_unreachable(tmp_path: Path):
    output = _run_ps(
        tmp_path,
        ["Same-SiteOrigin", "Start-BetaDevice"],
        """
try {
  $device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
  if ($null -eq $device) { "FELL_BACK" } else { "DEVICE_STARTED" }
} catch { "REFUSED: " + $_.Exception.Message }
""",
        site=_closed_site(),
    )

    assert "REFUSED" in output
    assert "could not reach" in output
    assert "does not offer" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_start_beta_device_reports_an_answer_it_cannot_read(tmp_path: Path):
    # A 200 with a body that is not the expected JSON is a misconfigured
    # deployment, not a transport failure — and it must not be reported as one.
    with _serve(
        [(200, b"<html><body>no such route</body></html>", {"Content-Type": "text/html"})]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Start-BetaDevice"],
            """
try {
  $device = Start-BetaDevice -Site $env:KRYO_SITE -NoBrowser
  if ($null -eq $device) { "FELL_BACK" } else { "DEVICE_STARTED" }
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "does not understand" in output
    assert "could not reach" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_wait_beta_download_url_polls_with_the_download_purpose(tmp_path: Path):
    token = "b" * 64
    with _serve([]) as (site, server):
        server.replies[:] = [
            (200, {"status": "pending"}, {}),
            (
                200,
                {
                    "status": "approved",
                    "download_url": f"{site}/api/beta/download?t=dl_{token}",
                    "expires_in_min": 15,
                },
                {},
            ),
        ]
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
$url = Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
"DOWNLOAD_URL=" + $url
""",
            site=site,
        )

    assert f"DOWNLOAD_URL={site}/api/beta/download?t=dl_{token}" in output
    assert len(server.seen) == 2
    assert all(call["path"] == "/api/beta/device/poll" for call in server.seen)
    assert all(call["body"]["purpose"] == "download" for call in server.seen)


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_wait_beta_download_url_refuses_a_download_link_for_another_site(tmp_path: Path):
    other = "http://elsewhere.example"
    with _serve(
        [
            (
                200,
                {
                    "status": "approved",
                    "download_url": f"{other}/api/beta/download?t=dl_{'b' * 64}",
                    "expires_in_min": 15,
                },
                {},
            )
        ]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
try {
  $url = Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
  "DOWNLOAD_URL=" + $url
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "different site" in output
    assert "DOWNLOAD_URL=" not in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_refused_download_link_ends_the_install_rather_than_retrying(tmp_path: Path):
    # A guard is only fail-closed if the script stops. Here the harness keeps
    # the installer's real Die, so a refusal that merely returned would let the
    # loop take the next answer — a link this run never validated.
    with _serve([]) as (site, server):
        server.replies[:] = [
            (
                200,
                {
                    "status": "approved",
                    "download_url": f"http://elsewhere.example/api/beta/download?t=dl_{'b' * 64}",
                    "expires_in_min": 15,
                },
                {},
            ),
            (
                200,
                {
                    "status": "approved",
                    "download_url": f"{site}/api/beta/download?t=dl_{'a' * 64}",
                    "expires_in_min": 15,
                },
                {},
            ),
        ]
        code, output = _run_ps_real_die(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
$url = Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
"RETURNED=" + $url
""",
            site=site,
        )

    assert code != 0, output
    assert "RETURNED=" not in output
    assert "different site" in output
    assert len(server.seen) == 1, "a refusal must not poll again"


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_wait_beta_download_url_keeps_polling_through_a_server_failure(tmp_path: Path):
    token = "b" * 64
    with _serve([]) as (site, server):
        server.replies[:] = [
            (500, {"error": "boom"}, {}),
            (
                200,
                {
                    "status": "approved",
                    "download_url": f"{site}/api/beta/download?t=dl_{token}",
                    "expires_in_min": 15,
                },
                {},
            ),
        ]
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
$url = Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
"DOWNLOAD_URL=" + $url
""",
            site=site,
        )

    # A single failed poll is not a verdict; the deadline is. Giving up here
    # would make a five-second hiccup look like a denial.
    assert f"DOWNLOAD_URL={site}/api/beta/download?t=dl_{token}" in output
    assert len(server.seen) == 2


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_wait_beta_download_url_reports_a_denial(tmp_path: Path):
    with _serve(
        [(200, {"status": "denied", "reason": "access was revoked"}, {})]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
try {
  Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "access was revoked" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_wait_beta_download_url_reports_an_expired_code(tmp_path: Path):
    with _serve([(200, {"status": "expired"}, {})]) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Same-SiteOrigin", "Wait-BetaDownloadUrl"],
            """
$device = @{ device_code = "c" * 64 }
try {
  Wait-BetaDownloadUrl -Site $env:KRYO_SITE -Device $device -PollSeconds 0 -TimeoutMinutes 1
} catch { "REFUSED: " + $_.Exception.Message }
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "expired" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_download_wheel_verifies_the_bytes_it_fetched(tmp_path: Path):
    wheel = tmp_path / "kryonsec.whl"
    with _serve(
        [
            (
                200,
                WHEEL_BYTES,
                {
                    "Content-Type": "application/octet-stream",
                    "X-Kryonsec-Wheel-SHA256": WHEEL_SHA256,
                },
            )
        ]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Verify-WheelHash", "Download-Wheel"],
            f"""
try {{
  Download-Wheel "{wheel}" "$env:KRYO_SITE/wheel"
  "DOWNLOADED"
}} catch {{ "REFUSED: " + $_.Exception.Message }}
""",
            site=site,
        )

    assert "DOWNLOADED" in output
    assert wheel.read_bytes() == WHEEL_BYTES


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_download_wheel_refuses_a_mismatched_header(tmp_path: Path):
    wheel = tmp_path / "kryonsec.whl"
    with _serve(
        [
            (
                200,
                WHEEL_BYTES,
                {
                    "Content-Type": "application/octet-stream",
                    "X-Kryonsec-Wheel-SHA256": "0" * 64,
                },
            )
        ]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Verify-WheelHash", "Download-Wheel"],
            f"""
try {{
  Download-Wheel "{wheel}" "$env:KRYO_SITE/wheel"
  "DOWNLOADED"
}} catch {{ "REFUSED: " + $_.Exception.Message }}
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "does not match" in output


@pytest.mark.skipif(_powershell() is None, reason="PowerShell is not installed")
def test_download_wheel_refuses_missing_verification_metadata(tmp_path: Path):
    wheel = tmp_path / "kryonsec.whl"
    with _serve(
        [(200, WHEEL_BYTES, {"Content-Type": "application/octet-stream"})]
    ) as (site, _server):
        output = _run_ps(
            tmp_path,
            ["Verify-WheelHash", "Download-Wheel"],
            f"""
try {{
  Download-Wheel "{wheel}" "$env:KRYO_SITE/wheel"
  "DOWNLOADED"
}} catch {{ "REFUSED: " + $_.Exception.Message }}
""",
            site=site,
        )

    assert "REFUSED" in output
    assert "verification metadata" in output
