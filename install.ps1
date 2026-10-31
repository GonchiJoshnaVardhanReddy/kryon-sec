# Kryonsec installer (Windows PowerShell).
#
#   irm https://kryonsec.in/install.ps1 -OutFile "$env:TEMP\kryonsec-install.ps1"
#   powershell -ExecutionPolicy Bypass -File "$env:TEMP\kryonsec-install.ps1"
#
# That command is short, stable, and carries no credential. The script asks
# kryonsec.in for a browser sign-in code, opens the approval page, and waits
# for a signed-in member to approve this machine. Approval yields a fresh,
# single-use download link that expires in 15 minutes; the wheel's SHA-256 is
# checked against the release metadata before anything is installed, and the
# link itself is never printed or stored.
#
# Membership keys still work: set KRYONSEC_KEY (or KRYONSEC_LICENSE_KEY) and
# the script uses the key path without asking for a browser approval. If the
# site has no sign-in route at all, it falls back to prompting for a key; a
# refusal or a network failure is reported as itself instead.
# KRYONSEC_WHEEL installs a local or remote wheel directly, and
# KRYONSEC_DOWNLOAD_URL accepts a link prepared elsewhere.
#
# Kryonsec is commercial, closed-source software: there is no public repository
# to clone. The release below is a built wheel, and either the membership key
# or a member's approval is what unlocks it.
#
# Download-then-run rather than piping the response straight into PowerShell's
# expression evaluator: fetching to a file means you can read the script before
# it runs, where the pipe form executes whatever the URL returns, uninspected.
# Bypass is scoped to that one process — a freshly downloaded script is blocked
# outright under the Windows client default policy.
#
# What it does:
#   1. checks for Python 3.11+
#   2. reuses a compatible ~\.kryonsec\venv or preserves an incomplete one with -Repair
#   3. asks for browser approval (or uses a membership key), fetches the
#      kryonsec release from kryonsec.in, and verifies its SHA-256 — saving
#      the key only on the key path
#   4. adds ~\.kryonsec\venv\Scripts to the user PATH
#   5. runs `kryonsec setup` (the wizard: LLM, tools, MCP) and doctor
#
# Purple Team (Mode B) is Linux-only — this installs the Copilot (Mode A).
# For Purple Team use WSL2: see install.sh / the README.

param(
    [switch]$DryRun,
    [switch]$Repair
)

$ErrorActionPreference = "Stop"
$DryRun = $DryRun -or ($env:KRYONSEC_DRY_RUN -eq "1")
$Repair = $Repair -or ($env:KRYONSEC_REPAIR -eq "1")
if ($env:KRYONSEC_PROFILE -and $env:KRYONSEC_PROFILE -ne "copilot") {
    Write-Host "error: Purple Team must be installed from WSL2/Linux with install.sh; Windows supports Copilot only" -ForegroundColor Red
    exit 2
}
$Site = if ($env:KRYONSEC_SITE) { $env:KRYONSEC_SITE } else { "https://kryonsec.in" }
$DownloadUrl = "$Site/api/download"
# The membership key unlocks the download here and Purple Team later.
# KRYONSEC_LICENSE_KEY is the name the app itself reads, so accept both.
$Key = if ($env:KRYONSEC_KEY) { $env:KRYONSEC_KEY } else { $env:KRYONSEC_LICENSE_KEY }
$Home1 = if ($env:KRYONSEC_HOME) { $env:KRYONSEC_HOME } else { Join-Path $env:USERPROFILE ".kryonsec" }
$Venv = Join-Path $Home1 "venv"

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

# ---- 1. python 3.11+ --------------------------------------------------------
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Die "Python not found. Install 3.11+ first: https://www.python.org/downloads/" }
$pyCmd = if ($py.Source -match "py.exe$") { @($py.Source, "-3") } else { @($py.Source) }

$version = & $pyCmd -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
if (-not $version -or [version]$version -lt [version]"3.11") {
    Die "Python 3.11+ required (found: $(if ($version) { $version } else { 'unknown' })). https://www.python.org/downloads/"
}
Say "using Python $version"

# ---- 2. venv ----------------------------------------------------------------
if ($DryRun) {
    if (Test-Path (Join-Path $Home1 "config.toml")) {
        Say "dry run: existing configuration will be preserved"
    } else {
        Say "dry run: first-run setup will be required"
    }
    Say "dry run: would create or reuse $Venv, install the Copilot wheel, and update the user PATH"
    Say "dry run: no download, file write, or package installation was performed"
    exit 0
}

$VenvPython = Join-Path $Venv "Scripts\python.exe"
if (Test-Path $VenvPython) {
    $venvVersion = & $VenvPython -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')" 2>$null
    if (-not $venvVersion -or [version]$venvVersion -lt [version]"3.11") {
        if (-not $Repair) { Die "$Venv exists but its Python is incompatible. Re-run with -Repair to preserve it before repair." }
        $backup = "$Venv.backup.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
        Move-Item -LiteralPath $Venv -Destination $backup
        Say "preserved the old virtualenv at $backup"
    } else {
        Say "existing compatible virtualenv is ready: $Venv"
    }
} elseif (Test-Path $Venv) {
    if (-not $Repair) { Die "$Venv exists but is incomplete. Re-run with -Repair to preserve it before repair." }
    $backup = "$Venv.backup.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
    Move-Item -LiteralPath $Venv -Destination $backup
    Say "preserved the old virtualenv at $backup"
}

if (-not (Test-Path $VenvPython)) {
    $tmpVenv = Join-Path $Home1 ".venv.tmp.$([guid]::NewGuid().ToString('N'))"
    Say "creating virtualenv at $Venv"
    & $pyCmd -m venv $tmpVenv
    if (-not (Test-Path (Join-Path $tmpVenv "Scripts\pip.exe"))) {
        Remove-Item -LiteralPath $tmpVenv -Recurse -Force -ErrorAction SilentlyContinue
        Die "venv creation failed (pip missing). Install Python 3.11+ with venv support and re-run."
    }
    Move-Item -LiteralPath $tmpVenv -Destination $Venv
}

$Pip = Join-Path $Venv "Scripts\pip.exe"
$Kryo = Join-Path $Venv "Scripts\kryonsec.exe"

# ---- 3. install --------------------------------------------------------------
# Kryonsec is closed-source, so there is no repo to clone and no public tag
# list to read. The release ships as a built wheel and the site decides which
# version the key gets, which is why nothing here resolves a version at all.
#
# KRYONSEC_WHEEL overrides the download entirely — a URL or a local .whl. It
# is the escape hatch for air-gapped machines, and it is how support hands
# someone a build without going through the site.
$Wheel = $env:KRYONSEC_WHEEL

function Verify-WheelHash($Path, $Headers = $null, [switch]$RequireMetadata) {
    $expected = $env:KRYONSEC_WHEEL_SHA256
    if (-not $expected -and $Headers) {
        foreach ($name in @($Headers.Keys)) {
            if ($name -ieq "X-Kryonsec-Wheel-SHA256") {
                $expected = @($Headers[$name])[0]
                break
            }
        }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($expected) {
        $expected = $expected.ToString().Replace("sha256:", "").Trim().ToLowerInvariant()
        if ($actual -ne $expected) { Die "wheel SHA-256 does not match the release metadata; the artifact was not installed" }
        Say "wheel verified (SHA-256 $actual)"
    } elseif ($RequireMetadata) {
        Die "release did not provide wheel verification metadata; the artifact was not installed"
    } else {
        Say "local wheel override supplied without release metadata; use KRYONSEC_WHEEL_SHA256 to verify it"
    }
}

function Download-Wheel($Path, $Uri, $Key = $null) {
    $headers = @{}
    if ($Key) { $headers["X-Kryonsec-Key"] = $Key }
    try {
        # -PassThru is what returns the response headers with -OutFile; the
        # -ResponseHeadersVariable parameter does not exist in Windows
        # PowerShell, which is the shell this script's header tells people to run.
        $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 600 -Uri $Uri -Headers $headers `
            -OutFile $Path -PassThru
    } catch {
        $status = $null
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        if ($status -in @(400, 401, 403)) {
            Die "download refused (HTTP $status); check the membership key or request a fresh link"
        } elseif ($status -ge 500 -and $status -lt 600) {
            Die "download service failed (HTTP $status); retry later or contact support"
        } else {
            Die "could not download the release (DNS, TLS, network, or timeout); check connectivity and retry"
        }
    }
    # Outside the catch on purpose: an integrity failure is a finding, not a
    # network error, and must never be relabelled as one.
    Verify-WheelHash $Path $response.Headers -RequireMetadata
}

# ---- browser approval (the short command's credential) ----------------------
# The documented command carries no token. Instead the installer asks the site
# for a code, shows the member the approval page, and collects a fresh
# single-use download link after they approve. The device_code is the secret
# half of that exchange and is deliberately never printed: someone reading the
# screen learns only the short code, which approves nothing on its own.

function Same-SiteOrigin($Site, $Url) {
    # The approval page is what a person trusts with their sign-in and the
    # download link is what carries the credential, so both must be on the site
    # this installer was told to talk to. Whoever answers the request otherwise
    # also chooses the bytes, the hash header, and where the code gets typed.
    #
    # GetLeftPart(Authority) keeps any "user@host" credentials, so a link that
    # only *reads* as this site is refused too; comparing Host alone would let
    # https://kryonsec.in@elsewhere through while showing the trusted name.
    $siteUri = $null
    $urlUri = $null
    if (-not [System.Uri]::TryCreate($Site, [System.UriKind]::Absolute, [ref]$siteUri)) { return $false }
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$urlUri)) { return $false }
    $expected = $siteUri.GetLeftPart([System.UriPartial]::Authority)
    $actual = $urlUri.GetLeftPart([System.UriPartial]::Authority)
    return [string]::Equals($expected, $actual, [StringComparison]::OrdinalIgnoreCase)
}

function Start-BetaDevice($Site, [switch]$NoBrowser) {
    $payload = @{
        os = "Windows"
        arch = $env:PROCESSOR_ARCHITECTURE
        version = "installer"
        device_id = [guid]::NewGuid().ToString("N")
    } | ConvertTo-Json -Compress

    # The transport and the answer are checked separately on purpose. "The site
    # has no sign-in route", "the site refused", and "we never got there" are
    # three different facts, and collapsing them into "sign-in is unavailable"
    # sends people hunting for a membership key they do not need.
    $response = $null
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Post -TimeoutSec 30 `
            -Uri "$Site/api/beta/device/start" -ContentType "application/json" -Body $payload
    } catch {
        $status = $null
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        if ($status -in @(404, 503)) {
            # The one case where a key genuinely is the other door: this
            # deployment does not offer browser sign-in at all.
            Write-Host "==> this site does not offer browser sign-in (HTTP $status); a membership key can be used instead" -ForegroundColor Yellow
            return $null
        }
        if ($status) {
            Die "the site refused the sign-in request (HTTP $status); try again in a moment"
        }
        Die "could not reach $Site for browser sign-in (DNS, TLS, network, or timeout); check connectivity and retry, or install with KRYONSEC_KEY"
    }

    # A server that omits the JSON content type hands back bytes rather than
    # text; decode either shape instead of trusting Content's type.
    $text = if ($response.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
    try {
        $started = $text | ConvertFrom-Json
    } catch {
        Die "the site answered the sign-in request with something this installer does not understand; nothing was installed"
    }

    if (-not $started.url -or -not $started.code -or -not $started.device_code) {
        Write-Host "==> the site gave an unexpected answer to the sign-in request; a membership key can be used instead" -ForegroundColor Yellow
        return $null
    }

    if (-not (Same-SiteOrigin $Site ([string]$started.url))) {
        Die "the sign-in page the site offered belongs to a different site than $Site; nothing was opened and nothing was installed"
    }

    Write-Host ""
    Write-Host "Approve this install in the browser:" -ForegroundColor Cyan
    Write-Host "  $($started.url)" -ForegroundColor Cyan
    Write-Host "The page should show code $($started.code)." -ForegroundColor Cyan
    Write-Host "No browser here? Open the link on any device where you are signed in - the code in the link ties it to this machine." -ForegroundColor DarkGray
    Write-Host ""

    if (-not $NoBrowser) {
        try {
            Start-Process $started.url | Out-Null
        } catch {
            Write-Host "==> no browser available; open the link above" -ForegroundColor Yellow
        }
    }
    return $started
}

# Ask until the browser decides. "purpose = download" tells the poll route to
# return a single-use download link rather than a long-lived CLI session: an
# installer has no reason to become a signed-in machine just to fetch a wheel.
function Wait-BetaDownloadUrl($Site, $Device, [int]$PollSeconds = 2, [int]$TimeoutMinutes = 15) {
    $payload = @{ device_code = [string]$Device.device_code; purpose = "download" } | ConvertTo-Json -Compress
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    # Remember why the last poll failed. A dropped poll is not a verdict, but a
    # timeout that never got one answer is worth reporting as the failure it
    # actually was rather than as silence from the browser.
    $lastFailure = ""
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Method Post -TimeoutSec 30 `
                -Uri "$Site/api/beta/device/poll" -ContentType "application/json" -Body $payload
            $text = if ($response.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
            $answer = $text | ConvertFrom-Json
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            $lastFailure = if ($status) { "the site refused the polls (HTTP $status)" } else { "could not reach $Site" }
            Start-Sleep -Seconds ([Math]::Max(1, $PollSeconds))
            continue
        }

        $status = [string]$answer.status
        if ($status -eq "approved") {
            $url = [string]$answer.download_url
            if (-not $url) {
                Die "the site approved the install but sent no download link; nothing was installed"
            }
            if (-not (Same-SiteOrigin $Site $url)) {
                Die "the download link the site sent belongs to a different site than $Site; nothing was installed"
            }
            return $url
        }
        if ($status -eq "denied") {
            $why = ([string]$answer.reason).Trim()
            if ($why) { Die "sign-in was denied: $why" }
            Die "sign-in was denied in the browser; nothing was installed"
        }
        if ($status -eq "expired" -or $status -eq "unknown") {
            Die "that sign-in code $status; run the installer again"
        }
        Start-Sleep -Seconds $PollSeconds
    }
    if ($lastFailure) {
        Die "timed out waiting for approval in the browser, and $lastFailure; nothing was installed"
    }
    Die "timed out waiting for approval in the browser; nothing was installed"
}

function Get-WheelVersion($Path) {
    $script = @'
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    name = next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))
    for line in archive.read(name).decode('utf-8', 'replace').splitlines():
        if line.lower().startswith('version:'):
            print(line.split(':', 1)[1].strip())
            break
'@
    return (& $VenvPython -c $script $Path 2>$null | Select-Object -First 1)
}

if ($Wheel) {
    if (Test-Path -LiteralPath $Wheel -PathType Leaf) {
        Say "installing from local KRYONSEC_WHEEL override"
        Verify-WheelHash $Wheel
    } elseif ($Wheel -match '^https?://') {
        $downloaded = Join-Path ([System.IO.Path]::GetTempPath()) ("kryonsec-" + [guid]::NewGuid().ToString('N') + ".whl")
        Download-Wheel $downloaded $Wheel
        $Wheel = $downloaded
    } else {
        Die "KRYONSEC_WHEEL is neither a readable .whl file nor an HTTP(S) URL"
    }
} else {
    $DownloadUri = $env:KRYONSEC_DOWNLOAD_URL
    if (-not $DownloadUri -and -not $Key) {
        # The documented short command lands here. No key and no prepared
        # link: ask the site to authorise this machine in the browser, then
        # download with the single-use link its approval yields. A
        # non-interactive run has nobody to approve it, so it keeps the old
        # behaviour and asks for a key instead of waiting pointlessly.
        $device = $null
        if ([Environment]::UserInteractive) {
            $device = Start-BetaDevice $Site
        }
        if ($device) {
            Say "waiting for approval in the browser..."
            $DownloadUri = Wait-BetaDownloadUrl -Site $Site -Device $device
        } else {
            # This script is meant to be read and run interactively (see the
            # header), so asking here beats dying with a usage line.
            if ([Environment]::UserInteractive) {
                $Key = Read-Host "Membership key (KRYO-XXXX-XXXX-XXXX)"
            }
            if (-not $Key) {
                Die "a membership key is required. Request access at $Site"
            }
        }
    }

    if ($DownloadUri) {
        # A one-time link (from browser approval or the dashboard). No key is
        # asked for or saved: the link is the whole credential and it dies on
        # first use.
        $Wheel = Join-Path ([System.IO.Path]::GetTempPath()) ("kryonsec-beta-" + [guid]::NewGuid().ToString('N') + ".whl")
        Say "fetching the kryonsec release"
        Download-Wheel $Wheel $DownloadUri
    } else {
        $Wheel = Join-Path ([System.IO.Path]::GetTempPath()) ("kryonsec-" + [guid]::NewGuid().ToString('N') + ".whl")
        Say "fetching the kryonsec release"
        # The membership key is a header, not a query parameter, so it cannot land
        # in proxy/CDN/access logs as part of the URL.
        Download-Wheel $Wheel "$DownloadUrl`?os=windows" $Key
    }
}

$InstalledVersion = (& $VenvPython -c "import importlib.metadata as m; print(m.version('kryonsec'))" 2>$null | Out-String).Trim()
$WheelVersion = Get-WheelVersion $Wheel
if ($InstalledVersion -and $InstalledVersion -eq $WheelVersion -and $env:KRYONSEC_FORCE_UPGRADE -ne "1") {
    Say "kryonsec $InstalledVersion is already installed; skipping package replacement"
} else {
    if ($InstalledVersion) { Say "upgrading Kryonsec $InstalledVersion to $WheelVersion" }
    else { Say "installing Kryonsec $WheelVersion (dependency resolution may take a few minutes)" }
    & $Pip install --upgrade pip
    & $Pip install --upgrade $Wheel
    if ($LASTEXITCODE -ne 0) { Die "installation failed" }
}
if (-not (Test-Path $Kryo)) { Die "installation failed: kryonsec command was not created" }
& $Kryo --version

# Remember the key. It gated the download, and Purple Team will ask for it
# again at the first engagement - making the user paste it twice, from an
# email they may no longer have open, is the kind of small friction that
# reads as broken. Failure here is not fatal: the app also reads
# KRYONSEC_LICENSE_KEY from the environment.
if ($Key) {
    $saveKey = @'
import sys
from kryonsec.config import config_path, read_config, update_config_sections

key = sys.argv[1].strip()
path = config_path()
data = read_config(path)
if str(data.get("license", {}).get("key") or "") != key:
    update_config_sections(path, {"license": {"key": key}})
'@
    & (Join-Path $Venv "Scripts\python.exe") -c $saveKey $Key
    if ($LASTEXITCODE -eq 0) {
        Say "membership key preserved in config (never printed)"
    } else {
        Die "existing configuration could not be updated safely; it was not overwritten. Repair $Home1\config.toml and re-run"
    }
}

# uvx runs a Python CLI tool without installing it - npx for Python. It is
# what the wizard's `fetch` MCP preset starts, it ships with uv, and most
# machines do not have uv, so that preset failed on the very first run for
# everyone. Installed INTO the venv deliberately: it lands on the PATH this
# script already manages and goes away with the venv. Skipped when uv is
# already available; never fatal, because nothing in either mode depends on it.
if (-not (Get-Command uvx -ErrorAction SilentlyContinue) -and
    -not (Test-Path (Join-Path $Venv "Scripts\uvx.exe"))) {
    & $Pip install --quiet uv
    if ($LASTEXITCODE -eq 0) {
        Say "installed uv (provides uvx, for the 'fetch' MCP server)"
    } else {
        Say "WARNING: could not install uv - the 'fetch' MCP server needs it"
        Say "         install it later with: $Pip install uv"
    }
}

# ---- 4. PATH (user scope, idempotent) ----------------------------------------
$Bin = Join-Path $Venv "Scripts"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Bin*") {
    # a machine with no user PATH set returns $null/"" — prepending ";" would
    # leave an empty PATH entry, which Windows resolves to the current directory
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $Bin } else { "$userPath;$Bin" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Say "added $Bin to the user PATH (new terminals only)"
} else {
    Say "PATH already set up"
}
# Make it live in THIS process too, not just new terminals: the wizard runs
# below as a subprocess and resolves commands against the PATH it inherits, so
# without this it would warn that uvx is missing moments after we installed it.
$env:Path = "$Bin;$env:Path"

# ---- 5. first-run wizard -----------------------------------------------------
Say "starting setup wizard"
$setupRc = 0
& $Kryo setup
if ($LASTEXITCODE -ne 0) {
    $setupRc = $LASTEXITCODE
    Say "setup wizard did not finish - configuration is not claimed as complete; run 'kryonsec setup' when ready"
}

$doctorRc = 0
& $Kryo doctor
if ($LASTEXITCODE -ne 0) { $doctorRc = $LASTEXITCODE }
if ($setupRc -ne 0 -or -not (Test-Path (Join-Path $Home1 "config.toml")) -or $doctorRc -ne 0) {
    Say "Kryonsec is installed, but first-run configuration is still pending"
} else {
    Say "Kryonsec Copilot is installed and configured"
}
Say "done - open a new terminal and run: kryonsec"
