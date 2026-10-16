# Kryonsec installer (Windows PowerShell).
#
#   irm https://kryonsec.in/install.ps1 -OutFile install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Beta accounts do not use a key. Sign in at the site and its dashboard prints
# the command with KRYONSEC_DOWNLOAD_URL set to a one-time link:
#
#   $env:KRYONSEC_DOWNLOAD_URL='https://kryonsec.in/api/beta/download?t=dl_...'
#   irm https://kryonsec.in/install.ps1 -OutFile install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Kryonsec is commercial, closed-source software: there is no public repository
# to clone. The release below is a built wheel, and the membership key is what
# unlocks it, so this script asks for one before it downloads anything.
#
# Download-then-run rather than piping the response straight into PowerShell's
# expression evaluator: fetching to a file means you can read the script before
# it runs, where the pipe form executes whatever the URL returns, uninspected.
# Bypass is scoped to that one process — a freshly downloaded script is blocked
# outright under the Windows client default policy.
#
# What it does:
#   1. checks for Python 3.11+
#   2. creates ~\.kryonsec\venv
#   3. fetches the kryonsec release from kryonsec.in using your key, and
#      saves the key so Purple Team can use it later — or, for a beta account,
#      fetches the one-time link the dashboard gave you and saves no key
#   4. adds ~\.kryonsec\venv\Scripts to the user PATH
#   5. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
#
# Purple Team (Mode B) is Linux-only — this installs the Copilot (Mode A).
# For Purple Team use WSL2: see install.sh / the README.

$ErrorActionPreference = "Stop"
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
Say "creating virtualenv at $Venv"
& $pyCmd -m venv $Venv
if (-not (Test-Path (Join-Path $Venv "Scripts\pip.exe"))) { Die "venv creation failed (pip missing)" }

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
if ($Wheel) {
    Say "installing from KRYONSEC_WHEEL override"
} elseif ($env:KRYONSEC_DOWNLOAD_URL) {
    # The beta path. A signed-in account is handed a URL carrying a one-time
    # credential instead of a membership key, so this fetches to a file and
    # lets pip install the file. No key is asked for and none is saved: there
    # is no membership key in the beta, and Purple Team is Linux-only anyway.
    $Wheel = Join-Path ([System.IO.Path]::GetTempPath()) "kryonsec-beta.whl"
    Say "fetching the kryonsec release"
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 600 `
            -Uri $env:KRYONSEC_DOWNLOAD_URL -OutFile $Wheel
    } catch {
        Die "could not download kryonsec - that link was refused, has expired, or $Site is unreachable. Reload your dashboard at $Site/dashboard for a fresh one."
    }
} else {
    if (-not $Key) {
        # This script is meant to be read and run interactively (see the
        # header), so asking here beats dying with a usage line — but a
        # non-interactive run has no one to ask and must not hang.
        if ([Environment]::UserInteractive) {
            $Key = Read-Host "Membership key (KRYO-XXXX-XXXX-XXXX)"
        }
        if (-not $Key) {
            Die "a membership key is required. Request access at $Site"
        }
    }
    $Wheel = Join-Path ([System.IO.Path]::GetTempPath()) "kryonsec.whl"
    Say "fetching the kryonsec release"
    try {
        # -UseBasicParsing: the full parser needs Internet Explorer's engine,
        # which is absent or unconfigured on plenty of Windows installs, and
        # fails as an unrelated "cannot parse the response" error.
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 600 `
            -Uri "$DownloadUrl`?key=$Key&os=windows" -OutFile $Wheel
    } catch {
        Die "could not download kryonsec - the key was rejected, or $Site is unreachable. Check the key, or request access again at $Site"
    }
}

Say "installing kryonsec (this pulls litellm, mcp, rich, ...)"
& $Pip install --quiet --upgrade pip

# Not --quiet: the dependency tree takes minutes and pip prints nothing while
# it resolves, so a silent install reads as a hung one.
Say "installing kryonsec (a few minutes - pip is quiet while it resolves)"
& $Pip install $Wheel
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Kryo)) { Die "installation failed" }
& $Kryo --version

# Remember the key. It gated the download, and Purple Team will ask for it
# again at the first engagement - making the user paste it twice, from an
# email they may no longer have open, is the kind of small friction that
# reads as broken. Failure here is not fatal: the app also reads
# KRYONSEC_LICENSE_KEY from the environment.
if ($Key) {
    $saveKey = @'
import sys
from kryonsec.config import load_config
cfg = load_config()
cfg.license_key = sys.argv[1].strip()
cfg.save()
'@
    & (Join-Path $Venv "Scripts\python.exe") -c $saveKey $Key
    if ($LASTEXITCODE -eq 0) {
        Say "membership key saved"
    } else {
        Say "WARNING: could not save the membership key"
        Say "         add it later under [license] in $Home1\config.toml"
    }
}

# uvx runs a Python CLI tool without installing it - npx for Python. It is
# what the wizard's `fetch` MCP preset starts, it ships with uv, and most
# machines do not have uv, so that preset failed on the very first run for
# everyone. Installed INTO the venv deliberately: it lands on the PATH this
# script already manages and goes away with the venv. Skipped when uv is
# already available; never fatal, because nothing in either mode depends on it.
if (-not (Get-Command uvx -ErrorAction SilentlyContinue)) {
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
& $Kryo setup

Say "done - open a new terminal and run: kryonsec"
