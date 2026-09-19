# Kryonsec one-line installer (Windows PowerShell).
#
#   powershell -c "irm https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.ps1 | iex"
#
# What it does:
#   1. checks for Python 3.11+ and git (installs git via winget if missing)
#   2. creates ~\.kryonsec\venv
#   3. installs the latest released tag of kryonsec into it (from GitHub)
#   4. adds ~\.kryonsec\venv\Scripts to the user PATH
#   5. runs `kryonsec setup` (the wizard: LLM, tools, MCP)
#
# Purple Team (Mode B) is Linux-only — this installs the Copilot (Mode A).
# For Purple Team use WSL2: see install.sh / the README.

$ErrorActionPreference = "Stop"
$Repo = "https://github.com/GonchiJoshnaVardhanReddy/kryon-sec"
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
# git powers the release-tag lookup and the pip install itself (pip shells out
# to git for a git+https URL). Check early so the failure is actionable.
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Say "git not found - required to install kryonsec from GitHub"
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say "installing git via winget"
        # winget frequently exits non-zero for reasons that don't matter here
        # (already installed, source refresh warning). $ErrorActionPreference
        # is "Stop" script-wide, so a native-command failure must not be
        # allowed to abort the install — we re-check for git instead.
        $eap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & winget install --id Git.Git -e --source winget `
                --accept-package-agreements --accept-source-agreements
        } catch {
            Say "winget could not install git: $($_.Exception.Message)"
        } finally {
            $ErrorActionPreference = $eap
        }
        # winget updates the machine/user PATH, not this process's copy
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPathNow = [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = (@($machinePath, $userPathNow) | Where-Object { $_ }) -join ";"
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Die "git is required. Install it from https://git-scm.com/downloads and re-run."
    }
    Say "git installed"
}

Say "installing kryonsec (this pulls litellm, mcp, rich, ...)"
& $Pip install --quiet --upgrade pip

# Install a released version, not whatever is on main at this moment (matches
# install.sh). The latest tag comes from the GitHub tags API; FALLBACK_TAG
# covers offline installs and repos without tags. KRYONSEC_VERSION overrides
# both ("@v1.3.1", "@main", "@<commit-sha>"). Bump FALLBACK_TAG on every release.
$FallbackTag = "v1.3.1"
$Version = $env:KRYONSEC_VERSION
if (-not $Version) {
    $tagNames = @()
    try {
        # per_page: the default page is 30 tags — a busy repo would hide the
        # newest release past the first page (we sort by semver, so ordering
        # doesn't matter, but the cutoff would)
        $resp = Invoke-RestMethod -TimeoutSec 20 `
            -Uri "https://api.github.com/repos/GonchiJoshnaVardhanReddy/kryon-sec/tags?per_page=100"
        $tagNames = @($resp | ForEach-Object { $_.name })
    } catch {
        Say "could not query tags ($($_.Exception.Message))"
    }
    $latest = $null
    if ($tagNames.Count -gt 0) {
        $latest = $tagNames | Sort-Object -Property @{ Expression = {
            $parts = $_.TrimStart("v") -split "\."
            try { [int]$parts[0] * 1000000 + [int]$parts[1] * 1000 + [int]$parts[2] }
            catch { 0 }
        } } | Select-Object -Last 1
    }
    if ($latest) {
        $Version = "@$latest"
        Say "installing latest release $latest"
    } else {
        $Version = "@$FallbackTag"
        Say "no tags found - using pinned $FallbackTag"
    }
}
& $Pip install --quiet "git+$Repo.git$Version"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Kryo)) { Die "installation failed" }
& $Kryo --version

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

# ---- 5. first-run wizard -----------------------------------------------------
Say "starting setup wizard"
& $Kryo setup

Say "done - open a new terminal and run: kryonsec"
