# Kryonsec one-line installer (Windows PowerShell).
#
#   powershell -c "irm https://raw.githubusercontent.com/GonchiJoshnaVardhanReddy/kryon-sec/main/install.ps1 | iex"
#
# What it does:
#   1. checks for Python 3.11+
#   2. creates ~\.kryonsec\venv
#   3. installs kryonsec into it (from GitHub)
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
    Die "Python 3.11+ required (found: $($version ?? 'unknown')). https://www.python.org/downloads/"
}
Say "using Python $version"

# ---- 2. venv ----------------------------------------------------------------
Say "creating virtualenv at $Venv"
& $pyCmd -m venv $Venv
if (-not (Test-Path (Join-Path $Venv "Scripts\pip.exe"))) { Die "venv creation failed (pip missing)" }

$Pip = Join-Path $Venv "Scripts\pip.exe"
$Kryo = Join-Path $Venv "Scripts\kryonsec.exe"

# ---- 3. install --------------------------------------------------------------
Say "installing kryonsec (this pulls litellm, mcp, rich, ...)"
& $Pip install --quiet --upgrade pip
& $Pip install --quiet "git+$Repo.git"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Kryo)) { Die "installation failed" }
& $Kryo --version

# ---- 4. PATH (user scope, idempotent) ----------------------------------------
$Bin = Join-Path $Venv "Scripts"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$Bin", "User")
    Say "added $Bin to the user PATH (new terminals only)"
} else {
    Say "PATH already set up"
}

# ---- 5. first-run wizard -----------------------------------------------------
Say "starting setup wizard"
& $Kryo setup

Say "done - open a new terminal and run: kryonsec"
