<#
.SYNOPSIS
  Installs stuntkey on Windows for someone who has no Python. No admin needed.

.DESCRIPTION
  What it does, in order:
    1. Looks for Python 3.10 or newer (py, then python).
       If missing, it tells you and asks once before installing Python 3.12 with winget.
    2. Installs pipx (python -m pip install --user pipx; pipx ensurepath).
    3. Installs stuntkey with pipx (from PyPI, or from a wheel file you pass with -Wheel).
    4. Starts stuntkey's guided first run.
    5. Prints plain next steps.

  It only talks to PyPI (pip), winget (Python) and python.org (through winget).
  It prints every command it runs. Running it twice is safe.

.PARAMETER WhatIf
  Print the plan and change nothing.

.PARAMETER Wheel
  Path to a local stuntkey wheel (.whl) to install instead of the one on PyPI.

.PARAMETER Yes
  Do not ask before installing Python with winget.

.PARAMETER NoStart
  Install only; skip the guided first run.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [string]$Wheel = "",
    [switch]$Yes,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"

function Say($text)  { Write-Host $text }
function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Ran($text)  { Write-Host "   > $text" -ForegroundColor DarkGray }

# Finds a working Python 3.10+; returns @{Exe=..; Args=..} or $null.
function Find-Python {
    $candidates = @(
        @{ Exe = "py";      Args = @("-3") },
        @{ Exe = "python";  Args = @() }
    )
    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $out = & $c.Exe @($c.Args) -c "import sys; print(sys.version_info[0]*100+sys.version_info[1])" 2>$null
            if ($LASTEXITCODE -eq 0 -and [int]("$out".Trim()) -ge 310) { return $c }
        } catch { }
    }
    return $null
}

function Invoke-Logged($exe, [string[]]$arguments) {
    Ran ("$exe " + ($arguments -join " "))
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "'$exe' stopped with exit code $LASTEXITCODE." }
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user    = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($user, $machine) | Where-Object { $_ }) -join ";"
}

Say "stuntkey installer"
if ($WhatIf) { Say "(-WhatIf: this only prints the plan. Nothing is changed.)" }

if ($Wheel -ne "" -and -not $WhatIf -and -not (Test-Path -LiteralPath $Wheel)) {
    throw "The wheel file '$Wheel' was not found."
}

# ---- 1. Python ---------------------------------------------------------------
Step "Step 1 of 4: Python 3.10 or newer"
$py = Find-Python
if ($py) {
    Say ("Found Python: " + $py.Exe + " " + ($py.Args -join " "))
} elseif ($WhatIf) {
    Say "Python 3.10+ was not found. Plan: ask once, then run:"
    Ran "winget install --id Python.Python.3.12 -e --scope user --accept-package-agreements --accept-source-agreements"
    $py = @{ Exe = "python"; Args = @() }
} else {
    Say "Python 3.10 or newer was not found on this PC."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Say "winget is not available either. Install Python 3.12 from https://www.python.org/downloads/"
        Say "(tick 'Add python.exe to PATH'), then run this installer again."
        exit 1
    }
    Say "I can install Python 3.12 for you with winget (it comes from python.org, for your user only, no admin)."
    $go = $Yes.IsPresent
    if (-not $go) {
        $answer = Read-Host "Install Python 3.12 now? (y/n)"
        $go = ($answer -match '^(y|yes)$')
    }
    if (-not $go) { Say "OK. Nothing was installed. Run this again when you are ready."; exit 1 }
    Invoke-Logged "winget" @("install", "--id", "Python.Python.3.12", "-e", "--scope", "user",
                             "--accept-package-agreements", "--accept-source-agreements")
    Refresh-Path
    $py = Find-Python
    if (-not $py) {
        Say "Python is installed, but this window cannot see it yet."
        Say "Close this window, open a new PowerShell window, and run this installer again."
        exit 1
    }
}

# ---- 2. pipx -----------------------------------------------------------------
Step "Step 2 of 4: pipx (installs command-line programs in their own space)"
if ($WhatIf) {
    Ran "python -m pip install --user --upgrade pipx"
    Ran "python -m pipx ensurepath"
} else {
    Invoke-Logged $py.Exe (@($py.Args) + @("-m", "pip", "install", "--user", "--upgrade", "pipx"))
    Invoke-Logged $py.Exe (@($py.Args) + @("-m", "pipx", "ensurepath"))
    Refresh-Path
}

# ---- 3. stuntkey -------------------------------------------------------------
Step "Step 3 of 4: stuntkey"
$target = "stuntkey"
if ($Wheel -ne "") { $target = $Wheel }
if ($WhatIf) {
    Ran "python -m pipx install --force $target"
} else {
    Invoke-Logged $py.Exe (@($py.Args) + @("-m", "pipx", "install", "--force", $target))
    Refresh-Path
}

# ---- 4. first run ------------------------------------------------------------
Step "Step 4 of 4: first run"
# `stuntkey setup` today connects the services listed in a project's stuntkey.json.
# Use it only if its help does not say that; otherwise use the guided `stuntkey start`.
$firstRun = "start"
if (-not $WhatIf -and (Get-Command stuntkey -ErrorAction SilentlyContinue)) {
    try {
        $help = (& stuntkey setup --help 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0 -and $help -notmatch "stuntkey\.json") { $firstRun = "setup" }
    } catch { }
}
if ($WhatIf) {
    Ran "stuntkey setup   (or 'stuntkey start' if setup is not the guided first run)"
} elseif ($NoStart) {
    Say "Skipped (-NoStart)."
} else {
    $exe = Get-Command stuntkey -ErrorAction SilentlyContinue
    if ($exe) {
        Ran "stuntkey $firstRun"
        & stuntkey $firstRun
    } else {
        Say "stuntkey is installed, but this window cannot find it yet. Open a NEW PowerShell window and run: stuntkey start"
    }
}

# ---- next steps --------------------------------------------------------------
Step "Done"
if ($WhatIf) {
    Say "That was the plan. Run again without -WhatIf to do it."
} else {
    Say "Next steps:"
    Say "  1. Open a NEW PowerShell window (so the new PATH is used)."
    Say "  2. Run:  stuntkey doctor     (checks that everything works)"
    Say "  3. Run:  stuntkey start      (guided: saves a key and connects your AI tool)"
    Say "To remove it later:  pipx uninstall stuntkey"
}
