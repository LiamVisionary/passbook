# PassBook - one-command setup.
#
#     .\install.ps1
#
# The Windows counterpart to install.sh, and it does the same job: find a usable
# Python, hand over to `passbook install`, and get out of the way. Everything
# this script decides, it prints.
#
# It does not install anything into a Python the machine already relies on, and
# it does not need an administrator. If no suitable Python exists it says so and
# stops, rather than half-installing and leaving you to find out later.
#
# Most people on Windows will not need this at all: the desktop app from the
# releases page carries its own Python and its own copy of these commands. This
# is for a machine that wants the command line without the app.

[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$minorFloor = 9

function Test-Usable($exe, $prefix) {
    # `py -3` is a launcher plus an argument, so every candidate is carried as
    # a program and its own argument list rather than a bare path.
    try {
        $probe = "import sys; sys.exit(0 if sys.version_info[:2] >= (3, $minorFloor) else 1)"
        & $exe @prefix -c $probe 2>$null
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

function Test-Crypto($exe, $prefix) {
    try {
        & $exe @prefix -c 'import cryptography' 2>$null
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

# A Python that already has `cryptography` is worth more than a newer one
# without it: taking it skips provisioning entirely.
$candidates = @()
if ($env:PASSBOOK_PYTHON) { $candidates += , @($env:PASSBOOK_PYTHON, @()) }
$candidates += , @('py', @('-3'))
foreach ($name in 'python3', 'python', 'python3.13', 'python3.12', 'python3.11', 'python3.10') {
    $candidates += , @($name, @())
}

$chosen = $null
$chosenArgs = @()
foreach ($candidate in $candidates) {
    $exe, $prefix = $candidate
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
    if (-not (Test-Usable $exe $prefix)) { continue }
    if (Test-Crypto $exe $prefix) { $chosen = $exe; $chosenArgs = $prefix; break }
    if (-not $chosen) { $chosen = $exe; $chosenArgs = $prefix }
}

# uv can supply a Python on a machine that has none at all.
if (-not $chosen -and (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Output "no suitable Python found; asking uv for one..."
    & uv python install *> $null
    $found = (& uv python find 2>$null | Select-Object -First 1)
    if ($found -and (Test-Usable $found @())) { $chosen = $found; $chosenArgs = @() }
}

if (-not $chosen) {
    Write-Error @"
PassBook needs Python 3.$minorFloor or newer, and none was found.
Install one (https://python.org/downloads, or ``winget install Python.Python.3.12``),
or set PASSBOOK_PYTHON to the interpreter you want used.

Or take the desktop app from https://github.com/LiamVisionary/passbook/releases,
which brings its own Python and installs these same commands.
"@
    exit 1
}

Write-Output "python:    $chosen $($chosenArgs -join ' ')"

# PYTHONPATH so the modules resolve out of this checkout, exactly as install.sh
# does. Set for the child only: this process is about to exit anyway, but a
# dot-sourced run would otherwise leave it behind.
$previous = $env:PYTHONPATH
$src = Join-Path $here "src"
$env:PYTHONPATH = if ($previous) { "$src;$previous" } else { $src }
try {
    & $chosen @chosenArgs -m passbook_cli install @Rest
    exit $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $previous
}
