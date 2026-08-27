# Sign one file with Azure Trusted Signing, called by Tauri's bundler.
#
# This has to be Tauri's own hook rather than a step before or after the build,
# and the reason is worth writing down because it cost a release.
#
# The bundler patches the main binary in place before packaging it, to record
# which installer type it came from so the updater knows. In tauri-bundler that
# is `patch_binary`, and the line immediately after it reads:
#
#     // sign main binary for every package type after patch
#     if ... settings.windows().can_sign() { try_sign(&main_binary_path, ...) }
#
# So a signature applied before the bundler runs is applied to bytes the
# bundler then edits. It does not fail. It produces an installer carrying an
# application whose certificate is present and whose hash no longer matches,
# which Windows reports as HashMismatch and a person reasonably reads as
# tampered-with. Worse than not signing it at all.
#
#     sign-windows.ps1 -Path <file>
#
# Everything is written to a transcript as well as to stdout, because the
# bundler calls this with `output_ok()`, which captures both streams and prints
# nothing but "failed to run powershell" if the exit code is not zero. A
# signing hook you cannot see the output of is not one you can fix.

[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Continue'

# Windows PowerShell 5.1 is what `powershell` means, and it has no ternary.
$logDir = $env:RUNNER_TEMP
if (-not $logDir) { $logDir = $env:TEMP }
$transcript = Join-Path $logDir 'passbook-signing.log'
function Say($message) {
    $line = "{0:HH:mm:ss}  {1}" -f (Get-Date), $message
    Write-Host $line
    Add-Content -LiteralPath $transcript -Value $line -Encoding utf8
}

$endpoint = $env:PASSBOOK_SIGN_ENDPOINT
$account  = $env:PASSBOOK_SIGN_ACCOUNT
$profile  = $env:PASSBOOK_SIGN_PROFILE

Say "asked to sign $Path"
if (-not ($endpoint -and $account -and $profile)) {
    Say "signing is not configured: endpoint/account/profile must all be set"
    exit 2
}
if (-not (Test-Path -LiteralPath $Path)) {
    Say "nothing to sign at $Path"
    exit 3
}

$tool = Get-Command sign -ErrorAction SilentlyContinue
if (-not $tool) {
    Say "the 'sign' tool is not on PATH"
    Say "PATH = $env:PATH"
    exit 4
}
Say "using $($tool.Source)"

$output = & sign code trusted-signing $Path `
    --trusted-signing-endpoint $endpoint `
    --trusted-signing-account $account `
    --trusted-signing-certificate-profile $profile `
    --file-digest SHA256 `
    --timestamp-url 'http://timestamp.acs.microsoft.com' `
    --timestamp-digest SHA256 `
    --verbosity information 2>&1
$code = $LASTEXITCODE
$output | ForEach-Object { Say "  $_" }

if ($code -ne 0) {
    # The flag names are the only guesswork here, and a failed release is an
    # expensive way to discover them. Record what the tool accepts so one run
    # says exactly what to change.
    Say "exit $code; asking the tool what it accepts"
    (& sign code trusted-signing --help 2>&1) | ForEach-Object { Say "  $_" }
    exit $code
}

# Asked of Windows rather than inferred from an exit code.
$signature = Get-AuthenticodeSignature -LiteralPath $Path
Say "Windows reports: $($signature.Status)"
if ($signature.Status -ne 'Valid') {
    Say "signed and still not Valid"
    exit 5
}
Say "signed $([System.IO.Path]::GetFileName($Path))"
exit 0
