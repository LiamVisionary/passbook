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
# `can_sign()` is true exactly when a signCommand or a thumbprint is set, which
# is why configuring this makes the bundler do the signing at the only moment
# that works.
#
#     sign-windows.ps1 -Path <file>
#
# Configured by environment rather than arguments, so the account names live in
# the workflow next to the credentials they go with and not in the repository.

[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'

$endpoint = $env:PASSBOOK_SIGN_ENDPOINT
$account  = $env:PASSBOOK_SIGN_ACCOUNT
$profile  = $env:PASSBOOK_SIGN_PROFILE

if (-not ($endpoint -and $account -and $profile)) {
    throw "signing is not configured: PASSBOOK_SIGN_ENDPOINT, _ACCOUNT and _PROFILE must all be set"
}
if (-not (Test-Path -LiteralPath $Path)) {
    throw "nothing to sign at $Path"
}

Write-Host "signing $(Split-Path $Path -Leaf)"

& sign code trusted-signing $Path `
    --trusted-signing-endpoint $endpoint `
    --trusted-signing-account $account `
    --trusted-signing-certificate-profile $profile `
    --file-digest SHA256 `
    --timestamp-url 'http://timestamp.acs.microsoft.com' `
    --timestamp-digest SHA256 `
    --verbosity information

if ($LASTEXITCODE -ne 0) {
    # The flag names are the only part of this that is guesswork, and a failed
    # release is an expensive way to discover them. Print what the tool accepts
    # so one run says exactly what to change.
    Write-Host "--- sign code trusted-signing --help ---"
    & sign code trusted-signing --help
    throw "signing $Path failed with exit code $LASTEXITCODE"
}

# Asked of Windows rather than inferred from an exit code.
$signature = Get-AuthenticodeSignature -LiteralPath $Path
Write-Host "  $($signature.Status)"
if ($signature.Status -ne 'Valid') {
    throw "signed $Path and Windows still reports $($signature.Status)"
}
