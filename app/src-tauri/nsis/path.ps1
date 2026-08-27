# Put PassBook's commands on the user's PATH, and take them off again.
#
# Called by the NSIS installer and uninstaller. The desktop app does not need
# this — it addresses the bundled runtime directly — but a credential manager
# whose commands only work inside its own window is half a tool, and the README
# has always shown `passbook` at a prompt.
#
#     path.ps1 -Action add    -Directory "C:\...\PassBook\bin"
#     path.ps1 -Action remove -Directory "C:\...\PassBook\bin"
#
# Edits the registry rather than calling [Environment]::SetEnvironmentVariable.
# That helper writes REG_SZ unconditionally, so a PATH stored as REG_EXPAND_SZ
# comes back with every %USERPROFILE% in it frozen to whatever it meant at the
# moment of the install. Breaking somebody's PATH is not an acceptable cost for
# adding one entry to it.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('add', 'remove')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Directory
)

# An installer that fails because of a PATH edit is worse than one that
# installs and says the PATH was left alone.
$ErrorActionPreference = 'Continue'

function Get-RawPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if ($null -eq $key) { return @{ Value = ''; Kind = 'ExpandString' } }
    try {
        $value = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = $key.GetValueKind('Path')
    } catch {
        $value = ''
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
    } finally {
        $key.Close()
    }
    return @{ Value = [string]$value; Kind = $kind }
}

function Set-RawPath($Value, $Kind) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -eq $key) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    }
    try { $key.SetValue('Path', $Value, $Kind) } finally { $key.Close() }
}

function Publish-Change {
    # Without this, every already-open shell keeps the old PATH until logoff.
    $signature = @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
    string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    try {
        $native = Add-Type -MemberDefinition $signature -Name 'PassBookEnv' -Namespace 'PassBook' -PassThru
        $out = [UIntPtr]::Zero
        # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG, 5s
        $null = $native::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$out)
    } catch {
        # Cosmetic only: a new shell picks the change up regardless.
    }
}

$current = Get-RawPath
$kind = $current.Kind
if ($kind -eq [Microsoft.Win32.RegistryValueKind]::Unknown -or $kind -eq [Microsoft.Win32.RegistryValueKind]::None) {
    $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
}

# Split on ';' and drop empties, so a trailing separator does not become a
# blank entry meaning "the current directory" — which on PATH is a real hazard.
$entries = @($current.Value -split ';' | Where-Object { $_.Trim() -ne '' })
$wanted = $Directory.TrimEnd('\')
$matches = @($entries | Where-Object { $_.TrimEnd('\') -ieq $wanted })

if ($Action -eq 'add') {
    if ($matches.Count -gt 0) {
        Write-Output "PATH already contains $wanted"
        exit 0
    }
    $updated = @($entries + $wanted)
} else {
    if ($matches.Count -eq 0) {
        Write-Output "PATH does not contain $wanted"
        exit 0
    }
    $updated = @($entries | Where-Object { $_.TrimEnd('\') -ine $wanted })
}

Set-RawPath -Value ($updated -join ';') -Kind $kind
Publish-Change
Write-Output "PATH $Action`: $wanted"
exit 0
