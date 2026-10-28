param([switch] $PreflightOnly)
# CI-only, no feature enablement/elevation/global PostgreSQL service or default WSL mutation.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
    throw 'NATIVE_WINDOWS_GITHUB_RUNNER_REQUIRED'
}
$feature = Get-CimInstance Win32_OptionalFeature -Filter "Name='Microsoft-Windows-Subsystem-Linux'"
if (-not $feature -or $feature.InstallState -ne 1) {
    throw 'EXISTING_WSL_FEATURE_REQUIRED_NO_AUTOMATIC_ENABLEMENT'
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'WSL_COMMAND_UNAVAILABLE' }
# Read-only capability probe; never install/upgrade WSL or enable a hypervisor.
$existing = & wsl.exe --list --quiet
if ($LASTEXITCODE -ne 0) { throw 'WSL_READONLY_PROBE_FAILED' }
if ($PreflightOnly) {
    Write-Output 'Existing Windows WSL capability probe passed; no environment mutation performed.'
    exit 0
}
$name = 'PeerloomCI-' + [Guid]::NewGuid().ToString('N')
if (@($existing | ForEach-Object { ($_ -replace "`0", '').Trim() }) -contains $name) {
    throw 'REFUSE_EXISTING_DISTRO'
}
$root = Split-Path -Parent $PSScriptRoot
$directory = Join-Path $env:RUNNER_TEMP $name
if (Test-Path $directory) { throw 'REFUSE_EXISTING_TEST_DIRECTORY' }
New-Item -ItemType Directory $directory | Out-Null
# Empty new directory only. Install a protected current-user DACL before writing secrets.
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $directory -AclObject $acl
try {
    & python (Join-Path $PSScriptRoot 'windows-service.py') --directory $directory --distro $name
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_SERVICE_ACCEPTANCE_FAILED' }
} finally {
    $remaining = & wsl.exe --list --quiet
    if ($LASTEXITCODE -ne 0) { throw 'WSL_CLEANUP_VERIFICATION_FAILED' }
    if (@($remaining | ForEach-Object { ($_ -replace "`0", '').Trim() }) -contains $name) {
        throw 'OWNED_DISTRO_CLEANUP_INCOMPLETE_PRIVATE_DIRECTORY_RETAINED'
    }
    Remove-Item -LiteralPath $directory -Recurse -Force
}
