# Native Windows runner only. No Wine/WSL/cross-compile success claims.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $IsWindows) { throw 'WINDOWS_NATIVE_RUNNER_REQUIRED' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'VSWHERE_MISSING' }
$vs = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $vs) { throw 'MSVC_X64_TOOLCHAIN_MISSING' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
# Capture, never print the environment (which may contain runner credentials).
$environmentLines = & cmd.exe /d /s /c "`"$vcvars`" >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'MSVC_ENVIRONMENT_SETUP_FAILED' }
foreach ($line in $environmentLines) {
    $index = $line.IndexOf('=')
    if ($index -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$index), $line.Substring($index+1), 'Process') }
}
function Invoke-Checked([string] $Program, [string[]] $Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "NATIVE_COMMAND_FAILED:$Program" }
}
$manifest = Join-Path $root 'src\device-sdk\Cargo.toml'
$triple = 'x86_64-pc-windows-msvc'
$validation = Join-Path $root 'dist\validation'
New-Item -ItemType Directory -Force $validation | Out-Null
@(
    "ImageOS=$env:ImageOS", "ImageVersion=$env:ImageVersion", "WindowsSDKVersion=$env:WindowsSDKVersion",
    "MSVC=$((Get-Item (Get-Command cl.exe).Source).VersionInfo.FileVersion)",
    "Linker=$((Get-Item (Get-Command link.exe).Source).VersionInfo.FileVersion)",
    "CargoLock=$((Get-FileHash (Join-Path (Split-Path $manifest) 'Cargo.lock') -Algorithm SHA256).Hash)"
) | Set-Content -Encoding utf8 (Join-Path $validation 'windows-toolchain.txt')
Invoke-Checked 'rustc' @('+1.99.1', '-Vv')
Invoke-Checked 'cargo' @('+1.99.1', 'fmt', '--manifest-path', $manifest, '--all', '--', '--check')
Invoke-Checked 'cargo' @('+1.99.1', 'clippy', '--manifest-path', $manifest, '--workspace', '--all-targets', '--target', $triple, '--locked', '--', '-D', 'warnings')
Invoke-Checked 'cargo' @('+1.99.1', 'test', '--manifest-path', $manifest, '--workspace', '--target', $triple, '--locked')
Invoke-Checked 'cargo' @('+1.99.1', 'test', '--manifest-path', $manifest, '-p', 'device-transport-webrtc', '--test', 'native_pair', '--target', $triple, '--locked', '--', '--ignored', '--nocapture')
Invoke-Checked 'cargo' @('+1.99.1', 'build', '--manifest-path', $manifest, '-p', 'device-core', '--example', 'windows_secure_peer', '--target', $triple, '--locked')
foreach ($profile in @('debug', 'release')) {
    $profileArgs = if ($profile -eq 'release') { @('--release') } else { @() }
    Invoke-Checked 'cargo' (@('+1.99.1', 'build', '--manifest-path', $manifest, '-p', 'device-ffi', '--target', $triple, '--locked') + $profileArgs)
    $target = Join-Path (Split-Path $manifest) "target\$triple\$profile"
    $harness = Join-Path $root 'src\device-sdk\device-ffi\tests\lifecycle.cpp'
    $headerProbe = Join-Path $root 'src\device-sdk\device-ffi\tests\header.c'
    $include = Join-Path $root 'src\device-sdk\device-ffi\include'
    $testDir = Join-Path $target 'native-tests'
    New-Item -ItemType Directory -Force $testDir | Out-Null
    $dll = Join-Path $target 'device_ffi.dll'
    $import = Join-Path $target 'device_ffi.dll.lib'
    $static = Join-Path $target 'device_ffi.lib'
    foreach ($file in @($dll,$import,$static)) { if (-not (Test-Path $file)) { throw 'EXPECTED_NATIVE_ABI_ARTIFACT_MISSING' } }
    Copy-Item $dll $testDir -Force
    Push-Location $testDir
    try {
        Invoke-Checked 'cl.exe' @('/nologo','/std:c11','/W4','/WX','/MD',"/I$include",$headerProbe,$import,'/link','/OUT:header.exe')
        Invoke-Checked (Join-Path $testDir 'header.exe') @()
        Invoke-Checked 'cl.exe' @('/nologo','/std:c++17','/EHsc','/W4','/WX','/MD','/permissive-',"/I$include",$harness,$import,'/link','/OUT:lifecycle-shared.exe')
        Invoke-Checked (Join-Path $testDir 'lifecycle-shared.exe') @()
        # Ask the actual target compiler for required system libraries; do not guess
        # that a static Rust library has no platform link dependencies.
        $notes = & cargo +1.99.1 rustc --manifest-path $manifest -p device-ffi --lib --target $triple --locked @profileArgs -- --print native-static-libs 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'RUST_STATIC_LINK_METADATA_FAILED' }
        $line = ($notes | ForEach-Object { "$_" } | Where-Object { $_ -match 'native-static-libs:' } | Select-Object -Last 1)
        if (-not $line) { throw 'RUST_STATIC_LINK_METADATA_MISSING' }
        $native = ($line -replace '^.*native-static-libs:\s*','')
        $libraries = @([regex]::Matches($native, '"([^"]+)"|(\S+)') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } })
        $native | Set-Content -Encoding utf8 (Join-Path $validation 'windows-static-link-libraries.txt')
        $arguments = @('/nologo','/std:c++17','/EHsc','/W4','/WX','/MD','/permissive-',"/I$include",$harness,$static) + $libraries + @('/link','/OUT:lifecycle-static.exe')
        Invoke-Checked 'cl.exe' $arguments
        Invoke-Checked (Join-Path $testDir 'lifecycle-static.exe') @()
    } finally { Pop-Location }
}
Write-Output 'Windows native Rust/DPAPI/ACL/direct-pair/C11/C++17 DLL and static lifecycle checks passed.'
