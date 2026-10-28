# Parse the real producer, then execute only its profile setup and metadata call
# against an external argument probe. No compiler or Windows host is needed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$parseErrors = $null
$producer = Join-Path $PSScriptRoot 'test-windows.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($producer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'WINDOWS_PRODUCER_PARSE_FAILED' }
$loop = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.ForEachStatementAst] -and $node.Variable.VariablePath.UserPath -eq 'profile'
}, $true)
if ($null -eq $loop) { throw 'PROFILE_LOOP_MISSING' }
$metadata = $loop.Find({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$notes'
}, $true)
if ($null -eq $metadata) { throw 'METADATA_COMMAND_MISSING' }
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("peerloom-arguments-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temporary | Out-Null
$probe = Join-Path $temporary 'arguments.py'
'import json,sys; print(json.dumps(sys.argv[1:]))' | Set-Content -Encoding utf8 $probe
$manifest = 'fixture/Cargo.toml'
$triple = 'x86_64-pc-windows-msvc'
try {
foreach ($profile in @('debug', 'release')) {
    foreach ($statement in $loop.Body.Statements) {
        if ($statement.Extent.Text -like '*Invoke-Checked*') { break }
        . ([scriptblock]::Create($statement.Extent.Text))
    }
    . ([scriptblock]::Create($metadata.Extent.Text.Replace('& cargo ', '& python $probe ')))
    if ($LASTEXITCODE -ne 0) { throw 'ARGUMENT_PROBE_FAILED' }
    $observed = $notes | ConvertFrom-Json
    $expected = @('+1.99.1', 'rustc', '--manifest-path', $manifest, '-p', 'device-ffi', '--lib', '--target', $triple, '--locked')
    if ($profile -eq 'release') { $expected += '--release' }
    $expected += @('--', '--print', 'native-static-libs')
    if (($observed -join "`n") -cne ($expected -join "`n")) { throw "PROFILE_ARGUMENTS_SPLIT:$profile" }
}
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
Write-Output 'Windows debug/release cargo argument arrays PASS'
