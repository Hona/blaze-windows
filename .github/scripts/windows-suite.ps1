# Run one ordinary libtest suite at a time. Stop early under memory pressure so the runner
# retains logs and memory peaks for the batch summary instead of losing contact with the service.
param(
    [Parameter(Mandatory)] [string] $Crate,
    [string] $OutDir = '.'
)
$ErrorActionPreference = 'Stop'

$root = $PWD.Path
$dir = Join-Path $root "crates/$Crate"
$exe = Join-Path $root "target/debug/deps/$Crate.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Missing prebuilt test executable: $exe"
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$outPath = (Resolve-Path -LiteralPath $OutDir).Path

. (Join-Path $PSScriptRoot 'windows-memory.ps1')

$stdout = Join-Path $outPath "$Crate.stdout.log"
$stderr = Join-Path $outPath "$Crate.stderr.log"
$metricsPath = Join-Path $outPath "$Crate.metrics.json"
$metaPath = Join-Path $outPath "$Crate.meta.json"

$p = Start-Process $exe -ArgumentList '--test-threads=1' -WorkingDirectory $dir -NoNewWindow -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$metrics = Wait-WithHeadroom -Process $p -MetricsPath $metricsPath -NoThrow
$exitCode = if ($p.HasExited) { $p.ExitCode } else { 137 }
if ($metrics.guard_tripped -and $exitCode -eq 0) { $exitCode = 137 }
$p.Dispose()

$meta = [ordered]@{
    kind = 'unit'
    crate = $Crate
    exit_code = $exitCode
    guard_tripped = [bool]$metrics.guard_tripped
    elapsed_seconds = $metrics.elapsed_seconds
    metrics = $metrics
}
$meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metaPath -Encoding utf8

# The Actions console drops lines from large bursts of libtest diagnostics. The workflow
# saves both original streams; keep the counts and failing test names visible in console too.
if (Test-Path -LiteralPath $stdout) {
    Select-String -Path $stdout -Pattern '^test result:|^test .* \.\.\. FAILED$' | ForEach-Object Line
}
exit $exitCode
