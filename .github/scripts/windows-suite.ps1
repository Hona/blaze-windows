# Run one ordinary libtest suite at a time. Stop early under memory pressure so the runner
# can retain the log rather than losing contact with the service.
param([Parameter(Mandatory)][string] $Crate)
$ErrorActionPreference = 'Stop'
$root = $PWD.Path
$dir = Join-Path $root "crates/$Crate"
$exe = Join-Path $root "target/debug/deps/$Crate.exe"
. (Join-Path $PSScriptRoot 'windows-memory.ps1')
$stdout = Join-Path $root "$Crate.stdout.log"
$stderr = Join-Path $root "$Crate.stderr.log"
$p = Start-Process $exe -ArgumentList '--test-threads=1' -WorkingDirectory $dir -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
Wait-WithHeadroom $p
# The Actions console drops lines from large bursts of libtest diagnostics. The workflow
# saves both original streams on failure; keep the counts visible on successful runs too.
Select-String -Path $stdout -Pattern '^test result:|^test .* \.\.\. FAILED$' | ForEach-Object Line
exit $p.ExitCode
