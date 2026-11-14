# Run one ordinary libtest suite at a time. Stop early under memory pressure so the runner
# can retain the log rather than losing contact with the service.
param([Parameter(Mandatory)][string] $Crate)
$ErrorActionPreference = 'Stop'
$root = $PWD.Path
$dir = Join-Path $root "crates/$Crate"
$exe = Join-Path $root "target/debug/deps/$Crate.exe"
. (Join-Path $PSScriptRoot 'windows-memory.ps1')
$p = Start-Process $exe -ArgumentList '--test-threads=1' -WorkingDirectory $dir -NoNewWindow -PassThru
Wait-WithHeadroom $p
exit $p.ExitCode
