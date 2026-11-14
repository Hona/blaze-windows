# Run one ordinary libtest suite at a time. Stop early under memory pressure so the runner
# can retain the log rather than losing contact with the service.
param([Parameter(Mandatory)][string] $Crate)
$ErrorActionPreference = 'Stop'
$root = $PWD.Path
$dir = Join-Path $root "crates/$Crate"
$exe = Join-Path $root "target/debug/deps/$Crate.exe"
$watch = [Diagnostics.Stopwatch]::StartNew()
$memory = [Diagnostics.PerformanceCounter]::new('Memory', 'Available Bytes')
$commit = [Diagnostics.PerformanceCounter]::new('Memory', 'Committed Bytes')
$limit = [Diagnostics.PerformanceCounter]::new('Memory', 'Commit Limit')
function Sample {
    $ram = $memory.RawValue
    $used = $commit.RawValue
    $max = $limit.RawValue
    Write-Host ('memory {0:n0}s: RAM free {1:n0} MiB; commit {2:n0}/{3:n0} MiB' -f $watch.Elapsed.TotalSeconds, ($ram/1MB), ($used/1MB), ($max/1MB))
    if (($max - $used) -lt 2GB -or $ram -lt 768MB) { throw 'suite stopped at runner memory guard (commit headroom <2 GiB or available RAM <768 MiB)' }
}
Sample
$p = Start-Process $exe -ArgumentList '--test-threads=1' -WorkingDirectory $dir -NoNewWindow -PassThru
try {
    while (!$p.WaitForExit(1000)) { Sample }
} finally {
    if (!$p.HasExited) { $p.Kill($true); $p.WaitForExit() }
}
exit $p.ExitCode
