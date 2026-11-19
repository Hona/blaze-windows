# Keep the last sample in the Actions log, not just in an artifact on the guest.
function Wait-WithHeadroom([Diagnostics.Process] $Process) {
    $counters = @('Available Bytes', 'Committed Bytes', 'Commit Limit') | ForEach-Object {
        [Diagnostics.PerformanceCounter]::new('Memory', $_)
    }
    try {
        do {
            $ram = $counters[0].RawValue
            $headroom = $counters[2].RawValue - $counters[1].RawValue
            Write-Host ('{0:o} available RAM {1:F0} MiB; commit headroom {2:F0} MiB' -f [datetime]::UtcNow, ($ram/1MB), ($headroom/1MB))
            if ($ram -lt 768MB -or $headroom -lt 2GB) { throw 'Stopped at runner memory guard' }
        } while (!$Process.WaitForExit(3000))
    } finally {
        if (!$Process.HasExited) { $Process.Kill($true); $Process.WaitForExit() }
        foreach ($counter in $counters) { $counter.Dispose() }
    }
}
