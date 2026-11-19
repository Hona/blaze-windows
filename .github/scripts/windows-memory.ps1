# Keep the last memory/commit sample in the Actions log and record peaks for the batch summary.
function Wait-WithHeadroom {
    param(
        [Parameter(Mandatory)] [Diagnostics.Process] $Process,
        [string] $MetricsPath = '',
        [int] $IntervalMs = 3000,
        [switch] $LogDisk,
        [switch] $NoThrow
    )
    $counters = @('Available Bytes', 'Committed Bytes', 'Commit Limit') | ForEach-Object {
        [Diagnostics.PerformanceCounter]::new('Memory', $_)
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $samples = 0
    $minRam = [double]::PositiveInfinity
    $maxCommitted = 0.0
    $commitLimit = 0.0
    $minHeadroom = [double]::PositiveInfinity
    $guardTripped = $false
    try {
        do {
            $ramBytes = [double]$counters[0].RawValue
            $committedBytes = [double]$counters[1].RawValue
            $limitBytes = [double]$counters[2].RawValue
            $headroomBytes = $limitBytes - $committedBytes

            $ramMiB = $ramBytes / 1MB
            $committedMiB = $committedBytes / 1MB
            $limitMiB = $limitBytes / 1MB
            $headroomMiB = $headroomBytes / 1MB

            $samples++
            if ($ramMiB -lt $minRam) { $minRam = $ramMiB }
            if ($committedMiB -gt $maxCommitted) { $maxCommitted = $committedMiB }
            if ($limitMiB -gt $commitLimit) { $commitLimit = $limitMiB }
            if ($headroomMiB -lt $minHeadroom) { $minHeadroom = $headroomMiB }

            $diskPart = ''
            if ($LogDisk) {
                $cFree = [int]((Get-PSDrive C).Free / 1MB)
                $dFree = [int]((Get-PSDrive D).Free / 1MB)
                $diskPart = "; disk C $cFree MiB, D $dFree MiB"
            }
            Write-Host ('{0:o} available RAM {1:F0} MiB; committed {2:F0} MiB; commit headroom {3:F0} MiB{4}' -f [datetime]::UtcNow, $ramMiB, $committedMiB, $headroomMiB, $diskPart)

            if ($ramBytes -lt 768MB -or $headroomBytes -lt 2GB) {
                $guardTripped = $true
                Write-Warning "Runner memory guard tripped (available RAM $([int]$ramMiB) MiB, commit headroom $([int]$headroomMiB) MiB)"
                break
            }
        } while (!$Process.WaitForExit($IntervalMs))
    } finally {
        if (!$Process.HasExited) {
            try { $Process.Kill($true) } catch {}
            try { [void]$Process.WaitForExit(15000) } catch {}
        }
        foreach ($counter in $counters) { $counter.Dispose() }
        $watch.Stop()
        $metrics = [ordered]@{
            samples = $samples
            min_available_ram_mib = if ($samples -gt 0) { [int][math]::Round($minRam) } else { $null }
            max_committed_mib = if ($samples -gt 0) { [int][math]::Round($maxCommitted) } else { $null }
            commit_limit_mib = if ($samples -gt 0) { [int][math]::Round($commitLimit) } else { $null }
            min_commit_headroom_mib = if ($samples -gt 0) { [int][math]::Round($minHeadroom) } else { $null }
            guard_tripped = $guardTripped
            elapsed_seconds = [math]::Round($watch.Elapsed.TotalSeconds, 2)
        }
        if ($MetricsPath) {
            $parent = Split-Path -Parent $MetricsPath
            if ($parent) { New-Item -ItemType Directory -Force $parent | Out-Null }
            $metrics | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $MetricsPath -Encoding utf8
        }
    }
    if ($guardTripped -and -not $NoThrow) {
        throw 'Stopped at runner memory guard'
    }
    return $metrics
}
