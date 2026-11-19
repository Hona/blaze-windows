# Run one real-world Windows corpus project from harness/windows-corpus.json through blaze:
# fetch -> lock -> check -> build -> run --version -> test -> noop -> edit -> stop -> profile.
# Continues past independent failures (when -ContinueOnFailure is set) and writes corpus-result.json,
# timings.csv, script-runs.csv, memory-peak.csv and memory-tasks.csv for the batch summary.
param(
    [string] $Blaze = '',
    [string] $Out = '',
    [string] $Project = '',
    [string] $Manifest = 'harness/windows-corpus.json',
    [string] $SourcesDir = '',
    [switch] $ContinueOnFailure,
    [switch] $SkipEdit,
    [switch] $SelfTest
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Manifest)) {
    throw "Corpus manifest not found: $Manifest"
}
$manifestData = Get-Content -LiteralPath $Manifest -Raw -Encoding utf8 | ConvertFrom-Json
$allProjects = @($manifestData.projects)

if ($SelfTest) {
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($allProjects.Count -eq 0) { throw 'Corpus manifest has no projects' }
    foreach ($p in $allProjects) {
        if (-not $p.name) { throw 'Corpus entry missing name' }
        if (-not $seen.Add($p.name)) { throw "Duplicate corpus project name: $($p.name)" }
        if ($p.source.kind -eq 'git') {
            if (-not $p.source.repo -or $p.source.repo -notmatch '^[^/\s]+/[^/\s]+$') {
                throw "$($p.name): invalid git repo '$($p.source.repo)'"
            }
            if (-not $p.source.rev -or $p.source.rev -notmatch '^[0-9a-f]{40}$') {
                throw "$($p.name): git rev must be a full 40-char SHA, got '$($p.source.rev)'"
            }
        } elseif ($p.source.kind -eq 'local') {
            if (-not (Test-Path -LiteralPath $p.source.path)) {
                throw "$($p.name): local path missing: $($p.source.path)"
            }
            if (-not (Test-Path -LiteralPath (Join-Path $p.source.path 'Cargo.toml'))) {
                throw "$($p.name): Cargo.toml missing under $($p.source.path)"
            }
            if ($p.edit -and $p.edit.file) {
                $editPath = Join-Path $p.source.path $p.edit.file
                if (-not (Test-Path -LiteralPath $editPath)) {
                    throw "$($p.name): edit target missing: $editPath"
                }
                $txt = Get-Content -LiteralPath $editPath -Raw -Encoding utf8
                if (-not $txt.Contains([string]$p.edit.find)) {
                    throw "$($p.name): edit.find not found in $editPath"
                }
            }
        } else {
            throw "$($p.name): unknown source.kind '$($p.source.kind)'"
        }
    }
    Write-Host "SelfTest OK: $($allProjects.Count) corpus projects validated ($($allProjects.name -join ', '))"
    exit 0
}

if (-not $Blaze -or -not $Out -or -not $Project) {
    throw 'Required parameters: -Blaze <path> -Out <dir> -Project <name> (or -SelfTest)'
}
$proj = $allProjects | Where-Object { $_.name -eq $Project } | Select-Object -First 1
if ($null -eq $proj) {
    $valid = ($allProjects | ForEach-Object { $_.name }) -join ', '
    throw "Unknown corpus project '$Project'. Valid projects: $valid"
}
if (-not (Test-Path -LiteralPath $Blaze)) {
    throw "Blaze executable not found: $Blaze"
}
$blazePath = (Resolve-Path -LiteralPath $Blaze).Path

$totalWatch = [Diagnostics.Stopwatch]::StartNew()
New-Item -ItemType Directory -Force $Out | Out-Null
$outPath = (Resolve-Path -LiteralPath $Out).Path

$env:BLAZE_HOME = Join-Path $outPath 'home'
$env:BLAZE_CORES = if ($proj.cores) { [string]$proj.cores } else { '1' }
$env:BLAZE_LOCK = 'write'
$env:CARGO_TERM_COLOR = 'never'
$env:RUST_BACKTRACE = '0'

$stepTimeoutMin = if ($proj.step_timeout_minutes) { [int]$proj.step_timeout_minutes } else { 25 }
$timings = Join-Path $outPath 'timings.csv'
'project,step,seconds,exit' | Set-Content -LiteralPath $timings -Encoding utf8

$stepRecords = [System.Collections.Generic.List[object]]::new()
$anyFail = $false
$scriptRunsInfo = $null
$testCounts = $null
$daemonPeakLines = @()

function Strip-Ansi([string] $Text) {
    if ($null -eq $Text) { return '' }
    return ([regex]::Replace($Text, "`e\[[0-9;]*[A-Za-z]", ''))
}

function Get-TailSnippet([string[]] $Paths, [int] $Lines = 25) {
    $buf = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Paths) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            $tail = @(Get-Content -LiteralPath $p -Tail $Lines -ErrorAction SilentlyContinue)
            if ($tail.Count -gt 0) {
                $buf.Add("--- $(Split-Path -Leaf $p) ---")
                foreach ($line in $tail) { $buf.Add($line) }
            }
        }
    }
    return ($buf -join "`n")
}

function Record-Step([string] $name, [string] $cmd, [string] $status, [int] $exitCode, [double] $seconds, [string] $err, [string] $tail) {
    $stepRecords.Add([ordered]@{
        name = $name
        command = $cmd
        status = $status
        exit_code = $exitCode
        seconds = $seconds
        error = $err
        log_tail = $tail
    })
    if ($status -ne 'ok' -and $status -ne 'skipped') {
        $script:anyFail = $true
    }
}

function Parse-TestStream([string] $StdoutPath, [string] $StderrPath) {
    $raw = ''
    foreach ($p in @($StdoutPath, $StderrPath)) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            $chunk = Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue
            if ($chunk) { $raw += "`n" + $chunk }
        }
    }
    $lines = (Strip-Ansi $raw) -split "`r?`n"
    $passed = 0
    $failed = 0
    $ignored = 0
    $summaries = 0
    $failedTests = [System.Collections.Generic.List[string]]::new()
    foreach ($ln in $lines) {
        if ($ln -match '^test (\S+)(?: - .*)? \.\.\. FAILED$') {
            $failedTests.Add($Matches[1])
        } elseif ($ln -match '^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;') {
            $summaries++
            $passed += [int]$Matches[1]
            $failed += [int]$Matches[2]
            $ignored += [int]$Matches[3]
        }
    }
    return [ordered]@{
        summaries = $summaries
        passed = $passed
        failed = $failed
        ignored = $ignored
        failed_tests = @($failedTests | Select-Object -First 40)
    }
}

function Run-BlazeStep([string] $step, [string] $dir, [string[]] $words, [string] $expect) {
    $log = Join-Path $outPath "$Project-$step.log"
    $err = Join-Path $outPath "$Project-$step.stderr.log"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $code = -1
    $client = Start-Process $blazePath -WorkingDirectory $dir -ArgumentList $words -PassThru -NoNewWindow `
        -RedirectStandardOutput $log -RedirectStandardError $err
    try {
        while (!$client.WaitForExit(60000)) {
            $sample = Join-Path $outPath "$Project-$step-status-$([int]$watch.Elapsed.TotalSeconds)"
            $status = Start-Process $blazePath -WorkingDirectory $dir -ArgumentList @('status', '--json') `
                -PassThru -NoNewWindow -RedirectStandardOutput "$sample.log" -RedirectStandardError "$sample.stderr.log"
            try {
                if (!$status.WaitForExit(5000)) {
                    $status.Kill($true)
                    Write-Warning "status timed out ($sample)"
                } elseif ($status.ExitCode) { Write-Warning "status exited $($status.ExitCode) ($sample)" }
            } finally { $status.Dispose() }
            if ($watch.Elapsed.TotalMinutes -ge $stepTimeoutMin) {
                $timedOut = $true
                break
            }
        }
        if (!$timedOut) { $code = $client.ExitCode } else { $code = 124 }
    } finally {
        if (!$client.HasExited) { $client.Kill($true) }
        $client.Dispose()
    }
    $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    "$Project,$step,$seconds,$code" | Add-Content -LiteralPath $timings -Encoding utf8
    $cmdStr = "blaze $($words -join ' ')"
    Write-Host "$Project $step ($($words -join ' ')): exit $code in $seconds s"

    $failReason = ''
    if ($timedOut) {
        $failReason = "$Project $step exceeded $stepTimeoutMin minutes (see $err and status logs)"
    } elseif ($code -ne 0) {
        $failReason = "$Project $step failed with exit $code (log $log)"
    } elseif ($expect -and -not (Select-String -Path $log,$err -SimpleMatch $expect -Quiet)) {
        $failReason = "$Project $step did not print '$expect' (log $log)"
    }

    if ($failReason) {
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 60 }
        if (Test-Path -LiteralPath $err) { Get-Content -LiteralPath $err -Tail 60 }
        $tail = Get-TailSnippet @($log, $err) 25
        $st = if ($timedOut) { 'TIMEOUT' } else { 'FAILED' }
        Record-Step $step $cmdStr $st $code $seconds $failReason $tail
        if (-not $ContinueOnFailure) { throw $failReason }
        Write-Warning $failReason
        return $false
    }

    Record-Step $step $cmdStr 'ok' $code $seconds '' ''
    return $true
}

function Prepare-ProjectDir {
    $workRoot = Join-Path $outPath 'work'
    $workDir = Join-Path $workRoot $Project
    if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force }
    New-Item -ItemType Directory -Force $workRoot | Out-Null

    $watch = [Diagnostics.Stopwatch]::StartNew()
    if ($proj.source.kind -eq 'local') {
        Copy-Item -LiteralPath $proj.source.path -Destination $workDir -Recurse
        $watch.Stop()
        Record-Step 'fetch' "copy $($proj.source.path)" 'ok' 0 ([math]::Round($watch.Elapsed.TotalSeconds, 3)) '' ''
        return $workDir
    }

    $repo = [string]$proj.source.repo
    $rev = [string]$proj.source.rev
    $url = "https://github.com/$repo.git"
    $cacheDir = if ($SourcesDir) { Join-Path $SourcesDir "$Project-$($rev.Substring(0,12))" } else { '' }
    $fetchDir = if ($cacheDir) { $cacheDir } else { $workDir }

    $needClone = $true
    if ($cacheDir -and (Test-Path -LiteralPath (Join-Path $cacheDir '.git'))) {
        $curHead = (& git -C $cacheDir rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $curHead -eq $rev) {
            $needClone = $false
        }
    }

    if ($needClone) {
        if (Test-Path -LiteralPath $fetchDir) { Remove-Item -LiteralPath $fetchDir -Recurse -Force }
        New-Item -ItemType Directory -Force $fetchDir | Out-Null
        $fetchLog = Join-Path $outPath "$Project-fetch.log"
        & git -C $fetchDir init --quiet *> $fetchLog
        if ($LASTEXITCODE) { throw "git init failed ($LASTEXITCODE)" }
        & git -C $fetchDir remote add origin $url *>> $fetchLog
        if ($LASTEXITCODE) { throw "git remote add failed ($LASTEXITCODE)" }
        & git -C $fetchDir fetch --depth 1 origin $rev *>> $fetchLog
        if ($LASTEXITCODE) { throw "git fetch $url $rev failed ($LASTEXITCODE)" }
        & git -C $fetchDir checkout --quiet --detach FETCH_HEAD *>> $fetchLog
        if ($LASTEXITCODE) { throw "git checkout FETCH_HEAD failed ($LASTEXITCODE)" }
        $got = (& git -C $fetchDir rev-parse HEAD).Trim()
        if ($got -ne $rev) {
            throw "Pinned commit mismatch for ${Project}: expected $rev, got $got"
        }
    }

    if ($cacheDir) {
        Copy-Item -LiteralPath $cacheDir -Destination $workDir -Recurse
        $dotGit = Join-Path $workDir '.git'
        if (Test-Path -LiteralPath $dotGit) { Remove-Item -LiteralPath $dotGit -Recurse -Force }
    }

    $watch.Stop()
    Record-Step 'fetch' "git fetch $repo@$($rev.Substring(0,9))" 'ok' 0 ([math]::Round($watch.Elapsed.TotalSeconds, 3)) '' ''
    return $workDir
}

try {
    $projectDir = Prepare-ProjectDir
    $serverLog = Join-Path $outPath 'serve.stderr.log'
    $serverStdout = Join-Path $outPath 'serve.stdout.log'
    $tcLog = Join-Path $outPath 'toolchain.log'

    $tcWatch = [Diagnostics.Stopwatch]::StartNew()
    & $blazePath toolchain *> $tcLog
    $tcCode = $LASTEXITCODE
    $tcSec = [math]::Round($tcWatch.Elapsed.TotalSeconds, 3)
    if ($tcCode -ne 0) {
        Record-Step 'toolchain' 'blaze toolchain' 'FAILED' $tcCode $tcSec "blaze toolchain failed: $tcCode (see toolchain.log)" (Get-TailSnippet @($tcLog) 25)
        throw "blaze toolchain failed: $tcCode"
    }
    Record-Step 'toolchain' 'blaze toolchain' 'ok' 0 $tcSec '' ''

    $serveWatch = [Diagnostics.Stopwatch]::StartNew()
    $server = Start-Process -FilePath $blazePath -ArgumentList 'serve' -NoNewWindow -PassThru `
        -RedirectStandardError $serverLog -RedirectStandardOutput $serverStdout
    $ready = $false
    try {
        $deadline = [datetime]::UtcNow.AddMinutes(4)
        do {
            if ($server.HasExited) {
                if (Test-Path -LiteralPath $serverLog) { Get-Content -LiteralPath $serverLog -Tail 40 }
                $serveSec = [math]::Round($serveWatch.Elapsed.TotalSeconds, 3)
                Record-Step 'serve' 'blaze serve' 'FAILED' $server.ExitCode $serveSec "blaze serve exited during startup: $($server.ExitCode)" (Get-TailSnippet @($serverLog, $serverStdout) 25)
                throw "blaze serve exited during startup: $($server.ExitCode)"
            }
            $ready = Select-String -LiteralPath $serverLog -SimpleMatch 'blaze serve: listening on ' -Quiet -ErrorAction SilentlyContinue
            if (!$ready) { Start-Sleep -Milliseconds 500 }
        } until ($ready -or [datetime]::UtcNow -ge $deadline)
        $serveSec = [math]::Round($serveWatch.Elapsed.TotalSeconds, 3)
        if (!$ready) {
            Record-Step 'serve' 'blaze serve' 'TIMEOUT' 124 $serveSec 'blaze serve did not announce its listener in four minutes' (Get-TailSnippet @($serverLog, $serverStdout) 25)
            throw 'blaze serve did not announce its listener in four minutes'
        }
        Record-Step 'serve' 'blaze serve' 'ok' 0 $serveSec '' ''

        $locked = Run-BlazeStep 'lock' $projectDir @('lock') ''
        if (-not $locked) {
            foreach ($sk in @('check', 'build', 'run', 'test', 'noop', 'edit')) {
                Record-Step $sk "blaze $sk" 'skipped' 0 0 'lock failed' ''
            }
        } else {
            $checkArgs = @('check') + @($proj.check_args | Where-Object { $null -ne $_ })
            $buildArgs = @('build') + @($proj.build_args | Where-Object { $null -ne $_ })
            $testArgs = @('test') + @($proj.test_args | Where-Object { $null -ne $_ })

            [void](Run-BlazeStep 'check' $projectDir $checkArgs '')
            $built = Run-BlazeStep 'build' $projectDir $buildArgs ''

            if ($built) {
                if ($null -ne $proj.run_args) {
                    $runArgs = @('run', '-q') + @($proj.run_args | Where-Object { $null -ne $_ })
                    [void](Run-BlazeStep 'run' $projectDir $runArgs ([string]$proj.run_expect))
                } else {
                    Record-Step 'run' 'blaze run' 'skipped' 0 0 'server binary (no --version CLI)' ''
                }
            } else {
                Record-Step 'run' 'blaze run' 'skipped' 0 0 'build failed' ''
            }

            [void](Run-BlazeStep 'test' $projectDir $testArgs '')
            $testCounts = Parse-TestStream (Join-Path $outPath "$Project-test.log") (Join-Path $outPath "$Project-test.stderr.log")

            if ($built) {
                [void](Run-BlazeStep 'noop' $projectDir $buildArgs '')
                if (-not $SkipEdit -and $proj.edit -and $proj.edit.file) {
                    $editFile = Join-Path $projectDir ([string]$proj.edit.file)
                    if (Test-Path -LiteralPath $editFile) {
                        $orig = Get-Content -LiteralPath $editFile -Raw -Encoding utf8
                        $find = [string]$proj.edit.find
                        if ($orig.Contains($find)) {
                            $orig.Replace($find, [string]$proj.edit.replace) | Set-Content -LiteralPath $editFile -NoNewline -Encoding utf8
                            $edited = Run-BlazeStep 'edit' $projectDir $buildArgs ''
                            if ($edited -and $proj.edit.run_expect -and $null -ne $proj.run_args) {
                                $runArgs = @('run', '-q') + @($proj.run_args | Where-Object { $null -ne $_ })
                                [void](Run-BlazeStep 'run-edited' $projectDir $runArgs ([string]$proj.edit.run_expect))
                            }
                        } else {
                            Record-Step 'edit' 'edit source' 'FAILED' 1 0 "edit.find string not found in $($proj.edit.file)" ''
                        }
                    } else {
                        Record-Step 'edit' 'edit source' 'FAILED' 1 0 "edit target file missing: $($proj.edit.file)" ''
                    }
                } else {
                    Record-Step 'edit' 'blaze build' 'skipped' 0 0 'edit skipped' ''
                }
            } else {
                Record-Step 'noop' 'blaze build' 'skipped' 0 0 'build failed' ''
                Record-Step 'edit' 'blaze build' 'skipped' 0 0 'build failed' ''
            }
        }
    } finally {
        $stopWatch = [Diagnostics.Stopwatch]::StartNew()
        $stopErr = ''
        if ($ready) {
            if (!$server.HasExited) {
                $stop = Start-Process -FilePath $blazePath -ArgumentList 'stop' -NoNewWindow -PassThru `
                    -RedirectStandardError (Join-Path $outPath 'stop.stderr.log') -RedirectStandardOutput (Join-Path $outPath 'stop.log')
                if (!$stop.WaitForExit(60000)) {
                    $stop.Kill()
                    $stopErr = 'blaze stop timed out'
                    Write-Warning $stopErr
                } elseif ($stop.ExitCode -ne 0) {
                    $stopErr = "blaze stop exited $($stop.ExitCode)"
                    Write-Warning $stopErr
                }
                $stop.Dispose()
            }
            if (!$server.WaitForExit(30000)) {
                $server.Kill()
                $stopSec = [math]::Round($stopWatch.Elapsed.TotalSeconds, 3)
                Record-Step 'stop' 'blaze stop' 'FAILED' 124 $stopSec 'foreground daemon did not shut down cleanly' (Get-TailSnippet @($serverLog) 25)
            } elseif ($server.ExitCode -ne 0) {
                $stopSec = [math]::Round($stopWatch.Elapsed.TotalSeconds, 3)
                Record-Step 'stop' 'blaze stop' 'FAILED' $server.ExitCode $stopSec "foreground daemon exited $($server.ExitCode) (see serve.stderr.log)" (Get-TailSnippet @($serverLog) 25)
            } else {
                $stopSec = [math]::Round($stopWatch.Elapsed.TotalSeconds, 3)
                Record-Step 'stop' 'blaze stop' 'ok' 0 $stopSec $stopErr ''
            }
        } elseif (!$server.HasExited) {
            try { $server.Kill($true) } catch {}
            try { [void]$server.WaitForExit(10000) } catch {}
        }
        $server.Dispose()
    }

    # Profile summary via DuckDB (build-script runs + peak memory by owner + top tasks).
    $profileDir = Join-Path $env:BLAZE_HOME 'v2/profile'
    $parquets = @(Get-ChildItem -LiteralPath $profileDir -Filter '*.builds.parquet' -ErrorAction SilentlyContinue)
    if ($parquets.Count -gt 0) {
        $profWatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $profile = $profileDir.Replace('\', '/')
            $missParquets = @(Get-ChildItem -LiteralPath $profileDir -Filter '*.misses.parquet' -ErrorAction SilentlyContinue)
            $query = if ($missParquets.Count -gt 0) {
@"
with b as (select distinct build_id, started_unix_ns, command, workspace, outcome, dur_ns
           from read_parquet('$profile/*.builds.parquet', union_by_name=true)),
     m as (select distinct build_id, item from read_parquet('$profile/*.misses.parquet', union_by_name=true)
           where step = 'build script run')
select b.build_id, b.started_unix_ns, b.command, b.workspace, b.outcome, round(b.dur_ns / 1e9, 3) as engine_s, count(m.item) as script_runs
from b left join m using (build_id) group by all order by b.started_unix_ns
"@
            } else {
@"
select distinct build_id, started_unix_ns, command, workspace, outcome, round(dur_ns / 1e9, 3) as engine_s, 0 as script_runs
from read_parquet('$profile/*.builds.parquet', union_by_name=true)
order by started_unix_ns
"@
            }
            python -m pip install --quiet duckdb
            if ($LASTEXITCODE) { throw 'pip install duckdb failed' }
            $counts = Join-Path $outPath 'script-runs.csv'
            python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $query $counts
            if ($LASTEXITCODE) { throw "the profile query failed (profile $profile)" }
            Get-Content -LiteralPath $counts

            $builds = @(Import-Csv $counts | Where-Object { $_.command -eq 'build' -and $_.outcome -eq 'ok' })
            $scriptRunsInfo = [ordered]@{
                completed_builds = $builds.Count
                build = if ($builds.Count -ge 1) { [int]$builds[0].script_runs } else { $null }
                noop = if ($builds.Count -ge 2) { [int]$builds[1].script_runs } else { $null }
                edit = if ($builds.Count -ge 3) { [int]$builds[2].script_runs } else { $null }
            }
            $profErr = ''
            if ($proj.check_zero_script_reruns -and -not $SkipEdit -and $builds.Count -ge 3) {
                if ([int]$builds[1].script_runs -ne 0) { $profErr = "no-op ran $($builds[1].script_runs) build script(s)" }
                elseif ([int]$builds[2].script_runs -ne 0) { $profErr = "one-line edit ran $($builds[2].script_runs) build script(s)" }
            }
            $profSec = [math]::Round($profWatch.Elapsed.TotalSeconds, 3)
            if ($profErr) {
                Record-Step 'profile' 'duckdb profile check' 'FAILED' 1 $profSec $profErr (Get-TailSnippet @($counts) 20)
            } else {
                Record-Step 'profile' 'duckdb profile check' 'ok' 0 $profSec '' ''
            }

            $counterParquets = @(Get-ChildItem -LiteralPath $profileDir -Filter '*.counters.parquet' -ErrorAction SilentlyContinue)
            if ($counterParquets.Count -gt 0) {
                $memQuery = @"
with c as (select build_id, t_ns, name, value
           from read_parquet('$profile/*.counters.parquet', union_by_name=true))
select name,
       round(max(value) / 1048576.0, 2) as peak_mib,
       round(arg_max(value, t_ns) / 1048576.0, 2) as end_mib
from c
where name in ('footprint bytes', 'heap live bytes', 'blaze-mem resident bytes',
               'allocator kept bytes', 'allocator purged bytes', 'committed bytes',
               'pool resident bytes', 'store heap bytes', 'blocks live bytes',
               'blocks warm bytes', 'blocks cold bytes', 'chunks warm bytes', 'chunks cold bytes')
   or name like 'tag live bytes: %'
   or name like 'tag heap bytes: %'
   or name like 'tag heap allocated bytes: %'
group by name
order by peak_mib desc
"@
                $memCsv = Join-Path $outPath 'memory-peak.csv'
                python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $memQuery $memCsv
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '--- Peak memory by owner (MiB) ---'
                    Get-Content -LiteralPath $memCsv
                }
            }

            $spanParquets = @(Get-ChildItem -LiteralPath $profileDir -Filter '*.spans.parquet' -ErrorAction SilentlyContinue)
            if ($spanParquets.Count -gt 0) {
                $taskMemQuery = @"
select build_id, function as task, crate, unit,
       round(peak_bytes / 1048576.0, 2) as peak_mib,
       round(heap_allocated_bytes / 1048576.0, 2) as alloc_mib,
       round(dur_ns / 1e9, 3) as dur_s
from read_parquet('$profile/*.spans.parquet', union_by_name=true)
where name = 'task' and (peak_bytes is not null or heap_allocated_bytes is not null)
order by coalesce(peak_bytes, 0) desc, coalesce(heap_allocated_bytes, 0) desc
limit 25
"@
                $taskMemCsv = Join-Path $outPath 'memory-tasks.csv'
                python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $taskMemQuery $taskMemCsv
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '--- Top tasks by memory (MiB) ---'
                    Get-Content -LiteralPath $taskMemCsv
                }
            }
        } catch {
            $profSec = [math]::Round($profWatch.Elapsed.TotalSeconds, 3)
            Record-Step 'profile' 'duckdb profile check' 'FAILED' 1 $profSec $_.Exception.Message ''
        }
    } else {
        Record-Step 'profile' 'duckdb profile check' 'skipped' 0 0 'no *.builds.parquet written' ''
    }

    if (Test-Path -LiteralPath $serverLog) {
        $daemonPeakLines = @(Select-String -LiteralPath $serverLog -Pattern 'peak memory:|peak commit' -ErrorAction SilentlyContinue | ForEach-Object { $_.Line })
        foreach ($ln in $daemonPeakLines) { Write-Host $ln }
    }

    if (Test-Path -LiteralPath $timings) { Get-Content -LiteralPath $timings }
} catch {
    if (-not $anyFail) {
        Record-Step 'fatal' 'windows-corpus.ps1' 'FAILED' 1 ([math]::Round($totalWatch.Elapsed.TotalSeconds, 3)) $_.Exception.Message ''
    }
    Write-Warning $_.Exception.Message
} finally {
    $totalWatch.Stop()
    $result = [ordered]@{
        kind = 'corpus'
        project = $Project
        archetype = [string]$proj.archetype
        source = $proj.source
        overall_ok = (-not $anyFail)
        elapsed_seconds = [math]::Round($totalWatch.Elapsed.TotalSeconds, 2)
        test_counts = $testCounts
        script_runs = $scriptRunsInfo
        daemon_peak = @($daemonPeakLines)
        steps = @($stepRecords)
    }
    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outPath 'corpus-result.json') -Encoding utf8
}

if ($anyFail) { exit 1 }
exit 0
