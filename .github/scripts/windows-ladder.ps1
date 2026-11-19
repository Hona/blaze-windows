# The small end-to-end ladder on a Windows runner (a VM): hello world, a crate with dependencies,
# rune-cstr, one-luau (12 packages) and r28-ops (17 packages), each checked, built, run/tested (for
# binary fixtures) with the blaze this run built, then a no-op build and a one-line edit, each timed,
# with the build-script runs and peak memory by owner read from the profile. Continues past
# independent step failures (when -ContinueOnFailure is set) and writes ladder-result.json so the
# batch summary reports every step's status, time, error and memory peaks in one place.
param(
    [Parameter(Mandatory)] [string] $Blaze,
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [ValidateSet('hello','withdeps','rune-cstr','one-luau','r28-ops')] [string] $Fixture,
    [switch] $ContinueOnFailure
)
$ErrorActionPreference = 'Stop'
$totalWatch = [Diagnostics.Stopwatch]::StartNew()
New-Item -ItemType Directory -Force $Out | Out-Null
$env:BLAZE_HOME = Join-Path $Out 'home'
$env:BLAZE_CORES = if ($Fixture -in @('withdeps','one-luau','r28-ops')) { '1' } else { 'all' }
$timings = Join-Path $Out 'timings.csv'
'project,step,seconds,exit' | Set-Content $timings

$stepRecords = [System.Collections.Generic.List[object]]::new()
$anyFail = $false
$scriptRunsInfo = $null
$daemonPeakLines = @()

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

function Step([string] $project, [string] $step, [string] $dir, [string[]] $words, [string] $expect) {
    $log = Join-Path $Out "$project-$step.log"
    $err = Join-Path $Out "$project-$step.stderr.log"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $code = -1
    $client = Start-Process $Blaze -WorkingDirectory $dir -ArgumentList $words -PassThru -NoNewWindow `
        -RedirectStandardOutput $log -RedirectStandardError $err
    try {
        # Capture a live request, not just the empty queue after a stall error. Keep the
        # client's own stall/task dump in stderr. Bound both clients independently.
        while (!$client.WaitForExit(60000)) {
            $sample = Join-Path $Out "$project-$step-status-$([int]$watch.Elapsed.TotalSeconds)"
            $status = Start-Process $Blaze -WorkingDirectory $dir -ArgumentList @('status','--json') `
                -PassThru -NoNewWindow -RedirectStandardOutput "$sample.log" -RedirectStandardError "$sample.stderr.log"
            try {
                if (!$status.WaitForExit(5000)) {
                    $status.Kill($true)
                    Write-Warning "status timed out ($sample)"
                } elseif ($status.ExitCode) { Write-Warning "status exited $($status.ExitCode) ($sample)" }
            } finally { $status.Dispose() }
            if ($watch.Elapsed.TotalMinutes -ge 20) {
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
    "$project,$step,$seconds,$code" | Add-Content $timings
    $cmdStr = "blaze $($words -join ' ')"
    Write-Host "$project $step ($($words -join ' ')): exit $code in $seconds s"

    $failReason = ''
    if ($timedOut) {
        $failReason = "$project $step exceeded 20 minutes (see $err and status logs)"
    } elseif ($code -ne 0) {
        $failReason = "$project $step failed with exit $code (log $log)"
    } elseif ($expect -and -not (Select-String -Path $log,$err -SimpleMatch $expect -Quiet)) {
        $failReason = "$project $step did not print '$expect' (log $log)"
    }

    if ($failReason) {
        if (Test-Path -LiteralPath $log) { Get-Content $log -Tail 60 }
        if (Test-Path -LiteralPath $err) { Get-Content $err -Tail 60 }
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

function Project([string] $name, [string] $manifest, [string] $main, [string] $entry = 'src/main.rs') {
    $dir = Join-Path $Out $name
    New-Item -ItemType Directory -Force (Join-Path $dir 'src') | Out-Null
    Set-Content (Join-Path $dir 'Cargo.toml') $manifest
    Set-Content (Join-Path $dir $entry) $main
    $dir
}

$main = @'
fn greeting() -> &'static str {
    "hello from blaze"
}

fn main() {
    println!("{}", greeting());
}

#[test]
fn it_greets() {
    assert!(greeting().starts_with("hello"));
}
'@
$hello = Project 'hello' "[package]`nname = `"hello`"`nversion = `"0.1.0`"`nedition = `"2024`"`n" $main
$cstr = Project 'rune-cstr' "[package]`nname = `"rune-cstr`"`nversion = `"0.1.0`"`nedition = `"2024`"`n" @'
const LOC: &[u8] = c"LOC".to_bytes();
fn main() {
    // SAFETY: the pointer is into the static C string allocation, including its NUL.
    let bytes = unsafe { std::slice::from_raw_parts(LOC.as_ptr(), 4) };
    println!("LOC allocation: {bytes:?}");
    assert_eq!(bytes, b"LOC\0");
}
'@
$withdeps = Project 'withdeps' @'
[package]
name = "withdeps"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
windows-sys = { version = "0.61", features = ["Win32_System_Threading"] }
'@ ($main.Replace('"hello from blaze"', '"hello from blaze with deps"') + @'

#[derive(serde::Serialize)]
struct Point {
    x: i32,
}

#[allow(dead_code)]
fn json() -> anyhow::Result<String> {
    // SAFETY: no arguments.
    let pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
    Ok(serde_json::to_string(&Point { x: pid as i32 })?)
}
'@)
$oneLuau = Project 'one-luau' @'
[package]
name = "perf-one-luau"
version = "0.0.0"
edition = "2024"

[dependencies]
mlua-sys = { git = "https://github.com/mlua-rs/mlua", rev = "a0ad4535fc72ba89967a931c5be57b162b5f0f3f", features = ["luau"] }
'@ "pub fn one() -> i32 { 1 }`n" 'src/lib.rs'
$r28Ops = Project 'r28-ops' @'
[package]
name = "perf-xlsx-ops"
version = "0.0.0"
edition = "2024"

[dependencies]
betteroffice-xlsx-ops = { git = "https://github.com/openooxml/betteroffice", rev = "ed0a3cea5bd24119c4f2e144a978849177e06fcd" }
'@ "pub fn one() -> u8 { 1 }`n" 'src/lib.rs'

try {
    $serverLog = Join-Path $Out 'serve.stderr.log'
    $serverStdout = Join-Path $Out 'serve.stdout.log'
    $tcLog = Join-Path $Out 'toolchain.log'

    # Auto-starting clients install the pinned sysroot first; a directly launched server requires
    # it to be whole already. Install with blaze's own verifier, not the runner's rustup default.
    $tcWatch = [Diagnostics.Stopwatch]::StartNew()
    & $Blaze toolchain *> $tcLog
    $tcCode = $LASTEXITCODE
    $tcSec = [math]::Round($tcWatch.Elapsed.TotalSeconds, 3)
    if ($tcCode -ne 0) {
        Record-Step 'toolchain' 'blaze toolchain' 'FAILED' $tcCode $tcSec "blaze toolchain failed: $tcCode (see toolchain.log)" (Get-TailSnippet @($tcLog) 25)
        throw "blaze toolchain failed: $tcCode (see toolchain.log)"
    }
    Record-Step 'toolchain' 'blaze toolchain' 'ok' 0 $tcSec '' ''

    $serveWatch = [Diagnostics.Stopwatch]::StartNew()
    $server = Start-Process -FilePath $Blaze -ArgumentList 'serve' -NoNewWindow -PassThru `
        -RedirectStandardError $serverLog -RedirectStandardOutput $serverStdout
    $ready = $false
    try {
        $deadline = [datetime]::UtcNow.AddMinutes(4)
        do {
            if ($server.HasExited) {
                if (Test-Path -LiteralPath $serverLog) { Get-Content $serverLog -Tail 40 }
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

        if ($Fixture -eq 'rune-cstr') {
            $locked = Step $Fixture 'lock' $cstr @('lock') ''
            if ($locked) {
                $built = Step $Fixture 'build' $cstr @('build') ''
                if ($built) {
                    [void](Step $Fixture 'run' $cstr @('run','-q') 'LOC allocation: [76, 79, 67, 0]')
                } else {
                    Record-Step 'run' 'blaze run -q' 'skipped' 0 0 'build failed' ''
                }
            } else {
                Record-Step 'build' 'blaze build' 'skipped' 0 0 'lock failed' ''
                Record-Step 'run' 'blaze run -q' 'skipped' 0 0 'lock failed' ''
            }
        }
        foreach ($p in @(@('hello', $hello, 'hello from blaze'), @('withdeps', $withdeps, 'hello from blaze with deps'))) {
            $name, $dir, $said = $p
            if ($name -ne $Fixture) { continue }
            $locked = Step $name 'lock' $dir @('lock') ''
            if (-not $locked) {
                foreach ($sk in @('check', 'build', 'run', 'test', 'noop', 'edit', 'run-edited')) {
                    Record-Step $sk "blaze $sk" 'skipped' 0 0 'lock failed' ''
                }
                continue
            }
            [void](Step $name 'check' $dir @('check') '')
            $built = Step $name 'build' $dir @('build') ''
            if ($built) {
                [void](Step $name 'run' $dir @('run', '-q') $said)
                [void](Step $name 'test' $dir @('test') 'test result: ok')
                [void](Step $name 'noop' $dir @('build') '')
                $file = Join-Path $dir 'src/main.rs'
                (Get-Content $file -Raw).Replace("`"$said`"", "`"$said, edited`"") | Set-Content $file -NoNewline
                $edited = Step $name 'edit' $dir @('build') ''
                if ($edited) {
                    [void](Step $name 'run-edited' $dir @('run', '-q') "$said, edited")
                } else {
                    Record-Step 'run-edited' 'blaze run -q' 'skipped' 0 0 'edit build failed' ''
                }
            } else {
                foreach ($sk in @('run', 'test', 'noop', 'edit', 'run-edited')) {
                    Record-Step $sk "blaze $sk" 'skipped' 0 0 'build failed' ''
                }
            }
        }
        foreach ($p in @(@('one-luau', $oneLuau, 'pub fn one() -> i32 { 1 }', 'pub fn one() -> i32 { 2 }'), @('r28-ops', $r28Ops, 'pub fn one() -> u8 { 1 }', 'pub fn one() -> u8 { 2 }'))) {
            $name, $dir, $before, $after = $p
            if ($name -ne $Fixture) { continue }
            $locked = Step $name 'lock' $dir @('lock') ''
            if (-not $locked) {
                foreach ($sk in @('check', 'build', 'noop', 'edit')) {
                    Record-Step $sk "blaze $sk" 'skipped' 0 0 'lock failed' ''
                }
                continue
            }
            [void](Step $name 'check' $dir @('check') '')
            $built = Step $name 'build' $dir @('build') ''
            if ($built) {
                [void](Step $name 'noop' $dir @('build') '')
                $file = Join-Path $dir 'src/lib.rs'
                (Get-Content $file -Raw).Replace($before, $after) | Set-Content $file -NoNewline
                [void](Step $name 'edit' $dir @('build') '')
            } else {
                foreach ($sk in @('noop', 'edit')) {
                    Record-Step $sk "blaze $sk" 'skipped' 0 0 'build failed' ''
                }
            }
        }
    } finally {
        # Stop only the daemon in this job's private home. Never ask for detached startup.
        $stopWatch = [Diagnostics.Stopwatch]::StartNew()
        $stopErr = ''
        if ($ready) {
            if (!$server.HasExited) {
                $stop = Start-Process -FilePath $Blaze -ArgumentList 'stop' -NoNewWindow -PassThru `
                    -RedirectStandardError (Join-Path $Out 'stop.stderr.log') -RedirectStandardOutput (Join-Path $Out 'stop.log')
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

    # The build-script runs each build made, plus peak memory by owner and top tasks from the
    # profile (`blaze debug sql` asks a Unix socket, which the Windows daemon has none of).
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
            $counts = Join-Path $Out 'script-runs.csv'
            python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $query $counts
            if ($LASTEXITCODE) { throw "the profile query failed (profile $profile)" }
            Get-Content $counts

            $builds = @(Import-Csv $counts | Where-Object { $_.command -eq 'build' -and $_.outcome -eq 'ok' })
            if ($Fixture -ne 'rune-cstr') {
                # The three standalone `build` requests in execution order: cold, no-op, edit.
                $scriptRunsInfo = [ordered]@{
                    completed_builds = $builds.Count
                    build = if ($builds.Count -ge 1) { [int]$builds[0].script_runs } else { $null }
                    noop = if ($builds.Count -ge 2) { [int]$builds[1].script_runs } else { $null }
                    edit = if ($builds.Count -ge 3) { [int]$builds[2].script_runs } else { $null }
                }
                $profErr = ''
                if ($builds.Count -ne 3) { $profErr = "expected three completed build profiles; got $($builds.Count)" }
                elseif ([int]$builds[1].script_runs -ne 0) { $profErr = "the no-op ran $($builds[1].script_runs) build script(s)" }
                elseif ([int]$builds[2].script_runs -ne 0) { $profErr = "the one-line edit ran $($builds[2].script_runs) build script(s)" }
                else {
                    Write-Host "build-script runs: build=$($builds[0].script_runs) noop=$($builds[1].script_runs) edit=$($builds[2].script_runs)"
                }
                $profSec = [math]::Round($profWatch.Elapsed.TotalSeconds, 3)
                if ($profErr) {
                    Record-Step 'profile' 'duckdb profile check' 'FAILED' 1 $profSec $profErr (Get-TailSnippet @($counts) 20)
                } else {
                    Record-Step 'profile' 'duckdb profile check' 'ok' 0 $profSec '' ''
                }
            } else {
                $scriptRunsInfo = [ordered]@{
                    completed_builds = $builds.Count
                    build = if ($builds.Count -ge 1) { [int]$builds[0].script_runs } else { $null }
                    noop = $null
                    edit = $null
                }
                $profSec = [math]::Round($profWatch.Elapsed.TotalSeconds, 3)
                Record-Step 'profile' 'duckdb profile check' 'ok' 0 $profSec '' ''
            }

            # Peak memory by owner from the profile's counters and task spans.
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
                $memCsv = Join-Path $Out 'memory-peak.csv'
                python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $memQuery $memCsv
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '--- Peak memory by owner (MiB) ---'
                    Get-Content $memCsv
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
                $taskMemCsv = Join-Path $Out 'memory-tasks.csv'
                python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $taskMemQuery $taskMemCsv
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '--- Top tasks by memory (MiB) ---'
                    Get-Content $taskMemCsv
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

    if (Test-Path -LiteralPath $timings) { Get-Content $timings }
} catch {
    if (-not $anyFail) {
        Record-Step 'fatal' 'windows-ladder.ps1' 'FAILED' 1 ([math]::Round($totalWatch.Elapsed.TotalSeconds, 3)) $_.Exception.Message ''
    }
    Write-Warning $_.Exception.Message
} finally {
    $totalWatch.Stop()
    $result = [ordered]@{
        kind = 'ladder'
        fixture = $Fixture
        overall_ok = (-not $anyFail)
        elapsed_seconds = [math]::Round($totalWatch.Elapsed.TotalSeconds, 2)
        script_runs = $scriptRunsInfo
        daemon_peak = @($daemonPeakLines)
        steps = @($stepRecords)
    }
    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Out 'ladder-result.json') -Encoding utf8
}

if ($anyFail) { exit 1 }
exit 0
