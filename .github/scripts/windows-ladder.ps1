# The small end-to-end ladder on a Windows runner (a VM): hello world and a crate with
# dependencies, each checked, built, run and tested with the blaze this job built, then a no-op
# build and a one-line edit, each timed, with the build-script runs each build made read from the
# profile. Every command's output goes to the log directory the workflow uploads. Stops at the
# first step that fails, naming it (docs/contributing.md, "Scripts that run commands").
param(
    [Parameter(Mandatory)] [string] $Blaze,
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [ValidateSet('hello','withdeps','rune-cstr','one-luau','r28-ops')] [string] $Fixture
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$env:BLAZE_HOME = Join-Path $Out 'home'
$env:BLAZE_CORES = if ($Fixture -in @('withdeps','one-luau','r28-ops')) { '1' } else { 'all' }
$timings = Join-Path $Out 'timings.csv'
'project,step,seconds,exit' | Set-Content $timings

function Step([string] $project, [string] $step, [string] $dir, [string[]] $words, [string] $expect) {
    $log = Join-Path $Out "$project-$step.log"
    $err = Join-Path $Out "$project-$step.stderr.log"
    $watch = [Diagnostics.Stopwatch]::StartNew()
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
            if ($watch.Elapsed.TotalMinutes -ge 20) { throw "$project $step exceeded 20 minutes (see $err and status logs)" }
        }
        $code = $client.ExitCode
    } finally {
        if (!$client.HasExited) { $client.Kill($true) }
        $client.Dispose()
    }
    $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    "$project,$step,$seconds,$code" | Add-Content $timings
    Write-Host "$project $step ($($words -join ' ')): exit $code in $seconds s"
    if ($code -ne 0) {
        Get-Content $log -Tail 60
        Get-Content $err -Tail 60
        throw "$project $step failed with exit $code (log $log)"
    }
    if ($expect -and -not (Select-String -Path $log,$err -SimpleMatch $expect -Quiet)) {
        Get-Content $log -Tail 60
        Get-Content $err -Tail 60
        throw "$project $step did not print '$expect' (log $log)"
    }
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

$serverLog = Join-Path $Out 'serve.stderr.log'
# Auto-starting clients install the pinned sysroot first; a directly launched server requires
# it to be whole already. Install with blaze's own verifier, not the runner's rustup default.
& $Blaze toolchain *> (Join-Path $Out 'toolchain.log')
if ($LASTEXITCODE) { throw "blaze toolchain failed: $LASTEXITCODE (see toolchain.log)" }
$server = Start-Process -FilePath $Blaze -ArgumentList 'serve' -NoNewWindow -PassThru `
    -RedirectStandardError $serverLog -RedirectStandardOutput (Join-Path $Out 'serve.stdout.log')
$ready = $false
try {
    $deadline = [datetime]::UtcNow.AddMinutes(4)
    do {
        if ($server.HasExited) {
            Get-Content $serverLog -Tail 40
            throw "blaze serve exited during startup: $($server.ExitCode)"
        }
        $ready = Select-String -LiteralPath $serverLog -SimpleMatch 'blaze serve: listening on ' -Quiet
        if (!$ready) { Start-Sleep -Milliseconds 500 }
    } until ($ready -or [datetime]::UtcNow -ge $deadline)
    if (!$ready) { throw 'blaze serve did not announce its listener in four minutes' }
    if ($Fixture -eq 'rune-cstr') {
        Step $Fixture 'lock' $cstr @('lock') ''
        Step $Fixture 'build' $cstr @('build') ''
        Step $Fixture 'run' $cstr @('run','-q') 'LOC allocation: [76, 79, 67, 0]'
    }
    foreach ($p in @(@('hello', $hello, 'hello from blaze'), @('withdeps', $withdeps, 'hello from blaze with deps'))) {
        $name, $dir, $said = $p
        if ($name -ne $Fixture) { continue }
        Step $name 'lock' $dir @('lock') ''
        Step $name 'check' $dir @('check') ''
        Step $name 'build' $dir @('build') ''
        Step $name 'run' $dir @('run', '-q') $said
        Step $name 'test' $dir @('test') 'test result: ok'
        Step $name 'noop' $dir @('build') ''
        $file = Join-Path $dir 'src/main.rs'
        (Get-Content $file -Raw).Replace("`"$said`"", "`"$said, edited`"") | Set-Content $file -NoNewline
        Step $name 'edit' $dir @('build') ''
        Step $name 'run-edited' $dir @('run', '-q') "$said, edited"
    }
    foreach ($p in @(@('one-luau', $oneLuau, 'pub fn one() -> i32 { 1 }', 'pub fn one() -> i32 { 2 }'), @('r28-ops', $r28Ops, 'pub fn one() -> u8 { 1 }', 'pub fn one() -> u8 { 2 }'))) {
        $name, $dir, $before, $after = $p
        if ($name -ne $Fixture) { continue }
        Step $name 'lock' $dir @('lock') ''
        Step $name 'check' $dir @('check') ''
        Step $name 'build' $dir @('build') ''
        Step $name 'noop' $dir @('build') ''
        $file = Join-Path $dir 'src/lib.rs'
        (Get-Content $file -Raw).Replace($before, $after) | Set-Content $file -NoNewline
        Step $name 'edit' $dir @('build') ''
    }

} finally {
    # Stop only the daemon in this job's private home. Never ask for detached startup.
    if ($ready -and !$server.HasExited) {
        $stop = Start-Process -FilePath $Blaze -ArgumentList 'stop' -NoNewWindow -PassThru `
            -RedirectStandardError (Join-Path $Out 'stop.stderr.log') -RedirectStandardOutput (Join-Path $Out 'stop.log')
        if (!$stop.WaitForExit(60000)) { $stop.Kill(); Write-Warning 'blaze stop timed out' }
        elseif ($stop.ExitCode -ne 0) { Write-Warning "blaze stop exited $($stop.ExitCode)" }
    }
    if (!$server.WaitForExit(30000)) {
        $server.Kill(); throw 'foreground daemon did not shut down cleanly'
    }
    if ($server.ExitCode -ne 0) { throw "foreground daemon exited $($server.ExitCode) (see serve.stderr.log)" }
}

# The build-script runs each build made, from the profile's misses (`blaze debug sql` asks a Unix
# socket, which the Windows daemon has none of).
$profile = (Join-Path $env:BLAZE_HOME 'v2/profile').Replace('\', '/')
$query = @"
with b as (select distinct build_id, started_unix_ns, command, workspace, outcome, dur_ns
           from read_parquet('$profile/*.builds.parquet', union_by_name=true)),
     m as (select distinct build_id, item from read_parquet('$profile/*.misses.parquet', union_by_name=true)
           where step = 'build script run')
select b.build_id, b.started_unix_ns, b.command, b.workspace, b.outcome, round(b.dur_ns / 1e9, 3) as engine_s, count(m.item) as script_runs
from b left join m using (build_id) group by all order by b.started_unix_ns
"@
python -m pip install --quiet duckdb
if ($LASTEXITCODE) { throw 'pip install duckdb failed' }
$counts = Join-Path $Out 'script-runs.csv'
python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $query $counts
if ($LASTEXITCODE) { throw "the profile query failed (profile $profile)" }
Get-Content $counts

if ($Fixture -ne 'rune-cstr') {
    # The three standalone `build` requests in execution order: cold, no-op, edit.
    $builds = @(Import-Csv $counts | Where-Object { $_.command -eq 'build' -and $_.outcome -eq 'ok' })
    if ($builds.Count -ne 3) { throw "expected three completed build profiles; got $($builds.Count)" }
    Write-Host "build-script runs: build=$($builds[0].script_runs) noop=$($builds[1].script_runs) edit=$($builds[2].script_runs)"
    if ([int]$builds[1].script_runs -ne 0) { throw 'the no-op ran a build script' }
    if ([int]$builds[2].script_runs -ne 0) { throw 'the one-line edit ran a build script' }
}

# Peak memory by owner from the profile's counters and task spans, plus the daemon's own peak
# snapshot (which includes query storage and Windows CommitMap at the highest footprint).
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
$memCsv = Join-Path $Out 'memory-peak.csv'
$taskMemCsv = Join-Path $Out 'memory-tasks.csv'
python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $memQuery $memCsv
if ($LASTEXITCODE -eq 0) {
    Write-Host '--- Peak memory by owner (MiB) ---'
    Get-Content $memCsv
}
python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $taskMemQuery $taskMemCsv
if ($LASTEXITCODE -eq 0) {
    Write-Host '--- Top tasks by memory (MiB) ---'
    Get-Content $taskMemCsv
}
Select-String -LiteralPath $serverLog -Pattern 'peak memory:|peak commit' | ForEach-Object { Write-Host $_.Line }

Get-Content $timings
