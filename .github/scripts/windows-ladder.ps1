# The small end-to-end ladder on a Windows runner (a VM): hello world and a crate with
# dependencies, each checked, built, run and tested with the blaze this job built, then a no-op
# build and a one-line edit, each timed, with the build-script runs each build made read from the
# profile. Every command's output goes to the log directory the workflow uploads. Stops at the
# first step that fails, naming it (docs/contributing.md, "Scripts that run commands").
param(
    [Parameter(Mandatory)] [string] $Blaze,
    [Parameter(Mandatory)] [string] $Out
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$env:BLAZE_HOME = Join-Path $Out 'home'
$env:BLAZE_CORES = 'all'
$timings = Join-Path $Out 'timings.csv'
'project,step,seconds,exit' | Set-Content $timings

function Step([string] $project, [string] $step, [string] $dir, [string[]] $words, [string] $expect) {
    $log = Join-Path $Out "$project-$step.log"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $dir
    try { & $Blaze @words *> $log; $code = $LASTEXITCODE } finally { Pop-Location }
    $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    "$project,$step,$seconds,$code" | Add-Content $timings
    Write-Host "$project $step ($($words -join ' ')): exit $code in $seconds s"
    if ($code -ne 0) {
        Get-Content $log -Tail 60
        throw "$project $step failed with exit $code (log $log)"
    }
    if ($expect -and -not (Select-String -Path $log -SimpleMatch $expect -Quiet)) {
        Get-Content $log -Tail 60
        throw "$project $step did not print '$expect' (log $log)"
    }
}

function Project([string] $name, [string] $manifest, [string] $main) {
    $dir = Join-Path $Out $name
    New-Item -ItemType Directory -Force (Join-Path $dir 'src') | Out-Null
    Set-Content (Join-Path $dir 'Cargo.toml') $manifest
    Set-Content (Join-Path $dir 'src/main.rs') $main
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
    foreach ($p in @(@('hello', $hello, 'hello from blaze'), @('withdeps', $withdeps, 'hello from blaze with deps'))) {
        $name, $dir, $said = $p
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
select b.build_id, b.command, b.workspace, b.outcome, round(b.dur_ns / 1e9, 3) as engine_s, count(m.item) as script_runs
from b left join m using (build_id) group by all order by b.started_unix_ns
"@
python -m pip install --quiet duckdb
if ($LASTEXITCODE) { throw 'pip install duckdb failed' }
$counts = Join-Path $Out 'script-runs.csv'
python -c "import duckdb,sys; duckdb.sql(sys.argv[1]).write_csv(sys.argv[2])" $query $counts
if ($LASTEXITCODE) { throw "the profile query failed (profile $profile)" }
Get-Content $counts

Get-Content $timings
