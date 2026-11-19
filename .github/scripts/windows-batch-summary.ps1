# Aggregate all artifacts from a Windows batch gate run into one readable Markdown summary
# (written to $OutDir/batch-summary.md and $GITHUB_STEP_SUMMARY) and one machine-readable JSON
# report ($OutDir/batch-summary.json). Cross-platform PowerShell 7 (runs on ubuntu-latest).
param(
    [Parameter(Mandatory)] [string] $ArtifactsDir,
    [Parameter(Mandatory)] [string] $OutDir,
    [string] $CorpusManifest = '',
    [string] $Commit = '',
    [string] $RefName = '',
    [string] $RunUrl = '',
    [string] $JobResultsJson = ''
)
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Force $OutDir | Out-Null
$outPath = (Resolve-Path -LiteralPath $OutDir).Path

$expectedCrates = @('blaze-cargo', 'blaze-cas', 'blaze-core', 'blaze-link', 'blaze-mem', 'blaze-usercode', 'blaze-vfs')
$expectedFixtures = @('hello', 'withdeps', 'rune-cstr', 'one-luau', 'r28-ops')

$jobResults = @{}
if ($JobResultsJson) {
    try {
        $parsedJobs = $JobResultsJson | ConvertFrom-Json -AsHashtable
        if ($parsedJobs) { $jobResults = $parsedJobs }
    } catch {
        Write-Warning "Could not parse JobResultsJson: $($_.Exception.Message)"
    }
}

function Strip-Ansi([string] $Text) {
    if ($null -eq $Text) { return '' }
    return ([regex]::Replace($Text, "`e\[[0-9;]*[A-Za-z]", ''))
}

function Read-JsonFile([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json)
    } catch {
        Write-Warning "Failed to parse JSON $Path`: $($_.Exception.Message)"
        return $null
    }
}

function Fmt-Num($Val, [string] $Suffix = '') {
    if ($null -eq $Val -or ($Val -is [string] -and $Val -eq '')) { return '-' }
    return "$Val$Suffix"
}

function Parse-LibtestLog([string] $StdoutPath, [string] $StderrPath) {
    $stdoutRaw = if ($StdoutPath -and (Test-Path -LiteralPath $StdoutPath)) { Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue } else { '' }
    $stderrRaw = if ($StderrPath -and (Test-Path -LiteralPath $StderrPath)) { Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue } else { '' }
    if ($null -eq $stdoutRaw) { $stdoutRaw = '' }
    if ($null -eq $stderrRaw) { $stderrRaw = '' }

    $lines = (Strip-Ansi $stdoutRaw) -split "`r?`n"
    $passed = 0
    $failed = 0
    $ignored = 0
    $finishedSec = $null
    $hasSummary = $false
    $summaryOk = $false
    $failedNames = [System.Collections.Generic.List[string]]::new()
    $lastTestSeen = ''

    foreach ($ln in $lines) {
        if ($ln -match '^test (\S+)(?: - .*)? \.\.\. (ok|FAILED|ignored)') {
            $name = $Matches[1]
            $state = $Matches[2]
            $lastTestSeen = $name
            switch ($state) {
                'ok'      { $passed++ }
                'FAILED'  { $failed++; $failedNames.Add($name) }
                'ignored' { $ignored++ }
            }
        } elseif ($ln -match '^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; \d+ filtered out; finished in ([\d.]+)s') {
            $hasSummary = $true
            $summaryOk = ($Matches[1] -eq 'ok')
            $passed = [int]$Matches[2]
            $failed = [int]$Matches[3]
            $ignored = [int]$Matches[4]
            $finishedSec = [double]$Matches[5]
        }
    }

    # Extract per-test stdout/stderr panic/assertion blocks from libtest's `failures:` section.
    $blocks = @{}
    function Add-Block([string] $Name, [System.Collections.Generic.List[string]] $LinesBuf) {
        if (-not $Name -or $LinesBuf.Count -eq 0) { return }
        if (-not $blocks.ContainsKey($Name)) {
            $blocks[$Name] = [System.Collections.Generic.List[string]]::new()
        }
        foreach ($l in $LinesBuf) { $blocks[$Name].Add($l) }
    }
    $inFailures = $false
    $curName = $null
    $buf = [System.Collections.Generic.List[string]]::new()
    foreach ($ln in $lines) {
        if ($ln -eq 'failures:') {
            Add-Block $curName $buf
            $curName = $null
            $buf.Clear()
            $inFailures = $true
            continue
        }
        if ($inFailures) {
            if ($ln -match '^---- (\S+) (?:stdout|stderr) ----$') {
                Add-Block $curName $buf
                $curName = $Matches[1]
                $buf.Clear()
            } elseif ($ln -match '^test result:') {
                Add-Block $curName $buf
                $curName = $null
                $buf.Clear()
                $inFailures = $false
            } elseif ($null -ne $curName) {
                $buf.Add($ln)
            }
        }
    }
    Add-Block $curName $buf

    $failures = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $failedNames) {
        $rawLines = @()
        if ($blocks.ContainsKey($name)) {
            $rawLines = @($blocks[$name] | Where-Object { $_.Trim() -ne '' })
        }
        # Prefer the panic/assertion lines when a test printed lots of debug chatter before panicking.
        $panicIdx = -1
        for ($i = 0; $i -lt $rawLines.Count; $i++) {
            if ($rawLines[$i] -match "panicked at|assertion|failed:|Error:") {
                $panicIdx = $i
                break
            }
        }
        $excerpt = if ($panicIdx -gt 1) {
            $start = if ($rawLines[$panicIdx - 1] -match '^blaze serve:') { $panicIdx } else { $panicIdx - 1 }
            @($rawLines[$start..([math]::Min($rawLines.Count - 1, $start + 17))])
        } elseif ($rawLines.Count -gt 18) {
            @($rawLines[0..17])
        } else {
            $rawLines
        }
        $failures.Add([ordered]@{
            test = $name
            message = ($excerpt -join "`n")
            total_lines = $rawLines.Count
        })
    }

    $stderrLines = @((Strip-Ansi $stderrRaw) -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
    $stderrTail = if ($stderrLines.Count -gt 0) {
        ($stderrLines | Select-Object -Last 25) -join "`n"
    } else { '' }
    $stdoutTail = (($lines | Where-Object { $_.Trim() -ne '' }) | Select-Object -Last 20) -join "`n"

    return [ordered]@{
        has_summary = $hasSummary
        summary_ok = $summaryOk
        passed = $passed
        failed = $failed
        ignored = $ignored
        finished_seconds = $finishedSec
        last_test = $lastTestSeen
        failures = @($failures)
        stderr_tail = $stderrTail
        stdout_tail = $stdoutTail
    }
}

$anyFailure = $false
$peakStats = [ordered]@{
    min_available_ram_mib = $null
    min_available_ram_source = ''
    max_committed_mib = $null
    max_committed_source = ''
    min_commit_headroom_mib = $null
    min_commit_headroom_source = ''
    any_guard_tripped = $false
}

function Track-Metrics([string] $Source, $Metrics) {
    if ($null -eq $Metrics) { return }
    if ($null -ne $Metrics.min_available_ram_mib) {
        $v = [int]$Metrics.min_available_ram_mib
        if ($null -eq $peakStats.min_available_ram_mib -or $v -lt $peakStats.min_available_ram_mib) {
            $peakStats.min_available_ram_mib = $v
            $peakStats.min_available_ram_source = $Source
        }
    }
    if ($null -ne $Metrics.max_committed_mib) {
        $v = [int]$Metrics.max_committed_mib
        if ($null -eq $peakStats.max_committed_mib -or $v -gt $peakStats.max_committed_mib) {
            $peakStats.max_committed_mib = $v
            $peakStats.max_committed_source = $Source
        }
    }
    if ($null -ne $Metrics.min_commit_headroom_mib) {
        $v = [int]$Metrics.min_commit_headroom_mib
        if ($null -eq $peakStats.min_commit_headroom_mib -or $v -lt $peakStats.min_commit_headroom_mib) {
            $peakStats.min_commit_headroom_mib = $v
            $peakStats.min_commit_headroom_source = $Source
        }
    }
    if ($Metrics.guard_tripped) { $peakStats.any_guard_tripped = $true }
}

# 1. Build stages
$buildUnitsDir = Join-Path $ArtifactsDir 'result-build-units'
$buildUnits = Read-JsonFile (Join-Path $buildUnitsDir 'build-units.json')
if ($null -eq $buildUnits) {
    $anyFailure = $true
} else {
    Track-Metrics 'build-units' $buildUnits.metrics
    if (-not $buildUnits.compile_ok -or -not $buildUnits.astlog_ok) { $anyFailure = $true }
}

$buildReleaseDir = Join-Path $ArtifactsDir 'result-build-release'
$buildRelease = Read-JsonFile (Join-Path $buildReleaseDir 'build-release.json')
if ($null -eq $buildRelease) {
    $anyFailure = $true
} else {
    Track-Metrics 'build-release' $buildRelease.metrics
    if (-not $buildRelease.build_ok -or -not $buildRelease.version_ok -or -not $buildRelease.stack_ok) { $anyFailure = $true }
}

# 2. Unit suites
$unitSummaries = [System.Collections.Generic.List[object]]::new()
$totalUnitsPassed = 0
$totalUnitsFailed = 0
$totalUnitsIgnored = 0
foreach ($crate in $expectedCrates) {
    $cDir = Join-Path $ArtifactsDir "result-unit-$crate"
    $meta = Read-JsonFile (Join-Path $cDir "$crate.meta.json")
    $metrics = if ($meta -and $meta.metrics) { $meta.metrics } else { Read-JsonFile (Join-Path $cDir "$crate.metrics.json") }
    $stdoutPath = Join-Path $cDir "$crate.stdout.log"
    $stderrPath = Join-Path $cDir "$crate.stderr.log"

    if ($null -eq $meta -and -not (Test-Path -LiteralPath $stdoutPath)) {
        $reason = if ($buildUnits -and -not $buildUnits.compile_ok) { 'NOT_RUN (build-units failed)' } else { 'MISSING (no artifact / VM lost)' }
        $anyFailure = $true
        $unitSummaries.Add([ordered]@{
            crate = $crate
            status = $reason
            ok = $false
            passed = 0
            failed = 0
            ignored = 0
            exit_code = $null
            elapsed_seconds = $null
            metrics = $null
            failures = @()
            crash_detail = $reason
        })
        continue
    }

    Track-Metrics "units/$crate" $metrics
    $parsed = Parse-LibtestLog $stdoutPath $stderrPath
    $exitCode = if ($meta) { [int]$meta.exit_code } else { -1 }
    $guardTripped = if ($meta) { [bool]$meta.guard_tripped } else { $false }
    $elapsed = if ($meta -and $null -ne $meta.elapsed_seconds) { $meta.elapsed_seconds } else { $parsed.finished_seconds }

    $status = 'ok'
    $ok = $true
    $crashDetail = ''
    if ($guardTripped) {
        $status = 'MEM_GUARD'
        $ok = $false
        $crashDetail = "Stopped at runner memory guard after last test '$($parsed.last_test)'"
    } elseif ($parsed.failed -gt 0) {
        $status = 'FAIL'
        $ok = $false
    } elseif ($exitCode -ne 0 -or -not $parsed.has_summary) {
        $status = 'CRASH'
        $ok = $false
        $crashDetail = "Exited $exitCode without completed libtest summary (last test: '$($parsed.last_test)')"
        if ($parsed.stderr_tail) { $crashDetail += "`n$($parsed.stderr_tail)" }
        elseif ($parsed.stdout_tail) { $crashDetail += "`n$($parsed.stdout_tail)" }
    } elseif ($parsed.passed -eq 0 -and $parsed.ignored -eq 0) {
        $status = 'EMPTY'
        $ok = $false
        $crashDetail = 'Suite reported 0 tests'
    }

    if (-not $ok) { $anyFailure = $true }
    $totalUnitsPassed += $parsed.passed
    $totalUnitsFailed += $parsed.failed
    $totalUnitsIgnored += $parsed.ignored

    $unitSummaries.Add([ordered]@{
        crate = $crate
        status = $status
        ok = $ok
        passed = $parsed.passed
        failed = $parsed.failed
        ignored = $parsed.ignored
        exit_code = $exitCode
        elapsed_seconds = $elapsed
        metrics = $metrics
        failures = $parsed.failures
        crash_detail = $crashDetail
    })
}

# 3. Compiler regressions
$regDir = Join-Path $ArtifactsDir 'result-regressions'
$regData = Read-JsonFile (Join-Path $regDir 'regressions.json')
$regCases = [System.Collections.Generic.List[object]]::new()
if ($null -eq $regData) {
    $anyFailure = $true
} else {
    Track-Metrics 'regressions' $regData.metrics
    if (-not $regData.overall_ok) { $anyFailure = $true }
    foreach ($c in @($regData.cases)) {
        $caseFailMsg = ''
        if ($c.status -ne 'ok') {
            $parsed = Parse-LibtestLog (Join-Path $regDir "$($c.slug).stdout.log") (Join-Path $regDir "$($c.slug).stderr.log")
            if ($parsed.failures.Count -gt 0) {
                $caseFailMsg = ($parsed.failures | ForEach-Object { $_.message }) -join "`n"
            } elseif ($parsed.stderr_tail) {
                $caseFailMsg = $parsed.stderr_tail
            } elseif ($parsed.stdout_tail) {
                $caseFailMsg = $parsed.stdout_tail
            } else {
                $caseFailMsg = [string]$c.error
            }
        }
        $regCases.Add([ordered]@{
            crate = $c.crate
            filter = $c.filter
            status = $c.status
            exit_code = $c.exit_code
            elapsed_seconds = $c.elapsed_seconds
            error = $c.error
            message = $caseFailMsg
        })
    }
}

# 4. Release ladders
$ladderSummaries = [System.Collections.Generic.List[object]]::new()
foreach ($fixture in $expectedFixtures) {
    $lDir = Join-Path $ArtifactsDir "result-ladder-$fixture"
    $lData = Read-JsonFile (Join-Path $lDir 'ladder-result.json')
    $lMetrics = Read-JsonFile (Join-Path $lDir 'metrics.json')
    Track-Metrics "ladder/$fixture" $lMetrics

    if ($null -eq $lData) {
        $reason = if ($buildRelease -and -not $buildRelease.build_ok) { 'NOT_RUN (build-release failed)' }
                  elseif ($lMetrics -and $lMetrics.guard_tripped) { 'MEM_GUARD' }
                  else { 'MISSING (no artifact / VM lost)' }
        $anyFailure = $true
        $ladderSummaries.Add([ordered]@{
            fixture = $fixture
            status = $reason
            ok = $false
            elapsed_seconds = if ($lMetrics) { $lMetrics.elapsed_seconds } else { $null }
            script_runs = $null
            metrics = $lMetrics
            steps = @()
        })
        continue
    }

    $guardTripped = ($null -ne $lMetrics -and [bool]$lMetrics.guard_tripped)
    $ok = [bool]$lData.overall_ok -and (-not $guardTripped)
    if (-not $ok) { $anyFailure = $true }
    $status = if ($guardTripped) { 'MEM_GUARD' } elseif ($ok) { 'ok' } else { 'FAIL' }

    $ladderSummaries.Add([ordered]@{
        fixture = $fixture
        status = $status
        ok = $ok
        elapsed_seconds = $lData.elapsed_seconds
        script_runs = $lData.script_runs
        daemon_peak = if ($lData.daemon_peak) { @($lData.daemon_peak) } else { @() }
        metrics = $lMetrics
        steps = @($lData.steps)
    })
}

# 5. Windows project corpus (B13)
$corpusExpected = [System.Collections.Generic.List[object]]::new()
if ($CorpusManifest -and (Test-Path -LiteralPath $CorpusManifest)) {
    $cManifest = Read-JsonFile $CorpusManifest
    if ($cManifest -and $cManifest.projects) {
        foreach ($p in @($cManifest.projects)) {
            $corpusExpected.Add([ordered]@{ name = [string]$p.name; archetype = [string]$p.archetype })
        }
    }
} elseif (Test-Path -LiteralPath $ArtifactsDir) {
    foreach ($d in @(Get-ChildItem -LiteralPath $ArtifactsDir -Directory -Filter 'result-corpus-*' -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $pName = $d.Name.Substring('result-corpus-'.Length)
        $corpusExpected.Add([ordered]@{ name = $pName; archetype = '' })
    }
}

$corpusSummaries = [System.Collections.Generic.List[object]]::new()
$corpusMissing = $false
foreach ($spec in $corpusExpected) {
    $pName = $spec.name
    $cDir = Join-Path $ArtifactsDir "result-corpus-$pName"
    $cData = Read-JsonFile (Join-Path $cDir 'corpus-result.json')
    $cMetrics = Read-JsonFile (Join-Path $cDir 'metrics.json')
    Track-Metrics "corpus/$pName" $cMetrics

    if ($null -eq $cData) {
        $reason = if ($buildRelease -and -not $buildRelease.build_ok) { 'NOT_RUN (build-release failed)' }
                  elseif ($cMetrics -and $cMetrics.guard_tripped) { 'MEM_GUARD' }
                  else { $corpusMissing = $true; 'MISSING (no artifact / VM lost)' }
        $corpusSummaries.Add([ordered]@{
            project = $pName
            archetype = $spec.archetype
            status = $reason
            ok = $false
            elapsed_seconds = if ($cMetrics) { $cMetrics.elapsed_seconds } else { $null }
            test_counts = $null
            script_runs = $null
            daemon_peak = @()
            metrics = $cMetrics
            steps = @()
        })
        continue
    }

    $guardTripped = ($null -ne $cMetrics -and [bool]$cMetrics.guard_tripped)
    $ok = [bool]$cData.overall_ok -and (-not $guardTripped)
    $status = if ($guardTripped) { 'MEM_GUARD' } elseif ($ok) { 'ok' } else { 'FAIL' }

    $corpusSummaries.Add([ordered]@{
        project = $pName
        archetype = if ($cData.archetype) { [string]$cData.archetype } else { $spec.archetype }
        status = $status
        ok = $ok
        elapsed_seconds = $cData.elapsed_seconds
        test_counts = $cData.test_counts
        script_runs = $cData.script_runs
        daemon_peak = if ($cData.daemon_peak) { @($cData.daemon_peak) } else { @() }
        metrics = $cMetrics
        steps = @($cData.steps)
    })
}
if ($corpusMissing) { $anyFailure = $true }

# Build Markdown report
$md = [System.Collections.Generic.List[string]]::new()
$verdict = if ($anyFailure) { 'FAIL' } else { 'PASS' }
$shortSha = if ($Commit.Length -ge 9) { $Commit.Substring(0, 9) } else { $Commit }

$md.Add("# Windows batch gate: $verdict")
$md.Add('')
$metaParts = @()
if ($shortSha) { $metaParts += "commit ``$shortSha``" }
if ($RefName) { $metaParts += "ref ``$RefName``" }
if ($RunUrl) { $metaParts += "[run]($RunUrl)" }
if ($metaParts.Count -gt 0) { $md.Add(($metaParts -join ' | ')) }

$regPassed = if ($regData) { $regData.passed } else { 0 }
$regTotal = if ($regData) { $regData.total } else { 0 }
$regDisplay = if ($regData) { "$regPassed/$regTotal passed" } else { 'missing / not run' }
$laddersOk = @($ladderSummaries | Where-Object { $_.ok }).Count
$unitsOk = @($unitSummaries | Where-Object { $_.ok }).Count
$corpusOk = @($corpusSummaries | Where-Object { $_.ok }).Count

function Fmt-Peak($Val, [string] $Source) {
    $num = Fmt-Num $Val ' MiB'
    if ($Source) { return "$num ($Source)" }
    return $num
}

$md.Add('')
$md.Add("- **Units:** $unitsOk/$($expectedCrates.Count) suites ok ($totalUnitsPassed passed, $totalUnitsFailed failed, $totalUnitsIgnored ignored)")
$md.Add("- **Regressions:** $regDisplay")
$md.Add("- **Ladders:** $laddersOk/$($expectedFixtures.Count) fixtures ok")
if ($corpusSummaries.Count -gt 0) {
    $md.Add("- **Project corpus:** $corpusOk/$($corpusSummaries.Count) projects ok (advisory; project bugs listed below, missing harness artifacts fail the run)")
}
$md.Add("- **Memory peaks (worst across batch):** min available RAM $(Fmt-Peak $peakStats.min_available_ram_mib $peakStats.min_available_ram_source), max committed $(Fmt-Peak $peakStats.max_committed_mib $peakStats.max_committed_source), min commit headroom $(Fmt-Peak $peakStats.min_commit_headroom_mib $peakStats.min_commit_headroom_source)$(if ($peakStats.any_guard_tripped) { ' — **MEMORY GUARD TRIPPED**' } else { '' })")
$md.Add('')

# Section 1: Builds & checks
$md.Add('## Builds and static checks')
$md.Add('')
$md.Add('| Stage | Status | Time (s) | Cache (reg / deps) | Min RAM (MiB) | Max commit (MiB) | Min headroom (MiB) | Notes |')
$md.Add('|---|---|---:|---|---:|---:|---:|---|')

if ($buildUnits) {
    $buSt = if ($buildUnits.compile_ok) { 'ok' } else { 'FAIL' }
    $buCache = "$($buildUnits.reg_cache_hit) / $($buildUnits.deps_cache_hit)"
    $buNotes = "15 test bins; astlog rules: $(if ($buildUnits.astlog_ok) { 'ok' } else { 'FAIL' }) ($($buildUnits.astlog_seconds)s)"
    $md.Add("| ``build-units`` | $buSt | $(Fmt-Num $buildUnits.compile_seconds) | $buCache | $(Fmt-Num $buildUnits.metrics.min_available_ram_mib) | $(Fmt-Num $buildUnits.metrics.max_committed_mib) | $(Fmt-Num $buildUnits.metrics.min_commit_headroom_mib) | $buNotes |")
} else {
    $st = if ($jobResults.ContainsKey('build_units')) { "MISSING ($($jobResults['build_units']))" } else { 'MISSING' }
    $md.Add("| ``build-units`` | $st | - | - | - | - | - | no artifact |")
}

if ($buildRelease) {
    $brOk = $buildRelease.build_ok -and $buildRelease.version_ok -and $buildRelease.stack_ok
    $brSt = if ($brOk) { 'ok' } else { 'FAIL' }
    $brCache = "$($buildRelease.reg_cache_hit) / $($buildRelease.deps_cache_hit)"
    $brNotes = "version=$(if ($buildRelease.version_ok) {'ok'} else {'FAIL'}), 8MiB stack=$(if ($buildRelease.stack_ok) {'ok'} else {'FAIL'})"
    if ($buildRelease.version_line) { $brNotes += " (``$($buildRelease.version_line)``)" }
    $md.Add("| ``build-release`` | $brSt | $(Fmt-Num $buildRelease.build_seconds) | $brCache | $(Fmt-Num $buildRelease.metrics.min_available_ram_mib) | $(Fmt-Num $buildRelease.metrics.max_committed_mib) | $(Fmt-Num $buildRelease.metrics.min_commit_headroom_mib) | $brNotes |")
} else {
    $st = if ($jobResults.ContainsKey('build_release')) { "MISSING ($($jobResults['build_release']))" } else { 'MISSING' }
    $md.Add("| ``build-release`` | $st | - | - | - | - | - | no artifact |")
}
$md.Add('')

# Section 2: Unit suites
$md.Add('## Unit suites')
$md.Add('')
$md.Add('| Crate | Status | Passed | Failed | Ignored | Time (s) | Min RAM (MiB) | Max commit (MiB) | Min headroom (MiB) |')
$md.Add('|---|---|---:|---:|---:|---:|---:|---:|---:|')
foreach ($u in $unitSummaries) {
    $m = $u.metrics
    $md.Add("| ``$($u.crate)`` | $($u.status) | $($u.passed) | $($u.failed) | $($u.ignored) | $(Fmt-Num $u.elapsed_seconds) | $(Fmt-Num $(if ($m) {$m.min_available_ram_mib})) | $(Fmt-Num $(if ($m) {$m.max_committed_mib})) | $(Fmt-Num $(if ($m) {$m.min_commit_headroom_mib})) |")
}
$md.Add('')

# Section 3: Compiler regressions
$md.Add('## Compiler regressions')
$md.Add('')
if ($regData) {
    $rm = $regData.metrics
    $md.Add("Total: $($regData.passed)/$($regData.total) passed in $($regData.elapsed_seconds)s (min RAM $(Fmt-Num $rm.min_available_ram_mib ' MiB'), max commit $(Fmt-Num $rm.max_committed_mib ' MiB'), min headroom $(Fmt-Num $rm.min_commit_headroom_mib ' MiB')).")
    $md.Add('')
    $md.Add('| Crate | Test | Status | Time (s) |')
    $md.Add('|---|---|---|---:|')
    foreach ($c in $regCases) {
        $md.Add("| ``$($c.crate)`` | ``$($c.filter)`` | $($c.status) | $(Fmt-Num $c.elapsed_seconds) |")
    }
} else {
    $st = if ($buildUnits -and -not $buildUnits.compile_ok) { 'NOT_RUN (build-units failed)' } else { 'MISSING (no artifact)' }
    $md.Add("Status: **$st**")
}
$md.Add('')

# Section 4: Release ladders
$md.Add('## Release ladders')
$md.Add('')
$md.Add('| Fixture | Status | Time (s) | Script runs (build / noop / edit) | Min RAM (MiB) | Max commit (MiB) | Min headroom (MiB) |')
$md.Add('|---|---|---:|---|---:|---:|---:|')
foreach ($l in $ladderSummaries) {
    $lm = $l.metrics
    $sr = '-'
    if ($l.script_runs) {
        $sr = "$(Fmt-Num $l.script_runs.build) / $(Fmt-Num $l.script_runs.noop) / $(Fmt-Num $l.script_runs.edit)"
    }
    $md.Add("| ``$($l.fixture)`` | $($l.status) | $(Fmt-Num $l.elapsed_seconds) | $sr | $(Fmt-Num $(if ($lm) {$lm.min_available_ram_mib})) | $(Fmt-Num $(if ($lm) {$lm.max_committed_mib})) | $(Fmt-Num $(if ($lm) {$lm.min_commit_headroom_mib})) |")
}
$md.Add('')

foreach ($l in $ladderSummaries) {
    if ($l.steps.Count -eq 0) { continue }
    $md.Add("### Ladder steps: ``$($l.fixture)``")
    $md.Add('')
    $md.Add('| Step | Status | Exit | Time (s) | Error |')
    $md.Add('|---|---|---:|---:|---|')
    foreach ($s in $l.steps) {
        $errCell = if ($s.error) { ($s.error -replace '\|', '\|' -replace "`r?`n", ' ') } else { '' }
        $md.Add("| ``$($s.name)`` | $($s.status) | $($s.exit_code) | $(Fmt-Num $s.seconds) | $errCell |")
    }
    if ($l.daemon_peak -and $l.daemon_peak.Count -gt 0) {
        $md.Add('')
        $md.Add('```text')
        foreach ($pk in $l.daemon_peak) { $md.Add((Strip-Ansi ([string]$pk))) }
        $md.Add('```')
    }
    $md.Add('')
}

# Section 5: Windows project corpus (B13)
if ($corpusSummaries.Count -gt 0) {
    function Get-StepCell($Steps, [string] $Name) {
        $st = @($Steps | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
        if ($st.Count -eq 0) { return '-' }
        $s = $st[0]
        if ($s.status -eq 'ok') { return "ok ($($s.seconds)s)" }
        if ($s.status -eq 'skipped') { return 'skip' }
        return "$($s.status) ($($s.seconds)s)"
    }

    $md.Add('## Windows project corpus')
    $md.Add('')
    $md.Add('| Project | Archetype | Status | Check | Build | Run | Test | Noop | Edit | Tests (p/f/i) | Script runs | Time (s) | Min RAM (MiB) | Max commit (MiB) |')
    $md.Add('|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|')
    foreach ($c in $corpusSummaries) {
        $cm = $c.metrics
        $tc = if ($c.test_counts -and $c.test_counts.summaries -gt 0) {
            "$($c.test_counts.passed)/$($c.test_counts.failed)/$($c.test_counts.ignored)"
        } else { '-' }
        $sr = if ($c.script_runs) {
            "$(Fmt-Num $c.script_runs.build) / $(Fmt-Num $c.script_runs.noop) / $(Fmt-Num $c.script_runs.edit)"
        } else { '-' }
        $md.Add("| ``$($c.project)`` | $($c.archetype) | $($c.status) | $(Get-StepCell $c.steps 'check') | $(Get-StepCell $c.steps 'build') | $(Get-StepCell $c.steps 'run') | $(Get-StepCell $c.steps 'test') | $(Get-StepCell $c.steps 'noop') | $(Get-StepCell $c.steps 'edit') | $tc | $sr | $(Fmt-Num $c.elapsed_seconds) | $(Fmt-Num $(if ($cm) {$cm.min_available_ram_mib})) | $(Fmt-Num $(if ($cm) {$cm.max_committed_mib})) |")
    }
    $md.Add('')
}

# Section 6: Complete fix list (every failure with assertion messages / tails)
$hasCorpusFail = (@($corpusSummaries | Where-Object { -not $_.ok }).Count -gt 0)
$md.Add('## Failures (fix list)')
$md.Add('')
if (-not $anyFailure -and -not $hasCorpusFail) {
    $md.Add('None. Every build, check, unit suite, regression, ladder fixture and corpus project passed.')
    $md.Add('')
} else {
    if ($buildUnits -and (-not $buildUnits.compile_ok -or -not $buildUnits.astlog_ok)) {
        if (-not $buildUnits.compile_ok) {
            $md.Add('### `build-units` compile failure')
            $md.Add('')
            $errLog = Join-Path $buildUnitsDir 'compile.stderr.log'
            $tail = if (Test-Path -LiteralPath $errLog) { ((Get-Content -LiteralPath $errLog -Tail 60) -join "`n") } else { 'see build-units job log' }
            $md.Add('```text')
            $md.Add((Strip-Ansi $tail))
            $md.Add('```')
            $md.Add('')
        }
        if (-not $buildUnits.astlog_ok) {
            $md.Add('### `astlog-core --test rules` failure')
            $md.Add('')
            $astParsed = Parse-LibtestLog (Join-Path $buildUnitsDir 'astlog.stdout.log') (Join-Path $buildUnitsDir 'astlog.stderr.log')
            foreach ($f in $astParsed.failures) {
                $md.Add("- **``$($f.test)``**")
                if ($f.message) {
                    $md.Add('  ```text')
                    foreach ($line in ($f.message -split "`n")) { $md.Add("  $line") }
                    $md.Add('  ```')
                }
            }
            if ($astParsed.failures.Count -eq 0 -and $astParsed.stderr_tail) {
                $md.Add('```text')
                $md.Add($astParsed.stderr_tail)
                $md.Add('```')
            }
            $md.Add('')
        }
    }

    if ($buildRelease -and (-not $buildRelease.build_ok -or -not $buildRelease.version_ok -or -not $buildRelease.stack_ok)) {
        $md.Add('### `build-release` failure')
        $md.Add('')
        if ($buildRelease.error) { $md.Add("- $($buildRelease.error)") }
        $errLog = Join-Path $buildReleaseDir 'build-release.stderr.log'
        if (Test-Path -LiteralPath $errLog) {
            $md.Add('```text')
            $md.Add((Strip-Ansi ((Get-Content -LiteralPath $errLog -Tail 60) -join "`n")))
            $md.Add('```')
        }
        $md.Add('')
    }

    foreach ($u in $unitSummaries) {
        if ($u.ok) { continue }
        $md.Add("### Unit suite: ``$($u.crate)`` ($($u.status): $($u.passed) passed, $($u.failed) failed, $($u.ignored) ignored)")
        $md.Add('')
        if ($u.failures.Count -gt 0) {
            $shown = 0
            foreach ($f in $u.failures) {
                $shown++
                if ($shown -gt 60) {
                    $md.Add("- ... and $($u.failures.Count - 60) more failures (see artifact ``result-unit-$($u.crate)``)")
                    break
                }
                $md.Add("- **``$($f.test)``**")
                if ($f.message) {
                    $md.Add('  ```text')
                    foreach ($line in ($f.message -split "`n")) {
                        $trimmed = if ($line.Length -gt 240) { $line.Substring(0, 240) + '...' } else { $line }
                        $md.Add("  $trimmed")
                    }
                    $md.Add('  ```')
                } else {
                    $md.Add('  *(no panic output — possible silent unwind; inspect artifact logs)*')
                }
            }
        } elseif ($u.crash_detail) {
            $md.Add('```text')
            $md.Add($u.crash_detail)
            $md.Add('```')
        }
        $md.Add('')
    }

    $failedRegs = @($regCases | Where-Object { $_.status -ne 'ok' })
    if ($failedRegs.Count -gt 0) {
        $md.Add('### Compiler regressions')
        $md.Add('')
        foreach ($r in $failedRegs) {
            $md.Add("- **``$($r.crate)::$($r.filter)``** ($($r.status), $($r.elapsed_seconds)s): $($r.error)")
            if ($r.message) {
                $md.Add('  ```text')
                foreach ($line in ($r.message -split "`n")) {
                    $trimmed = if ($line.Length -gt 240) { $line.Substring(0, 240) + '...' } else { $line }
                    $md.Add("  $trimmed")
                }
                $md.Add('  ```')
            }
        }
        $md.Add('')
    }

    foreach ($l in $ladderSummaries) {
        if ($l.ok) { continue }
        $md.Add("### Release ladder: ``$($l.fixture)`` ($($l.status))")
        $md.Add('')
        $badSteps = @($l.steps | Where-Object { $_.status -ne 'ok' -and $_.status -ne 'skipped' })
        if ($badSteps.Count -eq 0) {
            $md.Add("- $($l.status) (see artifact ``result-ladder-$($l.fixture)``)")
        } else {
            foreach ($s in $badSteps) {
                $md.Add("- **``$($s.name)``** ($($s.status), exit $($s.exit_code), $($s.seconds)s): $($s.error)")
                if ($s.log_tail) {
                    $md.Add('  ```text')
                    foreach ($line in ((Strip-Ansi $s.log_tail) -split "`r?`n")) {
                        $trimmed = if ($line.Length -gt 240) { $line.Substring(0, 240) + '...' } else { $line }
                        $md.Add("  $trimmed")
                    }
                    $md.Add('  ```')
                }
            }
        }
        $md.Add('')
    }

    foreach ($c in $corpusSummaries) {
        if ($c.ok) { continue }
        $md.Add("### Project corpus: ``$($c.project)`` ($($c.status))")
        $md.Add('')
        $badSteps = @($c.steps | Where-Object { $_.status -ne 'ok' -and $_.status -ne 'skipped' })
        if ($badSteps.Count -eq 0) {
            $md.Add("- $($c.status) (see artifact ``result-corpus-$($c.project)``)")
        } else {
            foreach ($s in $badSteps) {
                $md.Add("- **``$($s.name)``** ($($s.status), exit $($s.exit_code), $($s.seconds)s): $($s.error)")
                if ($s.log_tail) {
                    $md.Add('  ```text')
                    foreach ($line in ((Strip-Ansi $s.log_tail) -split "`r?`n")) {
                        $trimmed = if ($line.Length -gt 240) { $line.Substring(0, 240) + '...' } else { $line }
                        $md.Add("  $trimmed")
                    }
                    $md.Add('  ```')
                }
            }
        }
        if ($c.test_counts -and $c.test_counts.failed_tests -and $c.test_counts.failed_tests.Count -gt 0) {
            $md.Add("- Failing tests (first $($c.test_counts.failed_tests.Count)): " + (($c.test_counts.failed_tests | ForEach-Object { "``$_``" }) -join ', '))
        }
        if ($c.daemon_peak -and $c.daemon_peak.Count -gt 0) {
            $md.Add('```text')
            foreach ($pk in $c.daemon_peak) { $md.Add((Strip-Ansi ([string]$pk))) }
            $md.Add('```')
        }
        $md.Add('')
    }
}

$mdText = $md -join "`n"
$mdPath = Join-Path $outPath 'batch-summary.md'
$mdText | Set-Content -LiteralPath $mdPath -Encoding utf8

if ($env:GITHUB_STEP_SUMMARY) {
    $summaryText = $mdText
    # GitHub rejects step summaries larger than 1 MiB; keep the full report in the artifact.
    if ([System.Text.Encoding]::UTF8.GetByteCount($summaryText) -gt 900000) {
        $summaryText = $summaryText.Substring(0, [math]::Min($summaryText.Length, 450000)) + "`n`n*(Truncated for GitHub Step Summary 1 MiB limit; download artifact ``windows-batch-summary`` for the complete ``batch-summary.md``.)*`n"
    }
    $summaryText | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}

$jsonOut = [ordered]@{
    verdict = $verdict
    commit = $Commit
    ref = $RefName
    run_url = $RunUrl
    peaks = $peakStats
    builds = [ordered]@{
        units = $buildUnits
        release = $buildRelease
    }
    units = @($unitSummaries)
    regressions = [ordered]@{
        overall_ok = if ($regData) { [bool]$regData.overall_ok } else { $false }
        passed = $regPassed
        total = $regTotal
        metrics = if ($regData) { $regData.metrics } else { $null }
        cases = @($regCases)
    }
    ladders = @($ladderSummaries)
    corpus = @($corpusSummaries)
}
$jsonOut | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $outPath 'batch-summary.json') -Encoding utf8

Write-Host $mdText
if ($anyFailure) { exit 1 }
exit 0
