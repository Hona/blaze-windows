# Run all Windows compiler regression tests, continuing past failures so a single batch
# reports every regression at once alongside memory telemetry peaks.
param(
    [string] $BinDir = 'target/debug/deps',
    [string] $OutDir = 'regressions-out',
    [switch] $UseCargo
)
$ErrorActionPreference = 'Stop'

$root = $PWD.Path
New-Item -ItemType Directory -Force $OutDir | Out-Null
$outPath = (Resolve-Path -LiteralPath $OutDir).Path
$binPath = if ($UseCargo) { '' } else { (Resolve-Path -LiteralPath $BinDir).Path }

. (Join-Path $PSScriptRoot 'windows-memory.ps1')

$cases = @(
    @('blaze-graph', 'a_held_reader_does_not_own_the_core_its_writer_needs'),
    @('blaze-graph', 'system_allocator_still_attributes_allocation_churn_by_tag'),
    @('blaze-query', 'an_absent_row_page_does_not_commit_an_ingredients_directory'),
    @('blaze-query', 'a_fresh_storage_does_not_commit_page_owners_for_unallocated_pages'),
    @('blaze-query', 'owners_ids_and_argument_names_are_read_from_the_pages'),
    @('blaze-item-hash', 'every_tracked_query_a_step_reads_is_named_by_a_rule'),
    @('blaze-item-hash', 'an_assoc_items_hygiene_key_is_its_containers_fields_or_refused'),
    @('blaze-items', 'a_read_of_an_items_query_stands_for_its_signature'),
    @('hir-def', 'name_read_classifies_nameres_reads_with_host_file_separators'),
    @('hir-ty', 'an_expansion_adding_only_an_unnamed_const_publishes_its_trait_impl'),
    @('hir-ty-mir', 'a_reference_to_part_of_an_allocation_keeps_all_of_it'),
    @('hir-ty-pure', 'saturating_by_conclusion_is_saturating_by_premise'),
    @('hir-ty-pure', 'a_join_proves_a_shared_premise_once_and_propagates_backwards'),
    @('hir-ty-pure', 'a_wide_dispatch_proof_scales'),
    @('hir-ty-pure', 'wide_dispatch_work_grows_near_linearly'),
    @('hir-ty-pure', 'sparse_liveness_matches_dense_liveness'),
    @('hir-ty-pure', 'sorted_intersect_and_diff_match_btreeset'),
    @('hir-ty-pure', 'a_join_forgets_the_implications_of_values_gone'),
    @('hir-ty-pure', 'a_body_with_no_loop_walks_each_block_once'),
    @('hir-ty-pure', 'a_loop_after_the_dispatch_does_not_rejoin_each_partial_arm'),
    @('hir-ty-pure', 'iterating_recursive_effects_proves_the_instance_sites_only_once'),
    @('hir-ty-pure', 'work_grows_near_linearly_with_the_body')
)

$results = [System.Collections.Generic.List[object]]::new()
$minRam = $null
$maxCommitted = $null
$commitLimit = $null
$minHeadroom = $null
$totalSamples = 0
$anyGuard = $false
$anyFail = $false
$totalWatch = [Diagnostics.Stopwatch]::StartNew()

$idx = 0
foreach ($case in $cases) {
    $idx++
    $crate, $filter = $case
    $slug = ('{0:D2}-{1}-{2}' -f $idx, $crate, ($filter -replace '[^A-Za-z0-9_-]', '_'))
    $stdout = Join-Path $outPath "$slug.stdout.log"
    $stderr = Join-Path $outPath "$slug.stderr.log"
    $metricsFile = Join-Path $outPath "$slug.metrics.json"
    $workDir = Join-Path $root "crates/$crate"

    Write-Host "=== [$idx/$($cases.Count)] $crate :: $filter ==="
    if ($UseCargo) {
        $p = Start-Process 'cargo' -ArgumentList @('test', '--locked', '--lib', '-p', $crate, $filter, '--', '--show-output', '--test-threads=1') `
            -WorkingDirectory $root -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    } else {
        $exe = Join-Path $binPath "$crate.exe"
        if (-not (Test-Path -LiteralPath $exe)) {
            $anyFail = $true
            $results.Add([ordered]@{
                crate = $crate
                filter = $filter
                slug = $slug
                status = 'MISSING_BIN'
                exit_code = -1
                matched_one = $false
                guard_tripped = $false
                elapsed_seconds = 0
                error = "Missing prebuilt test binary: $exe"
            })
            Write-Warning "Missing prebuilt test binary: $exe"
            continue
        }
        $p = Start-Process $exe -ArgumentList @($filter, '--show-output', '--test-threads=1') `
            -WorkingDirectory $workDir -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }

    $m = Wait-WithHeadroom -Process $p -MetricsPath $metricsFile -NoThrow
    $exitCode = if ($p.HasExited) { $p.ExitCode } else { 137 }
    if ($m.guard_tripped -and $exitCode -eq 0) { $exitCode = 137 }
    $p.Dispose()

    $totalSamples += $m.samples
    if ($null -ne $m.min_available_ram_mib -and ($null -eq $minRam -or $m.min_available_ram_mib -lt $minRam)) { $minRam = $m.min_available_ram_mib }
    if ($null -ne $m.max_committed_mib -and ($null -eq $maxCommitted -or $m.max_committed_mib -gt $maxCommitted)) { $maxCommitted = $m.max_committed_mib }
    if ($null -ne $m.commit_limit_mib -and ($null -eq $commitLimit -or $m.commit_limit_mib -gt $commitLimit)) { $commitLimit = $m.commit_limit_mib }
    if ($null -ne $m.min_commit_headroom_mib -and ($null -eq $minHeadroom -or $m.min_commit_headroom_mib -lt $minHeadroom)) { $minHeadroom = $m.min_commit_headroom_mib }
    if ($m.guard_tripped) { $anyGuard = $true }

    $outText = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue } else { '' }
    if ($null -eq $outText) { $outText = '' }
    $cleanOut = [regex]::Replace($outText, "`e\[[0-9;]*[A-Za-z]", '')
    $matchedOne = $cleanOut -match '(?m)^test result: ok\. 1 passed;'
    $ok = (-not $m.guard_tripped) -and ($exitCode -eq 0) -and $matchedOne
    $status = if ($m.guard_tripped) { 'MEM_GUARD' } elseif ($ok) { 'ok' } elseif ($exitCode -eq 0 -and -not $matchedOne) { 'NO_MATCH' } else { 'FAILED' }
    $errMsg = ''
    if (-not $ok) {
        $anyFail = $true
        if ($status -eq 'NO_MATCH') { $errMsg = "$crate $filter exited 0 but did not report 'test result: ok. 1 passed;'" }
        elseif ($status -eq 'MEM_GUARD') { $errMsg = 'Stopped at runner memory guard' }
        else { $errMsg = "exit $exitCode" }
    }

    if (Test-Path -LiteralPath $stdout) {
        Select-String -Path $stdout -Pattern '^test result:|^test .* \.\.\. (ok|FAILED)$' | ForEach-Object Line
    }

    $results.Add([ordered]@{
        crate = $crate
        filter = $filter
        slug = $slug
        status = $status
        exit_code = $exitCode
        matched_one = $matchedOne
        guard_tripped = [bool]$m.guard_tripped
        elapsed_seconds = $m.elapsed_seconds
        error = $errMsg
        metrics = $m
    })
}

$totalWatch.Stop()
$summary = [ordered]@{
    kind = 'regressions'
    overall_ok = (-not $anyFail)
    elapsed_seconds = [math]::Round($totalWatch.Elapsed.TotalSeconds, 2)
    passed = @($results | Where-Object { $_.status -eq 'ok' }).Count
    failed = @($results | Where-Object { $_.status -ne 'ok' }).Count
    total = $results.Count
    metrics = [ordered]@{
        samples = $totalSamples
        min_available_ram_mib = $minRam
        max_committed_mib = $maxCommitted
        commit_limit_mib = $commitLimit
        min_commit_headroom_mib = $minHeadroom
        guard_tripped = $anyGuard
        elapsed_seconds = [math]::Round($totalWatch.Elapsed.TotalSeconds, 2)
    }
    cases = @($results)
}
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outPath 'regressions.json') -Encoding utf8

Write-Host "Regressions complete: $($summary.passed)/$($summary.total) passed in $($summary.elapsed_seconds) s"
if ($anyFail) { exit 1 }
exit 0
