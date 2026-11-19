# Remove workspace member artifacts, executables and incremental state from target/<Profile>
# before saving the external+vendored dependency cache. Handles both Cargo 1.101's
# fine-grained-build-dir layout (target/<profile>/build/<pkg>/<hash>/) and legacy deps/.fingerprint.
param(
    [Parameter(Mandatory)]
    [ValidateSet('debug', 'release')]
    [string] $Profile
)
$ErrorActionPreference = 'Stop'

$profileDir = Join-Path 'target' $Profile
if (-not (Test-Path -LiteralPath $profileDir)) {
    Write-Host "Nothing to prune under $profileDir"
    exit 0
}

function Get-DirMiB([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [math]::Round($sum / 1MB, 1)
}

$beforeMiB = Get-DirMiB $profileDir

$metaJson = cargo metadata --no-deps --format-version 1
if ($LASTEXITCODE) { throw "cargo metadata failed ($LASTEXITCODE)" }
$meta = $metaJson | ConvertFrom-Json

$wsPkgs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$wsIdents = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($pkg in $meta.packages) {
    # Keep vendored workspace members (rustc_next_trait_solver, rustc_type_ir*, rustc_parse_format)
    # in the dependency cache; vendor/** is already part of the cache key.
    if ($pkg.manifest_path -match '[\\/]vendor[\\/]') { continue }
    [void]$wsPkgs.Add($pkg.name)
    [void]$wsIdents.Add($pkg.name.Replace('-', '_'))
    foreach ($t in $pkg.targets) {
        [void]$wsIdents.Add($t.name.Replace('-', '_'))
    }
}

# Remove incremental caches, examples, and top-level binaries/PDBs.
foreach ($sub in @('incremental', 'examples')) {
    $p = Join-Path $profileDir $sub
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }
}
Get-ChildItem -LiteralPath $profileDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in @('.exe', '.pdb', '.d', '.dll', '.lib') } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# Cargo 1.101 fine-grained build dir: target/<profile>/build/<pkg-name>/<hash>/{fingerprint,out}.
# Legacy Cargo build-script dir: target/<profile>/build/<pkg-name>-<16hex>/.
$buildDir = Join-Path $profileDir 'build'
$removedBuild = 0
if (Test-Path -LiteralPath $buildDir) {
    foreach ($entry in (Get-ChildItem -LiteralPath $buildDir -Directory -ErrorAction SilentlyContinue)) {
        $name = $entry.Name
        $isWs = $wsPkgs.Contains($name)
        if (-not $isWs -and $name -match '^(.+)-[0-9a-f]{16}$') {
            $isWs = $wsPkgs.Contains($Matches[1])
        }
        if ($isWs) {
            Remove-Item -LiteralPath $entry.FullName -Recurse -Force -ErrorAction SilentlyContinue
            $removedBuild++
        }
    }
}

# Legacy deps/ directory: remove workspace artifacts and all .exe/.pdb test binaries,
# keeping third-party proc-macro .dlls and .rlib/.rmeta files.
$depsDir = Join-Path $profileDir 'deps'
$removedDeps = 0
if (Test-Path -LiteralPath $depsDir) {
    foreach ($file in (Get-ChildItem -LiteralPath $depsDir -File -ErrorAction SilentlyContinue)) {
        $remove = $file.Extension -in @('.exe', '.pdb')
        if (-not $remove -and $file.Name -match '^(?:lib)?(.+?)-[0-9a-f]{16}(?:\.|$)') {
            $remove = $wsIdents.Contains($Matches[1])
        }
        if ($remove) {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            $removedDeps++
        }
    }
}

# Legacy .fingerprint/ directory: remove workspace member entries.
$fpDir = Join-Path $profileDir '.fingerprint'
$removedFp = 0
if (Test-Path -LiteralPath $fpDir) {
    foreach ($entry in (Get-ChildItem -LiteralPath $fpDir -Directory -ErrorAction SilentlyContinue)) {
        if ($entry.Name -match '^(.+)-[0-9a-f]{16}$' -and $wsPkgs.Contains($Matches[1])) {
            Remove-Item -LiteralPath $entry.FullName -Recurse -Force -ErrorAction SilentlyContinue
            $removedFp++
        }
    }
}

$afterMiB = Get-DirMiB $profileDir
Write-Host "Pruned $profileDir`: $beforeMiB MiB -> $afterMiB MiB (removed build=$removedBuild, deps=$removedDeps, fingerprint=$removedFp; ws pkgs=$($wsPkgs.Count))"
