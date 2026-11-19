<#
Installs blaze on Windows x86-64 (MSVC), so that `blaze build`, `blaze test` and `blaze run`
work, on a machine with or without Rust:

  irm https://ix.dev/blaze/install.ps1 | iex
  $env:BLAZE_CHANNEL = 'canary'; irm https://ix.dev/blaze/install.ps1 | iex
  $env:BLAZE_VERSION = '0.20261119.0'; irm https://ix.dev/blaze/install.ps1 | iex

Or when run as a local script file:

  .\install.ps1
  .\install.ps1 -Channel canary
  .\install.ps1 -Version 0.20261119.0
  .\install.ps1 --channel canary --verbose

It downloads the x86_64-pc-windows-msvc release archive from https://blaze-releases.ix.dev
(docs/release.md, "Where the bytes are"), verifies its SHA-256 against SHA256SUMS, installs
`blaze.exe`, `blaze-engine.exe` and `explore-core.wasm` into ${CARGO_HOME:-$HOME\.cargo}\bin,
adds that directory to your user PATH (unless -NoModifyPath), and runs `blaze toolchain` to fetch
the pinned Rust toolchain once. Nothing is asked interactively. Running it again installs the
newest release of the channel over the previous one.

  -Channel, --channel C        stable (default) or canary; or BLAZE_CHANNEL=C
  -Version, --version V        install release V (or BLAZE_VERSION=V), whatever the channel
  -NoToolchain, --no-toolchain download Rust at the first build instead (BLAZE_NO_TOOLCHAIN=1)
  -NoModifyPath, --no-modify-path  do not edit the user PATH registry entry (BLAZE_NO_MODIFY_PATH=1)
  -VerboseInstall, --verbose   say each step
  -Yes, --yes, -y              accepted; nothing is asked anyway
  -Help, --help, -h            show this help

BLAZE_RELEASES=https://... installs from another mirror laid out as blaze's
(<it>/v<version>/<asset>, <it>/channels/<channel>). BLAZE_ARCHIVE=<file> installs that local
archive (.tar.xz, .tar.gz or .zip laid out as a release's) instead of downloading one.
#>

$ErrorActionPreference = 'Stop'
$script:IsScriptFile = -not [string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)

function Invoke-BlazeInstaller {
    $SCRIPT_ARGS = @($args)

    $REPO = 'indexable-inc/blaze'
    $RELEASES = if ($env:BLAZE_RELEASES) { $env:BLAZE_RELEASES.TrimEnd('/') } else { 'https://blaze-releases.ix.dev' }
    # harness/toolchain; harness/toolchain_bump.py writes it
    $TOOLCHAIN = 'nightly-2026-10-27'
    $VERSION = if ($env:BLAZE_VERSION) { $env:BLAZE_VERSION.Trim() } else { '' }
    $CHANNEL = if ($env:BLAZE_CHANNEL) { $env:BLAZE_CHANNEL.Trim() } else { '' }
    $NO_TOOLCHAIN = -not [string]::IsNullOrEmpty($env:BLAZE_NO_TOOLCHAIN) -and $env:BLAZE_NO_TOOLCHAIN -ne '0'
    $NO_MODIFY_PATH = -not [string]::IsNullOrEmpty($env:BLAZE_NO_MODIFY_PATH) -and $env:BLAZE_NO_MODIFY_PATH -ne '0'
    $ARCHIVE = if ($env:BLAZE_ARCHIVE) { $env:BLAZE_ARCHIVE.Trim() } else { '' }
    $VERBOSE_LOG = $false

    function Write-Say([string] $Message) {
        Write-Output $Message
    }

    function Write-Step([string] $Message) {
        if ($VERBOSE_LOG) {
            Write-Output "  $Message"
        }
    }

    function Stop-Fail([string] $Message, [string] $Detail = '') {
        [Console]::Error.WriteLine("error: $Message")
        if ($Detail) {
            foreach ($line in ($Detail -split "`r?`n")) {
                [Console]::Error.WriteLine("  $line")
            }
        }
        if ($script:IsScriptFile) { exit 1 }
        throw $Message
    }

    function Show-Usage {
        $help = @"
Installs blaze on Windows x86-64 (MSVC).

  irm https://ix.dev/blaze/install.ps1 | iex
  .\install.ps1 [-Channel stable|canary] [-Version V] [-NoToolchain] [-NoModifyPath] [-VerboseInstall]

Options:
  -Channel, --channel C           stable (default) or canary (env: BLAZE_CHANNEL)
  -Version, --version V           install release V (env: BLAZE_VERSION)
  -NoToolchain, --no-toolchain    skip downloading Rust now (env: BLAZE_NO_TOOLCHAIN=1)
  -NoModifyPath, --no-modify-path do not update user PATH (env: BLAZE_NO_MODIFY_PATH=1)
  -VerboseInstall, --verbose, -v  print each step
  -Yes, --yes, -y                 accepted; nothing is asked interactively
  -Help, --help, -h               print this help

Environment:
  BLAZE_RELEASES=https://...      alternate release mirror (HTTPS only)
  BLAZE_ARCHIVE=<path>            install from a local .tar.xz, .tar.gz or .zip archive
  CARGO_HOME=<path>               install into <CARGO_HOME>\bin (default: %USERPROFILE%\.cargo\bin)
  BLAZE_HOME=<path>               blaze home directory (default: %USERPROFILE%\.blaze)
"@
        Write-Say $help
    }

    # Parse command-line arguments.
    $i = 0
    while ($i -lt $SCRIPT_ARGS.Count) {
        $arg = [string]$SCRIPT_ARGS[$i]
        switch -Regex ($arg) {
            '^(?i:-Version|--version)$' {
                if ($i + 1 -ge $SCRIPT_ARGS.Count) {
                    Stop-Fail '--version needs a version, such as --version 0.20261119.0'
                }
                $VERSION = [string]$SCRIPT_ARGS[$i + 1]
                $i += 2
            }
            '^(?i:--version=|-Version:)(.+)$' {
                $VERSION = $Matches[1]
                $i++
            }
            '^(?i:-Channel|--channel)$' {
                if ($i + 1 -ge $SCRIPT_ARGS.Count) {
                    Stop-Fail '--channel needs a channel: stable or canary'
                }
                $CHANNEL = [string]$SCRIPT_ARGS[$i + 1]
                $i += 2
            }
            '^(?i:--channel=|-Channel:)(.+)$' {
                $CHANNEL = $Matches[1]
                $i++
            }
            '^(?i:-NoToolchain|--no-toolchain)$' {
                $NO_TOOLCHAIN = $true
                $i++
            }
            '^(?i:-NoModifyPath|--no-modify-path)$' {
                $NO_MODIFY_PATH = $true
                $i++
            }
            '^(?i:-VerboseInstall|--verbose|-v)$' {
                $VERBOSE_LOG = $true
                $i++
            }
            '^(?i:-Yes|--yes|-y)$' {
                $i++
            }
            '^(?i:-Help|--help|-h|/\?)$' {
                Show-Usage
                return
            }
            default {
                Stop-Fail "this installer has no option $arg" 'It takes --channel C, --version V, --no-toolchain, --no-modify-path, --verbose and --yes.'
            }
        }
    }

if (-not $RELEASES.StartsWith('https://')) {
    Stop-Fail "BLAZE_RELEASES is $RELEASES, which is not an https:// address." 'A release and its checksums come from there together, so they are fetched over HTTPS only.'
}

# A workspace pins blaze with a version or a channel's name, and so does --version.
if ($VERSION -in @('stable', 'canary')) {
    $CHANNEL = $VERSION
    $VERSION = ''
}
if ([string]::IsNullOrEmpty($CHANNEL)) { $CHANNEL = 'stable' }
if ($CHANNEL -notin @('stable', 'canary')) {
    Stop-Fail "blaze has no channel $CHANNEL." 'The channels are stable (the default) and canary.'
}

# ---------------------------------------------------------------------------------------------
# Which build this machine takes

$isWin = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.Platform -eq 'Win32NT') -or (-not $PSVersionTable.ContainsKey('Platform'))
if (-not $isWin) {
    Stop-Fail 'this installer is for Windows.' 'On macOS and Linux, run: curl -fsSL https://ix.dev/blaze | sh'
}

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if (-not [Environment]::Is64BitOperatingSystem -or $arch -notin @('AMD64', 'x86_64')) {
    Stop-Fail "blaze has no Windows build for $arch yet." 'Windows builds target x86-64 (x86_64-pc-windows-msvc).'
}
$target = 'x86_64-pc-windows-msvc'
$machine = 'Windows on x86-64'

# Ensure TLS 1.2+ on Windows PowerShell 5.1.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

function Invoke-Fetch([string] $Url, [string] $OutFile) {
    $lastErr = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $params = @{
                Uri = $Url
                OutFile = $OutFile
                UseBasicParsing = $true
                ErrorAction = 'Stop'
            }
            Invoke-WebRequest @params | Out-Null
            return
        } catch {
            $lastErr = $_
            if ($attempt -lt 3) { Start-Sleep -Seconds $attempt }
        }
    }
    throw $lastErr
}

function Find-Sha256Entry([string] $SumsPath, [string] $AssetName) {
    foreach ($line in (Get-Content -LiteralPath $SumsPath -Encoding utf8)) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            if ($Matches[2] -eq $AssetName) {
                return $Matches[1].ToLowerInvariant()
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------------------------
# Downloading & unpacking

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("blaze-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $tag = ''
    $shown = 'blaze'
    $asset = ''
    $archivePath = ''

    if ($ARCHIVE) {
        if (-not (Test-Path -LiteralPath $ARCHIVE -PathType Leaf)) {
            Stop-Fail "there is no file $ARCHIVE to install blaze from." "BLAZE_ARCHIVE names a release's archive, such as blaze-v0.20261119.0-$target.tar.xz."
        }
        $asset = Split-Path -Leaf $ARCHIVE
        $archivePath = Join-Path $tmp $asset
        Write-Say "Installing blaze from $asset for $machine..."
        Copy-Item -LiteralPath $ARCHIVE -Destination $archivePath
    } else {
        if ($VERSION) {
            $vTrim = if ($VERSION.StartsWith('v')) { $VERSION.Substring(1) } else { $VERSION }
            $tag = "v$vTrim"
        } else {
            $channelFile = Join-Path $tmp 'channel'
            try {
                Invoke-Fetch "$RELEASES/channels/$CHANNEL" $channelFile
            } catch {
                Stop-Fail "which release is blaze's $CHANNEL could not be read; is the network up?" "$($_.Exception.Message)`n$RELEASES/channels/$CHANNEL"
            }
            $named = (Get-Content -LiteralPath $channelFile -Raw).Trim()
            if ($named -notmatch '^\d+\.\d+\.\d+$') {
                Stop-Fail "blaze's $CHANNEL channel names $named, which is not a version." "$RELEASES/channels/$CHANNEL"
            }
            $tag = "v$named"
        }
        Write-Step "release $tag from $RELEASES ($CHANNEL)"

        $sumsFile = Join-Path $tmp 'SHA256SUMS'
        try {
            Invoke-Fetch "$RELEASES/$tag/SHA256SUMS" $sumsFile
        } catch {
            if ($VERSION) {
                Stop-Fail "there is no blaze release $VERSION." "Releases: https://github.com/$REPO/releases"
            }
            Stop-Fail "the list of blaze's releases could not be read; is the network up?" "$($_.Exception.Message)`n$RELEASES/$tag/SHA256SUMS"
        }

        $tarCmd = Get-Command 'tar.exe' -ErrorAction SilentlyContinue
        if (-not $tarCmd) { $tarCmd = Get-Command 'tar' -ErrorAction SilentlyContinue }

        $xzName = "blaze-$tag-$target.tar.xz"
        $gzName = "blaze-$tag-$target.tar.gz"
        $zipName = "blaze-$tag-$target.zip"

        $want = $null
        if ($tarCmd) {
            $xzSum = Find-Sha256Entry $sumsFile $xzName
            if ($xzSum) {
                $asset = $xzName
                $want = $xzSum
            } else {
                $gzSum = Find-Sha256Entry $sumsFile $gzName
                if ($gzSum) {
                    $asset = $gzName
                    $want = $gzSum
                }
            }
        }
        if (-not $want) {
            $zipSum = Find-Sha256Entry $sumsFile $zipName
            if ($zipSum) {
                $asset = $zipName
                $want = $zipSum
            }
        }
        if (-not $want) {
            Stop-Fail "blaze release $tag has no build for $machine." "Its files: https://github.com/$REPO/releases/tag/$tag"
        }

        $shown = "blaze $($tag.Substring(1))"
        if (-not $VERSION -and $CHANNEL -eq 'canary') { $shown = "$shown (canary)" }
        Write-Say "Installing $shown for $machine..."
        Write-Step "downloading $asset"
        $archivePath = Join-Path $tmp $asset
        try {
            Invoke-Fetch "$RELEASES/$tag/$asset" $archivePath
        } catch {
            Stop-Fail 'the download of blaze stopped before it finished; running this again retries it.' "$($_.Exception.Message)`n$RELEASES/$tag/$asset"
        }

        $got = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) {
            Stop-Fail 'the download is not the file the release published, so it was not installed. Running this again downloads it again.' "$asset`: sha256 $got, the release's SHA256SUMS says $want"
        }
    }

    $unpackedRoot = Join-Path $tmp 'unpacked'
    New-Item -ItemType Directory -Force -Path $unpackedRoot | Out-Null

    if ($asset -match '\.zip$') {
        try {
            Expand-Archive -LiteralPath $archivePath -DestinationPath $unpackedRoot -Force
        } catch {
            Stop-Fail 'the downloaded archive could not be unpacked.' $_.Exception.Message
        }
    } else {
        $tarExe = (Get-Command 'tar.exe' -ErrorAction SilentlyContinue)
        if (-not $tarExe) { $tarExe = (Get-Command 'tar' -ErrorAction SilentlyContinue) }
        if (-not $tarExe) {
            Stop-Fail 'unpacking the release archive needs Windows tar.exe, which is not on PATH.' 'Windows 10 build 17063+ and Windows 11 ship tar.exe in System32.'
        }
        $tarErr = Join-Path $tmp 'tar.stderr.log'
        & $tarExe.Source -xf $archivePath -C $unpackedRoot 2> $tarErr
        $tarCode = $LASTEXITCODE
        if ($tarCode -ne 0) {
            $errText = if (Test-Path -LiteralPath $tarErr) { Get-Content -LiteralPath $tarErr -Raw } else { "tar exited $tarCode" }
            Stop-Fail 'the downloaded archive could not be unpacked.' $errText
        }
    }

    $dirs = @(Get-ChildItem -LiteralPath $unpackedRoot -Directory)
    if ($dirs.Count -ne 1) {
        Stop-Fail "$asset is not a blaze release's archive: it does not hold one folder of programs." "Download blaze-<version>-$target.tar.xz from https://github.com/$REPO/releases and name it in BLAZE_ARCHIVE."
    }
    $unpacked = $dirs[0].FullName
    if (-not (Test-Path -LiteralPath (Join-Path $unpacked 'blaze.exe') -PathType Leaf)) {
        Stop-Fail "$asset is not a blaze release's archive: it has no blaze.exe in $($dirs[0].Name)." "Download blaze-<version>-$target.tar.xz from https://github.com/$REPO/releases and name it in BLAZE_ARCHIVE."
    }

    # ---------------------------------------------------------------------------------------------
    # Installing

    $userHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome '.cargo' }
    $bin = Join-Path $cargoHome 'bin'
    try {
        New-Item -ItemType Directory -Force -Path $bin | Out-Null
    } catch {
        Stop-Fail "blaze's folder could not be made." $_.Exception.Message
    }

    # Clean up any prior in-use renamed binaries left by an earlier upgrade.
    Get-ChildItem -LiteralPath $bin -Filter '.*.blaze-old' -File -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }

    # Place each file by staging beside its destination and swapping into place. On Windows a
    # running executable cannot be overwritten in place, but it can be renamed aside in the same
    # directory so a running daemon continues undisturbed and the next command runs the new binary.
    function Install-StagedFile([string] $Src, [string] $Name) {
        $dest = Join-Path $bin $Name
        $staged = Join-Path $bin ".$Name.blaze-new"
        $aside = Join-Path $bin ".$Name.blaze-old"
        Copy-Item -LiteralPath $Src -Destination $staged -Force
        if (Test-Path -LiteralPath $dest) {
            try {
                Move-Item -LiteralPath $staged -Destination $dest -Force -ErrorAction Stop
                return
            } catch {
                Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $dest -Destination $aside -Force
                Move-Item -LiteralPath $staged -Destination $dest -Force
                Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
                return
            }
        }
        Move-Item -LiteralPath $staged -Destination $dest -Force
    }

    foreach ($exe in (Get-ChildItem -LiteralPath $unpacked -Filter '*.exe' -File)) {
        Write-Step "installing $($exe.Name)"
        Install-StagedFile $exe.FullName $exe.Name
    }
    $exploreWasm = Join-Path $unpacked 'explore-core.wasm'
    if (Test-Path -LiteralPath $exploreWasm -PathType Leaf) {
        Write-Step 'installing explore-core.wasm'
        Install-StagedFile $exploreWasm 'explore-core.wasm'
    }

    # blaze's updates (docs/install.md, "Updates"): the blaze installed last runs, so a default an
    # earlier `blaze update` installed goes; and a canary install has `blaze update` follow canary,
    # unless its settings already name a channel.
    $blazeHome = if ($env:BLAZE_HOME) { $env:BLAZE_HOME } else { Join-Path $userHome '.blaze' }
    $defaultFile = Join-Path $blazeHome 'default'
    if (Test-Path -LiteralPath $defaultFile) {
        Remove-Item -LiteralPath $defaultFile -Force -ErrorAction SilentlyContinue
    }

    function Test-ConfigNamesChannel([string] $ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $false }
        $here = $false
        $top = $true
        foreach ($line in (Get-Content -LiteralPath $ConfigPath -Encoding utf8)) {
            if ($line -match '^\s*\[') {
                $here = ($line -match '^\s*\[\s*update\s*\]\s*(#.*)?$')
                $top = $false
                continue
            }
            if ($here -and $line -match '^\s*channel\s*=') { return $true }
            if ($top -and $line -match '^\s*update\s*\.\s*channel\s*=') { return $true }
        }
        return $false
    }

    $configPath = Join-Path $blazeHome 'config.toml'
    if ($CHANNEL -eq 'canary' -and -not $VERSION -and -not (Test-ConfigNamesChannel $configPath)) {
        New-Item -ItemType Directory -Force -Path $blazeHome | Out-Null
        if (Test-Path -LiteralPath $configPath -PathType Leaf) {
            $lines = @(Get-Content -LiteralPath $configPath -Encoding utf8)
            $hasHeader = $false
            foreach ($l in $lines) {
                if ($l -match '^\s*\[\s*update\s*\]\s*(#.*)?$') { $hasHeader = $true; break }
            }
            if ($hasHeader) {
                $outLines = [System.Collections.Generic.List[string]]::new()
                $inserted = $false
                foreach ($l in $lines) {
                    $outLines.Add($l)
                    if (-not $inserted -and $l -match '^\s*\[\s*update\s*\]\s*(#.*)?$') {
                        $outLines.Add('channel = "canary"')
                        $inserted = $true
                    }
                }
                $newCfg = Join-Path $blazeHome '.config.toml.new'
                $outLines | Set-Content -LiteralPath $newCfg -Encoding utf8
                Move-Item -LiteralPath $newCfg -Destination $configPath -Force
            } else {
                Add-Content -LiteralPath $configPath -Value "`n[update]`nchannel = `"canary`"" -Encoding utf8
            }
        } else {
            "[update]`nchannel = `"canary`"" | Set-Content -LiteralPath $configPath -Encoding utf8
        }
        Write-Step "``blaze update`` follows canary: [update] channel in $configPath"
    }

    # ---------------------------------------------------------------------------------------------
    # The Rust blaze builds with

    $blazeExe = Join-Path $bin 'blaze.exe'
    if ($NO_TOOLCHAIN) {
        Write-Step "Rust $TOOLCHAIN is downloaded at the first build"
    } else {
        $tcOut = Join-Path $tmp 'toolchain.out'
        $tcErr = Join-Path $tmp 'toolchain.err'
        $tp = Start-Process -FilePath $blazeExe -ArgumentList 'toolchain' -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $tcOut -RedirectStandardError $tcErr
        $tcCode = $tp.ExitCode
        $tp.Dispose()
        if ($tcCode -eq 0) {
            $tcSaid = if (Test-Path -LiteralPath $tcOut) { (Get-Content -LiteralPath $tcOut -Raw).Trim() } else { '' }
            if ($tcSaid) { Write-Step $tcSaid }
        } else {
            $tcDetail = if (Test-Path -LiteralPath $tcErr) { (Get-Content -LiteralPath $tcErr -Raw).Trim() } else { '' }
            Stop-Fail 'blaze is installed, but the Rust it builds with could not be downloaded; the first build tries again.' $tcDetail
        }
    }

    # ---------------------------------------------------------------------------------------------
    # Check for MSVC C++ Build Tools & Windows SDK

    function Test-MsvcInstalled {
        if ($env:VCToolsInstallDir -and (Test-Path -LiteralPath $env:VCToolsInstallDir)) { return $true }
        if (Get-Command 'cl.exe' -ErrorAction SilentlyContinue) { return $true }
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if ($vswhere -and (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
            $found = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($found | Out-String))) {
                return $true
            }
        }
        return $false
    }

    $linkerNote = ''
    if (-not (Test-MsvcInstalled)) {
        $linkerNote = @"
blaze links Windows programs with the MSVC C runtime and Windows SDK libraries, which were not found.
Install Visual Studio Build Tools with the "Desktop development with C++" workload:

    winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
"@
    }

    # ---------------------------------------------------------------------------------------------
    # User PATH

    function Normalize-Dir([string] $PathValue) {
        return $PathValue.Trim().TrimEnd('\', '/').ToLowerInvariant()
    }

    $normBin = Normalize-Dir $bin
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $allPersisted = @()
    if ($userPath) { $allPersisted += ($userPath -split ';' | Where-Object { $_.Trim() -ne '' }) }
    if ($machinePath) { $allPersisted += ($machinePath -split ';' | Where-Object { $_.Trim() -ne '' }) }
    $inPersisted = ($allPersisted | ForEach-Object { Normalize-Dir $_ }) -contains $normBin

    $pathNote = ''
    if (-not $inPersisted) {
        if (-not $NO_MODIFY_PATH) {
            $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $bin } else { "$bin;$userPath" }
            [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
            Write-Step "added $bin to your user PATH"
            $pathNote = "Added $bin to your user PATH. Open a new terminal (or run in this shell) if ``blaze`` is not found."
        } else {
            $pathNote = @"
Your shell finds blaze once your PATH has $bin, which it does not yet. Add it in PowerShell with:

    `$env:PATH = "$bin;`$env:PATH"
"@
        }
    }

    $inSession = (($env:PATH -split ';' | Where-Object { $_.Trim() -ne '' }) | ForEach-Object { Normalize-Dir $_ }) -contains $normBin
    if (-not $inSession -and -not $NO_MODIFY_PATH) {
        $env:PATH = "$bin;$env:PATH"
    }

    Write-Say ''
    if ($tag) {
        Write-Say "$shown is installed."
    } else {
        Write-Say 'blaze is installed.'
    }
    if ($linkerNote) { Write-Say ''; Write-Say $linkerNote }
    if ($pathNote) { Write-Say ''; Write-Say $pathNote }
    Write-Say ''
    Write-Say 'In a Rust project, run:'
    Write-Say ''
    Write-Say '    blaze run'
} finally {
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
}

Invoke-BlazeInstaller @args
