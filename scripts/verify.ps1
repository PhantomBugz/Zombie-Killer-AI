[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [switch]$SkipDependencyInstall,
    [switch]$SkipDocs,
    [switch]$SkipWeb,
    [switch]$SkipPython,
    [switch]$SkipRust,
    [switch]$SkipNativeBuild,
    [switch]$SkipReleaseFixture,
    [switch]$SkipNativeSmoke,
    [switch]$SkipPortableExe,
    [switch]$SkipSecretScan,
    [switch]$SkipSbom
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExitCode = 1
$script:InitialHead = ''
$script:InitialStatus = ''
$script:InitialStateDigest = ''
$script:SnapshotPython = ''
$script:NativeBuildRan = $false
$script:NativeArchive = ''
$script:PortableExecutable = ''
$script:PortableExecutableSha256 = ''
$script:PortablePayloadSha256 = ''
$script:TempRoot = $null
$RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$MainCargoManifest = Join-Path $RepositoryRoot 'apps/desktop/src-tauri/Cargo.toml'
$UnixHarnessManifest = Join-Path $RepositoryRoot 'apps/desktop/src-tauri/build_support/unix-test-harness/Cargo.toml'
$PortableCargoManifest = Join-Path $RepositoryRoot 'tools/portable-launcher/Cargo.toml'
$SidecarManifest = Join-Path $RepositoryRoot 'apps/desktop/src-tauri/resources/engine/BUILD-MANIFEST.json'
$ReleaseFixture = Join-Path $RepositoryRoot 'scripts/release-fixture.py'
$NativeSmoke = Join-Path $RepositoryRoot 'scripts/native-smoke.ps1'
$NativePackager = Join-Path $RepositoryRoot 'scripts/package-native-artifact.py'
$PortableBuilder = Join-Path $RepositoryRoot 'scripts/build-portable-exe.py'
$PortableSmoke = Join-Path $RepositoryRoot 'scripts/portable-smoke.ps1'

function Invoke-External {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $script:ExitCode = $exitCode
        throw "External command '$FilePath' failed with exit code $exitCode."
    }
}

function Invoke-ExternalCapture {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    $output = & $FilePath @ArgumentList
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $script:ExitCode = $exitCode
        throw "External command '$FilePath' failed with exit code $exitCode."
    }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Assert-ExactOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$Actual,
        [Parameter(Mandatory)]
        [string]$Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Label must be '$Expected'; found '$Actual'."
    }
}

function Resolve-SnapshotPython {
    $candidates = if ($IsWindows) { @('python') } else { @('python3', 'python') }
    foreach ($candidate in $candidates) {
        $command = Get-Command -Name $candidate -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $command) {
            continue
        }

        $output = & $command.Source '--version' 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            continue
        }
        $version = (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
        if ($version -match '^Python 3\.(11|12|13)\.\d+$') {
            return [string]$command.Source
        }
    }

    throw 'Python 3.11, 3.12, or 3.13 (python3 on Unix or python on Windows) is required for repository snapshot verification.'
}

function Get-RepositoryStatus {
    return Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'status', '--porcelain=v1', '--untracked-files=all'
    )
}

function Get-RepositoryStateDigest {
    if ([string]::IsNullOrWhiteSpace($script:SnapshotPython)) {
        throw 'Repository snapshot Python was not resolved during preflight.'
    }
    $snapshotJson = Invoke-ExternalCapture -FilePath $script:SnapshotPython -ArgumentList @(
        '-I', 'scripts/repository_state.py', '--repository-root', $RepositoryRoot
    )
    $snapshot = $snapshotJson | ConvertFrom-Json
    if ($snapshot.digest -notmatch '^[a-f0-9]{64}$') {
        throw 'Repository-state helper returned an invalid digest.'
    }
    return [string]$snapshot.digest
}

function New-VerificationTempRoot {
    $name = 'zombie-killer-verify-' + [guid]::NewGuid().ToString('D')
    $path = Join-Path ([System.IO.Path]::GetTempPath()) $name
    $created = New-Item -ItemType Directory -Path $path
    return [System.IO.Path]::GetFullPath($created.FullName)
}

function Remove-OwnedTempRoot {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $candidate = [System.IO.Path]::GetFullPath($Path)
    $temporaryParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $candidateParent = [System.IO.Path]::GetDirectoryName($candidate).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $candidateName = [System.IO.Path]::GetFileName($candidate)
    if (
        -not [string]::Equals(
            $candidateParent,
            $temporaryParent,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        $candidateName -notmatch '^zombie-killer-verify-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ) {
        throw 'Refusing to remove a temporary path not owned by this verification run.'
    }
    if (Test-Path -LiteralPath $candidate) {
        Remove-Item -LiteralPath $candidate -Recurse -Force
    }
}

function Add-Step {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Steps,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [bool]$Enabled,
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $Steps.Add([pscustomobject]@{
            Name = $Name
            Enabled = $Enabled
            Action = $Action
        })
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)]
        [int]$Index,
        [Parameter(Mandatory)]
        [int]$Total,
        [Parameter(Mandatory)]
        [object]$Step
    )

    $prefix = '[{0:D2}/{1:D2}]' -f $Index, $Total
    if (-not $Step.Enabled) {
        Write-Warning "$prefix SKIP $($Step.Name) (0.000s) -- NON-RELEASE"
        return
    }

    Write-Host "$prefix START $($Step.Name)"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Step.Action
        $stopwatch.Stop()
        Write-Host ("$prefix PASS  {0} ({1:N3}s)" -f $Step.Name, $stopwatch.Elapsed.TotalSeconds)
    }
    catch {
        $stopwatch.Stop()
        [Console]::Error.WriteLine(
            ("$prefix FAIL  {0} ({1:N3}s)" -f $Step.Name, $stopwatch.Elapsed.TotalSeconds)
        )
        throw
    }
}

$nonReleaseReasons = [System.Collections.Generic.List[string]]::new()
if ($AllowDirty) { $nonReleaseReasons.Add('-AllowDirty') }
if ($SkipDependencyInstall) { $nonReleaseReasons.Add('-SkipDependencyInstall') }
if ($SkipDocs) { $nonReleaseReasons.Add('-SkipDocs') }
if ($SkipWeb) { $nonReleaseReasons.Add('-SkipWeb') }
if ($SkipPython) { $nonReleaseReasons.Add('-SkipPython') }
if ($SkipRust) { $nonReleaseReasons.Add('-SkipRust') }
if ($SkipNativeBuild) { $nonReleaseReasons.Add('-SkipNativeBuild') }
if ($SkipReleaseFixture) { $nonReleaseReasons.Add('-SkipReleaseFixture') }
if ($SkipNativeSmoke) { $nonReleaseReasons.Add('-SkipNativeSmoke') }
if ($SkipPortableExe) { $nonReleaseReasons.Add('-SkipPortableExe') }
if ($SkipSecretScan) { $nonReleaseReasons.Add('-SkipSecretScan') }
if ($SkipSbom) { $nonReleaseReasons.Add('-SkipSbom') }
$isNonRelease = $nonReleaseReasons.Count -gt 0

if ($isNonRelease) {
    Write-Warning '=================================================================='
    Write-Warning 'NON-RELEASE VERIFICATION: full release approval is impossible.'
    Write-Warning ('Overrides: ' + ($nonReleaseReasons -join ', '))
    Write-Warning 'A successful scoped run exits 2, never 0.'
    Write-Warning '=================================================================='
}

$steps = [System.Collections.Generic.List[object]]::new()

Add-Step -Steps $steps -Name 'Repository preflight and git status --porcelain=v1 --untracked-files=all' -Enabled $true -Action {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'PowerShell 7 or newer is required.'
    }
    if ($env:ZK_ALLOW_UNPINNED_TOOLCHAIN -eq '1') {
        throw 'ZK_ALLOW_UNPINNED_TOOLCHAIN is forbidden during release verification.'
    }
    $observedRoot = Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'rev-parse', '--show-toplevel'
    )
    if (
        -not [string]::Equals(
            [System.IO.Path]::GetFullPath($observedRoot),
            $RepositoryRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw 'verify.ps1 must run from its own repository worktree.'
    }
    if (-not $SkipReleaseFixture -and -not (Test-Path -LiteralPath $ReleaseFixture -PathType Leaf)) {
        throw 'Full verification requires scripts/release-fixture.py. Use -SkipReleaseFixture only for a NON-RELEASE scoped run.'
    }
    if (-not $SkipNativeSmoke -and -not (Test-Path -LiteralPath $NativeSmoke -PathType Leaf)) {
        throw 'Full verification requires scripts/native-smoke.ps1. Use -SkipNativeSmoke only for a NON-RELEASE scoped run.'
    }
    if (-not $SkipNativeBuild -and -not (Test-Path -LiteralPath $NativePackager -PathType Leaf)) {
        throw 'Full verification requires scripts/package-native-artifact.py.'
    }
    if ($IsWindows -and -not $SkipPortableExe) {
        if (-not (Test-Path -LiteralPath $PortableBuilder -PathType Leaf) -or
            -not (Test-Path -LiteralPath $PortableSmoke -PathType Leaf)) {
            throw 'Full Windows verification requires the portable builder and smoke scripts.'
        }
        if ($SkipNativeBuild) {
            throw '-SkipNativeBuild requires -SkipPortableExe on Windows; stale native archives are never accepted.'
        }
        if ($SkipPython) {
            throw '-SkipPython requires -SkipPortableExe on Windows; the portable builder uses locked Python.'
        }
    }
    if ($SkipNativeBuild -and $IsWindows -and -not $SkipNativeSmoke) {
        throw '-SkipNativeBuild requires -SkipNativeSmoke; stale native artifacts are never accepted.'
    }
    if ($IsWindows -and -not $SkipNativeSmoke -and $env:ZK_DISPOSABLE_WINDOWS_PROFILE -ne '1') {
        throw 'Windows native and portable smoke require ZK_DISPOSABLE_WINDOWS_PROFILE=1 in a disposable Windows profile.'
    }
    $script:SnapshotPython = Resolve-SnapshotPython
    $script:InitialHead = Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'rev-parse', 'HEAD'
    )
    $script:InitialStatus = Get-RepositoryStatus
    if (-not $AllowDirty -and $script:InitialStatus.Length -gt 0) {
        $changedCount = ($script:InitialStatus -split "`n").Count
        throw "Release verification requires a clean worktree; found $changedCount changed path(s)."
    }
    $script:InitialStateDigest = Get-RepositoryStateDigest
}

Add-Step -Steps $steps -Name 'Exact toolchain pins' -Enabled $true -Action {
    Invoke-External -FilePath 'node' -ArgumentList @('scripts/check-toolchain.mjs')
    Assert-ExactOutput -Label 'Node' -Actual (
        Invoke-ExternalCapture -FilePath 'node' -ArgumentList @('--version')
    ) -Expected 'v24.18.0'
    Assert-ExactOutput -Label 'pnpm' -Actual (
        Invoke-ExternalCapture -FilePath 'pnpm' -ArgumentList @('--version')
    ) -Expected '10.33.2'
    $uvVersion = Invoke-ExternalCapture -FilePath 'uv' -ArgumentList @('--version')
    if ($uvVersion -notmatch '^uv 0\.12\.3(?:\s|$)') {
        throw "uv 0.12.3 is required; found '$uvVersion'."
    }
    $rustVersion = Invoke-ExternalCapture -FilePath 'rustc' -ArgumentList @('--version')
    if ($rustVersion -notmatch '^rustc 1\.97\.1(?:\s|$)') {
        throw "rustc 1.97.1 is required; found '$rustVersion'."
    }
    $cargoVersion = Invoke-ExternalCapture -FilePath 'cargo' -ArgumentList @('--version')
    if ($cargoVersion -notmatch '^cargo 1\.97\.1(?:\s|$)') {
        throw "cargo 1.97.1 is required; found '$cargoVersion'."
    }
}

Add-Step -Steps $steps -Name 'uv lock --check and uv sync --frozen' -Enabled (-not $SkipDependencyInstall) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @('lock', '--check')
    Invoke-External -FilePath 'uv' -ArgumentList @('sync', '--frozen')
}
Add-Step -Steps $steps -Name 'uv run --frozen python --version' -Enabled (-not $SkipPython) -Action {
    $pythonVersion = Invoke-ExternalCapture -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'python', '--version'
    )
    if ($pythonVersion -notmatch '^Python 3\.(11|12|13)\.\d+$') {
        throw "The locked uv runtime must use Python 3.11, 3.12, or 3.13; found '$pythonVersion'."
    }
}
Add-Step -Steps $steps -Name 'pnpm install --frozen-lockfile' -Enabled (-not $SkipDependencyInstall) -Action {
    $pnpmStore = Join-Path $script:TempRoot 'pnpm-store'
    Invoke-External -FilePath 'pnpm' -ArgumentList @(
        'install', '--frozen-lockfile', '--config.confirmModulesPurge=false',
        '--store-dir', $pnpmStore
    )
}
Add-Step -Steps $steps -Name 'Documentation and public policy checks' -Enabled (-not $SkipDocs) -Action {
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'lint:docs')
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'test:docs')
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'test:workspace')
}
Add-Step -Steps $steps -Name 'Frontend lint' -Enabled (-not $SkipWeb) -Action {
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'lint')
}
Add-Step -Steps $steps -Name 'Frontend and protocol typecheck' -Enabled (-not $SkipWeb) -Action {
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'typecheck')
}
Add-Step -Steps $steps -Name 'Frontend tests' -Enabled (-not $SkipWeb) -Action {
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'test')
}
Add-Step -Steps $steps -Name 'Frontend production build' -Enabled (-not $SkipWeb) -Action {
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'build')
}
Add-Step -Steps $steps -Name 'Ruff format --check' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'ruff', 'format', '--check',
        'services/engine', 'packages/sdk-python', 'packages/protocol/tests', 'scripts'
    )
}
Add-Step -Steps $steps -Name 'Ruff check' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'ruff', 'check',
        'services/engine', 'packages/sdk-python', 'packages/protocol/tests', 'scripts'
    )
}
Add-Step -Steps $steps -Name 'mypy strict type checking' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'mypy',
        'services/engine/src', 'packages/sdk-python/src',
        'scripts/package-native-artifact.py',
        'scripts/collect-sidecar-legal.py',
        'scripts/python_package_artifacts.py',
        'scripts/repository_state.py',
        'scripts/verify_python_distributions.py',
        'scripts/tests'
    )
}
Add-Step -Steps $steps -Name 'Engine tests: services/engine/tests' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'pytest', 'services/engine/tests', 'packages/protocol/tests', '-q'
    )
}
Add-Step -Steps $steps -Name 'SDK tests: packages/sdk-python/tests' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'pytest', 'packages/sdk-python/tests', '-q'
    )
}
Add-Step -Steps $steps -Name 'Release tooling tests: scripts/tests' -Enabled (-not $SkipPython) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'pytest', 'scripts/tests', '-q'
    )
}
Add-Step -Steps $steps -Name 'Python wheel/sdist build and verify_python_distributions.py inspection' -Enabled (-not $SkipPython) -Action {
    $distRoot = Join-Path $script:TempRoot 'python-dist'
    New-Item -ItemType Directory -Path $distRoot | Out-Null
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'build', '--package', 'zombie-killer-engine', '--out-dir', $distRoot
    )
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'build', '--package', 'zombie-killer-sdk', '--out-dir', $distRoot
    )
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'python', '-I', 'scripts/verify_python_distributions.py',
        '--dist-dir', $distRoot, '--repository-root', $RepositoryRoot
    )
}
Add-Step -Steps $steps -Name 'cargo fmt --check (main and Unix harness)' -Enabled (-not $SkipRust) -Action {
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'fmt', '--manifest-path', $MainCargoManifest, '--check'
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'fmt', '--manifest-path', $UnixHarnessManifest, '--check'
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'fmt', '--manifest-path', $PortableCargoManifest, '--check'
    )
}
Add-Step -Steps $steps -Name 'cargo clippy --locked --all-targets -- -D warnings' -Enabled (-not $SkipRust) -Action {
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'clippy', '--locked', '--manifest-path', $MainCargoManifest,
        '--all-targets', '--', '-D', 'warnings'
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'clippy', '--locked', '--manifest-path', $UnixHarnessManifest,
        '--all-targets', '--', '-D', 'warnings'
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'clippy', '--locked', '--manifest-path', $PortableCargoManifest,
        '--all-targets', '--', '-D', 'warnings'
    )
}
Add-Step -Steps $steps -Name 'cargo test --locked (main and Unix harness)' -Enabled (-not $SkipRust) -Action {
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'test', '--locked', '--manifest-path', $MainCargoManifest
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'test', '--locked', '--manifest-path', $UnixHarnessManifest
    )
    Invoke-External -FilePath 'cargo' -ArgumentList @(
        'test', '--locked', '--manifest-path', $PortableCargoManifest
    )
}
Add-Step -Steps $steps -Name 'Tauri build --no-bundle with fresh sidecar' -Enabled (-not $SkipNativeBuild) -Action {
    $manifestBeforeBuild = $null
    if (Test-Path -LiteralPath $SidecarManifest -PathType Leaf) {
        $before = Get-Item -LiteralPath $SidecarManifest
        $manifestBeforeBuild = '{0}:{1}' -f $before.Length, $before.LastWriteTimeUtc.Ticks
    }
    Invoke-External -FilePath 'pnpm' -ArgumentList @(
        '--filter', '@zombie-killer/desktop', 'tauri', 'build', '--no-bundle', '--', '--locked'
    )
    if (-not (Test-Path -LiteralPath $SidecarManifest -PathType Leaf)) {
        throw 'Native build did not produce BUILD-MANIFEST.json.'
    }
    $after = Get-Item -LiteralPath $SidecarManifest
    $manifestAfterBuild = '{0}:{1}' -f $after.Length, $after.LastWriteTimeUtc.Ticks
    if ($null -ne $manifestBeforeBuild -and $manifestAfterBuild -eq $manifestBeforeBuild) {
        throw 'Native build did not freshly replace BUILD-MANIFEST.json; refusing stale output.'
    }
    $script:NativeBuildRan = $true
}
Add-Step -Steps $steps -Name 'Package and verify fresh unsigned native archive' -Enabled (-not $SkipNativeBuild -and -not $SkipPython) -Action {
    if (-not $script:NativeBuildRan) {
        throw 'Native archive packaging requires a successful build from this verification run.'
    }
    $nativeOutput = Join-Path $script:TempRoot 'native-artifact'
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'python', '-I', 'scripts/package-native-artifact.py',
        '--output-dir', $nativeOutput
    )
    if ($IsWindows) {
        $archives = @(Get-ChildItem -LiteralPath $nativeOutput -Filter '*.zip' -File)
        if ($archives.Count -ne 1) {
            throw 'Expected exactly one fresh Windows native ZIP from this verification run.'
        }
        $script:NativeArchive = $archives[0].FullName
    }
}
Add-Step -Steps $steps -Name 'Real fixture: scripts/release-fixture.py' -Enabled (-not $SkipReleaseFixture) -Action {
    Invoke-External -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'python', 'scripts/release-fixture.py'
    )
}
Add-Step -Steps $steps -Name 'Native smoke: scripts/native-smoke.ps1' -Enabled (-not $SkipNativeSmoke) -Action {
    if (-not $IsWindows) {
        Write-Host 'N/A: native smoke is Windows-only; cross-platform Rust and Tauri gates remain required.'
        return
    }
    if (-not $script:NativeBuildRan) {
        throw 'Native smoke requires a successful native build from this verification run.'
    }
    Invoke-External -FilePath 'pwsh' -ArgumentList @(
        '-NoProfile', '-File', 'scripts/native-smoke.ps1'
    )
}
Add-Step -Steps $steps -Name 'Build unsigned portable Windows EXE from fresh native ZIP' -Enabled (-not $SkipPortableExe -and -not $SkipNativeBuild -and -not $SkipPython) -Action {
    if (-not $IsWindows) {
        Write-Host 'N/A: the portable EXE build is Windows-only.'
        return
    }
    if (-not $script:NativeBuildRan -or [string]::IsNullOrWhiteSpace($script:NativeArchive)) {
        throw 'Portable EXE build requires the native ZIP packaged from this verification run.'
    }
    $portableOutput = Join-Path $script:TempRoot 'portable-artifact'
    $buildOutput = Invoke-ExternalCapture -FilePath 'uv' -ArgumentList @(
        'run', '--frozen', 'python', '-I', 'scripts/build-portable-exe.py',
        '--archive', $script:NativeArchive, '--output-dir', $portableOutput
    )
    $buildLines = @($buildOutput -split "`n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($buildLines.Count -lt 1) { throw 'Portable builder did not return its artifact summary.' }
    try { $build = $buildLines[-1] | ConvertFrom-Json -AsHashtable -ErrorAction Stop }
    catch { throw 'Portable builder did not return valid artifact JSON.' }
    if ($build -isnot [Collections.IDictionary] -or
        [string]::IsNullOrWhiteSpace([string]$build['executable']) -or
        [string]$build['sha256'] -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$build['payload_sha256'] -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Portable builder returned an incomplete artifact summary.'
    }
    $executable = [IO.Path]::GetFullPath((Join-Path $portableOutput 'Zombie Killer.exe'))
    $reportedExecutable = [IO.Path]::GetFullPath([string]$build['executable'])
    if (-not [string]::Equals($executable, $reportedExecutable, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw 'Portable builder did not produce the expected EXE in its owned output directory.'
    }
    $actualSha = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumsPath = Join-Path $portableOutput 'SHA256SUMS'
    if ($actualSha -cne [string]$build['sha256'] -or
        -not (Test-Path -LiteralPath $checksumsPath -PathType Leaf) -or
        (Get-Content -LiteralPath $checksumsPath -Raw).TrimEnd() -cne "$actualSha  Zombie Killer.exe") {
        throw 'Portable EXE or SHA256SUMS does not match the builder summary.'
    }
    $script:PortableExecutable = $executable
    $script:PortableExecutableSha256 = $actualSha
    $script:PortablePayloadSha256 = [string]$build['payload_sha256']
}
Add-Step -Steps $steps -Name 'Portable Windows diagnostic and native lifecycle smoke' -Enabled (-not $SkipPortableExe -and -not $SkipNativeSmoke -and -not $SkipNativeBuild -and -not $SkipPython) -Action {
    if (-not $IsWindows) {
        Write-Host 'N/A: portable native lifecycle smoke is Windows-only.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($script:PortableExecutable) -or
        [string]::IsNullOrWhiteSpace($script:NativeArchive) -or
        [string]::IsNullOrWhiteSpace($script:PortablePayloadSha256)) {
        throw 'Portable smoke requires the fresh EXE and native ZIP from this verification run.'
    }
    $smokeReportPath = Join-Path $script:TempRoot 'portable-smoke.json'
    Invoke-External -FilePath 'pwsh' -ArgumentList @(
        '-NoProfile', '-File', 'scripts/portable-smoke.ps1',
        '-ExecutablePath', $script:PortableExecutable,
        '-ArchivePath', $script:NativeArchive,
        '-ReportPath', $smokeReportPath,
        '-ExpectedPayloadSha256', $script:PortablePayloadSha256
    )
    if (-not (Test-Path -LiteralPath $smokeReportPath -PathType Leaf)) {
        throw 'Portable smoke did not write a report.'
    }
    try { $report = Get-Content -LiteralPath $smokeReportPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop }
    catch { throw 'Portable smoke report was not valid JSON.' }
    if ($report -isnot [Collections.IDictionary] -or
        $report['passed'] -ne $true -or $report['state_removed'] -ne $true -or
        $report['native_readiness'] -ne $true -or $report['concurrent_isolation'] -ne $true -or
        $report['payload_sha256_independently_supplied'] -ne $true -or
        $report['executable_sha256'] -cne $script:PortableExecutableSha256 -or
        $report['diagnostic']['payload_sha256'] -cne $script:PortablePayloadSha256 -or
        $report['diagnostic']['cleanup'] -ne $true) {
        throw 'Portable smoke report did not prove the complete checked lifecycle.'
    }
    $runs = @($report['runs'])
    if ($runs.Count -ne 4) { throw 'Portable smoke report must include four controlled launches.' }
    foreach ($run in $runs) {
        if ($run['inventory_verified'] -ne $true -or $run['settled'] -ne $true) {
            throw 'Portable smoke report did not prove inventory and process settlement for every launch.'
        }
    }
}
Add-Step -Steps $steps -Name 'Tracked and complete-history secret:scan' -Enabled (-not $SkipSecretScan) -Action {
    $shallow = Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'rev-parse', '--is-shallow-repository'
    )
    if ($shallow -ne 'false') {
        throw 'Release verification requires complete, non-shallow Git history.'
    }
    Invoke-External -FilePath 'pnpm' -ArgumentList @('run', 'secret:scan')
}
Add-Step -Steps $steps -Name 'SBOM generate+test with BUILD-MANIFEST.json when built' -Enabled (-not $SkipSbom) -Action {
    Invoke-External -FilePath 'node' -ArgumentList @('scripts/test-sbom.mjs')
    $sourceSbom = Join-Path $script:TempRoot 'sbom-source'
    Invoke-External -FilePath 'node' -ArgumentList @(
        'scripts/generate-sbom.mjs', '--output', $sourceSbom
    )
    if ($script:NativeBuildRan) {
        if (-not (Test-Path -LiteralPath $SidecarManifest -PathType Leaf)) {
            throw 'Fresh native BUILD-MANIFEST.json is missing before sidecar SBOM generation.'
        }
        $nativeSbom = Join-Path $script:TempRoot 'sbom-native'
        Invoke-External -FilePath 'node' -ArgumentList @(
            'scripts/generate-sbom.mjs', '--output', $nativeSbom,
            '--sidecar-manifest', $SidecarManifest
        )
    }
}
Add-Step -Steps $steps -Name 'git diff --check, staged diff, HEAD, and clean status' -Enabled $true -Action {
    Invoke-External -FilePath 'git' -ArgumentList @('-C', $RepositoryRoot, 'diff', '--check')
    Invoke-External -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'diff', '--cached', '--check'
    )
    $finalHeadBefore = Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'rev-parse', 'HEAD'
    )
    $finalStateDigestBefore = Get-RepositoryStateDigest
    $finalStatusBefore = Get-RepositoryStatus
    $finalStateDigestAfter = Get-RepositoryStateDigest
    $finalHeadAfter = Invoke-ExternalCapture -FilePath 'git' -ArgumentList @(
        '-C', $RepositoryRoot, 'rev-parse', 'HEAD'
    )
    $finalStatusAfter = Get-RepositoryStatus
    if (
        $finalHeadBefore -ne $script:InitialHead -or
        $finalHeadAfter -ne $script:InitialHead -or
        $finalHeadBefore -ne $finalHeadAfter
    ) {
        throw 'Verification must not change HEAD.'
    }
    if (
        $finalStateDigestBefore -ne $script:InitialStateDigest -or
        $finalStateDigestAfter -ne $script:InitialStateDigest -or
        $finalStateDigestBefore -ne $finalStateDigestAfter
    ) {
        throw 'Verification changed release-relevant working, staged, or untracked content.'
    }
    if ($finalStatusBefore -ne $finalStatusAfter) {
        throw 'Release-relevant Git status changed during final verification.'
    }
    if ($AllowDirty) {
        if ($finalStatusAfter -ne $script:InitialStatus) {
            throw 'Scoped dirty verification changed the initial worktree state.'
        }
    }
    elseif ($finalStatusAfter.Length -gt 0) {
        $changedCount = ($finalStatusAfter -split "`n").Count
        throw "Verification left $changedCount changed path(s) in the worktree."
    }
}

$originalLocation = Get-Location
$failure = $null
try {
    Set-Location -LiteralPath $RepositoryRoot
    $script:TempRoot = New-VerificationTempRoot
    $env:CARGO_HOME = Join-Path $script:TempRoot 'cargo-home'
    for ($index = 0; $index -lt $steps.Count; $index += 1) {
        Invoke-Step -Index ($index + 1) -Total $steps.Count -Step $steps[$index]
    }
}
catch {
    $failure = $_
}
finally {
    try {
        if ($null -ne $script:TempRoot) {
            Remove-OwnedTempRoot -Path $script:TempRoot
        }
    }
    catch {
        if ($null -eq $failure) {
            $failure = $_
            $script:ExitCode = 1
        }
        else {
            [Console]::Error.WriteLine('Temporary verification output cleanup also failed.')
        }
    }
    Set-Location -LiteralPath $originalLocation
}

if ($null -ne $failure) {
    [Console]::Error.WriteLine(('Verification failed: ' + $failure.Exception.Message))
    exit $script:ExitCode
}

if ($isNonRelease) {
    Write-Warning 'NON-RELEASE scoped checks passed; this is not release approval.'
    exit 2
}

Write-Host 'All clean, unskipped source-release verification gates passed.'
Write-Host 'Artifacts remain unsigned and nothing was published.'
exit 0
