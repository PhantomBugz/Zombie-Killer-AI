<#
.SYNOPSIS
Verifies the single portable wrapper in a disposable Windows profile with exact process identities.
.DESCRIPTION
Requires PowerShell 7 on Windows. Does not close pre-existing applications. Dot-source
to reuse the focused helpers without executing the portable artifact. Its owned
extraction and temporary roots are separate from persistent application state,
which resolves through the Windows user profile.
#>
[CmdletBinding()]
param(
    [string] $ExecutablePath,
    [string] $ArchivePath,
    [string] $ReportPath,
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedPayloadSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Dot-sourced scripts bind their own param block in this scope. Preserve the portable
# CLI inputs before native-smoke initializes its similarly named parameters.
$portableEntryParameters = @{
    ExecutablePath = $ExecutablePath; ArchivePath = $ArchivePath
    ReportPath = $ReportPath; ExpectedPayloadSha256 = $ExpectedPayloadSha256
}
. (Join-Path $PSScriptRoot 'native-smoke.ps1')

function Assert-ZkPortableConfinedPath {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $StateRoot)
    $root = Get-ZkNormalizedPath -Path $StateRoot
    $path = Get-ZkNormalizedPath -Path $Path
    if (-not $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Portable runtime path is outside the confined owned state root.'
    }
    return $path
}

function Get-ZkPortableArchiveInventory {
    param([Parameter(Mandatory)][string] $ArchivePath)
    $files = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = [long] 0
    $zip = [IO.Compression.ZipFile]::OpenRead((Get-ZkNormalizedPath -Path $ArchivePath))
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name.EndsWith('/')) { continue }
            if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('/') -or $name.Contains(':') -or
                @($name.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
                throw "Unsafe relative archive path: $name"
            }
            if ($files.ContainsKey($name)) { throw "Duplicate Windows archive path: $name" }
            if ($name -match '(?i)\.(pdb|map|rs|ts|tsx|jsx|c|cpp|h|cs|py|ps1)$|(^|/)(src|tests?|fixtures|\.git|node_modules)(/|$)|(^|/)\.env($|\.)') {
                throw "Project source, debug, fixture, or credential artifact is shipped: $name"
            }
            $stream = $entry.Open()
            try { $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() }
            finally { $stream.Dispose() }
            $files.Add($name, [pscustomobject]@{ Size = [long] $entry.Length; Sha256 = $hash })
            $total += [long] $entry.Length
        }
    }
    finally { $zip.Dispose() }
    if ($files.Count -eq 0) { throw 'Archive file inventory is empty.' }
    return [pscustomobject]@{ Files = $files; TotalBytes = $total }
}

function Resolve-ZkPortableRuntimeRoot {
    param([Parameter(Mandatory)][psobject] $ApplicationIdentity, [Parameter(Mandatory)][string] $StateRoot)
    $app = Assert-ZkPortableConfinedPath -Path $ApplicationIdentity.ExecutablePath -StateRoot $StateRoot
    $suffix = [IO.Path]::DirectorySeparatorChar + 'target' + [IO.Path]::DirectorySeparatorChar + 'release' + [IO.Path]::DirectorySeparatorChar + 'zombie-killer.exe'
    if (-not $app.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native portable child does not use the exact packaged target/release layout.'
    }
    $runtime = $app.Substring(0, $app.Length - $suffix.Length)
    return Assert-ZkPortableConfinedPath -Path $runtime -StateRoot $StateRoot
}

function Assert-ZkPortableRuntimeInventory {
    param(
        [Parameter(Mandatory)][string] $RuntimeRoot,
        [Parameter(Mandatory)][string] $StateRoot,
        [Parameter(Mandatory)][psobject] $Inventory
    )
    $runtime = Assert-ZkPortableConfinedPath -Path $RuntimeRoot -StateRoot $StateRoot
    $rootItem = Get-Item -LiteralPath $runtime -Force
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Portable runtime must be a directory without reparse points.'
    }
    $items = @(Get-ChildItem -LiteralPath $runtime -Force -Recurse)
    if (@($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
        throw 'Portable runtime inventory contains a reparse point.'
    }
    $actual = @($items | Where-Object { -not $_.PSIsContainer })
    if ($actual.Count -ne $Inventory.Files.Count) { throw 'Portable runtime inventory has missing or unexpected files.' }
    foreach ($file in $actual) {
        $name = [IO.Path]::GetRelativePath($runtime, $file.FullName).Replace('\', '/')
        if (-not $Inventory.Files.ContainsKey($name)) { throw "Unexpected portable runtime file: $name" }
        $expected = $Inventory.Files[$name]
        if ($file.Length -ne $expected.Size -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected.Sha256) {
            throw "Portable runtime bytes/hash differ from original ZIP: $name"
        }
    }
}

function Assert-ZkPortableCheckResult {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Json,
        [Parameter(Mandatory)][int] $ExitCode,
        [Parameter(Mandatory)][string] $StateRoot,
        [Parameter(Mandatory)][psobject] $Inventory,
        [string] $ExpectedPayloadSha256
    )
    if ($ExitCode -ne 0) { throw "Portable diagnostic exit was $ExitCode instead of zero." }
    try { $metadata = ConvertFrom-Json -InputObject $Json -AsHashtable -ErrorAction Stop }
    catch { throw 'Portable diagnostic did not return valid JSON.' }
    $fields = @('runtime_root', 'files', 'total_bytes', 'payload_sha256', 'cleanup')
    if ($metadata -isnot [Collections.IDictionary] -or $metadata.Count -ne $fields.Count -or
        @($fields | Where-Object { -not $metadata.ContainsKey($_) }).Count -gt 0 -or
        $metadata.runtime_root -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($metadata.runtime_root) -or
        $metadata.files -isnot [long] -and $metadata.files -isnot [int] -or
        $metadata.total_bytes -isnot [long] -and $metadata.total_bytes -isnot [int] -or
        $metadata.files -ne $Inventory.Files.Count -or $metadata.total_bytes -ne $Inventory.TotalBytes) {
        throw 'Portable diagnostic metadata does not match the original ZIP inventory.'
    }
    if ($metadata.cleanup -isnot [bool] -or -not $metadata.cleanup) { throw 'Portable diagnostic cleanup must be boolean true.' }
    if ($metadata.payload_sha256 -isnot [string] -or $metadata.payload_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedPayloadSha256) -and $metadata.payload_sha256 -cne $ExpectedPayloadSha256)) {
        throw 'Portable diagnostic payload hash did not match the expected SHA256.'
    }
    $runtime = Assert-ZkPortableConfinedPath -Path $metadata.runtime_root -StateRoot $StateRoot
    if (Test-Path -LiteralPath $runtime) { throw 'Portable diagnostic runtime remains after reported cleanup.' }
    return [pscustomobject] $metadata
}

function Invoke-ZkPortableDiagnosticProcess {
    param(
        [Parameter(Mandatory)][Diagnostics.ProcessStartInfo] $StartInfo,
        [ValidateRange(1, 300)][int] $TimeoutSeconds = 60
    )
    $stateRoot = $StartInfo.Environment['LOCALAPPDATA']
    if ([string]::IsNullOrWhiteSpace($stateRoot)) { throw 'Portable diagnostic requires isolated LOCALAPPDATA.' }
    $work = Assert-ZkPortableConfinedPath -Path (Join-Path $stateRoot ('portable-diagnostic-host-' + [guid]::NewGuid().ToString('N'))) -StateRoot $stateRoot
    [IO.Directory]::CreateDirectory($work) | Out-Null
    $configPath = Join-Path $work 'config.json'
    $resultPath = Join-Path $work 'result.json'
    $workerPath = Join-Path $work 'host.ps1'
    $environment = @{}
    foreach ($entry in $StartInfo.Environment.GetEnumerator()) { $environment[$entry.Key] = $entry.Value }
    $config = @{
        Executable = $StartInfo.FileName; WorkingDirectory = $StartInfo.WorkingDirectory
        Arguments = @($StartInfo.ArgumentList | ForEach-Object { [string] $_ })
        Environment = $environment; ResultPath = $resultPath
    }
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    # The existing JobLaunch intentionally does not redirect handles. A finite, job-bound
    # PowerShell host captures the target's pipes to our owned file; every descendant inherits
    # the host's job membership. No change to native-smoke's launch implementation is needed.
    $worker = @'
param([string] $ConfigPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = [IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json -AsHashtable
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $config.Executable
$start.WorkingDirectory = $config.WorkingDirectory
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.Environment.Clear()
foreach ($key in $config.Environment.Keys) { $start.Environment[$key] = $config.Environment[$key] }
foreach ($argument in $config.Arguments) { $start.ArgumentList.Add([string] $argument) }
$process = [Diagnostics.Process]::Start($start)
try {
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $identity = @{ Pid = $process.Id; StartTimeUtcTicks = $process.StartTime.ToUniversalTime().Ticks; ExecutablePath = $start.FileName }
    $gui = $false
    while (-not $process.HasExited) {
        $process.Refresh()
        if (-not $process.HasExited -and $process.MainWindowHandle -ne [IntPtr]::Zero) { $gui = $true }
        Start-Sleep -Milliseconds 20
    }
    $process.WaitForExit()
    if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Diagnostic output pipes did not settle.' }
    $result = @{ ExitCode = $process.ExitCode; Stdout = $stdout.Result.Trim(); Stderr = $stderr.Result.Trim(); GuiObserved = $gui; Identity = $identity }
    [IO.File]::WriteAllText($config.ResultPath, ($result | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}
finally { $process.Dispose() }
'@
    [IO.File]::WriteAllText($workerPath, $worker, [Text.UTF8Encoding]::new($false))
    $hostInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $stateRoot
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-File', $workerPath, '-ConfigPath', $configPath)) { $hostInfo.ArgumentList.Add($argument) }
    $launch = $null
    $registry = New-ZkCaptureRegistry
    $hostIdentityBound = $false
    try {
        $launch = Start-ZkJobBoundProcess -StartInfo $hostInfo
        $hostProcess = Get-Process -Id ([int] $launch.ProcessId)
        try {
            $hostIdentity = Get-ZkProcessIdentity -Process $hostProcess
            Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $hostIdentity
            Add-ZkCapturedRecord -Registry $registry -Identity $hostIdentity -Process $hostProcess -Kind descendant | Out-Null
            $hostIdentityBound = $true
        }
        catch { $hostProcess.Dispose(); throw }
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            Sync-ZkJobCaptures -Launch $launch -Registry $registry -ApplicationPath $StartInfo.FileName -EnginePath (Join-Path $work 'unused-engine.exe')
            if (Test-ZkLaunchSettled -Launch $launch) { break }
            if (-not $launch.IsLaunchedProcessActive()) {
                # A successful host result is insufficient when even a closed-pipe child lives.
                throw 'Portable diagnostic job retained a live descendant after its host exited.'
            }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Portable diagnostic timed out.' }
            Start-Sleep -Milliseconds 20
        } while ($true)
        Update-ZkCapturedExitCodes -Registry $registry
        $hostRecord = $registry[(Get-ZkProcessIdentityKey -Identity $hostIdentity)]
        if (-not $hostRecord.ExitCodeObserved -or $hostRecord.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw 'Portable diagnostic host did not produce a settled result.'
        }
        $result = [IO.File]::ReadAllText($resultPath) | ConvertFrom-Json
        $result | Add-Member -NotePropertyName Settled -NotePropertyValue $true
        return $result
    }
    finally {
        try {
            if ($null -ne $launch -and -not (Test-ZkLaunchSettled -Launch $launch)) {
                if (-not $hostIdentityBound) { $launch.TerminateLaunchedProcess(5000) | Out-Null }
                $settled = Stop-ZkTrackedLaunchExactly -Launch $launch -Registry $registry -ApplicationPath $StartInfo.FileName -EnginePath (Join-Path $work 'unused-engine.exe')
                if (-not $settled) { Write-Warning "Diagnostic job did not settle; retain its owned state at '$stateRoot'." }
            }
        }
        finally {
            Dispose-ZkCaptureRegistry -Registry $registry
            if ($null -ne $launch) { $launch.Dispose() }
        }
    }
}

function Get-ZkPortableNativeRecord {
    param([Parameter(Mandatory)][psobject] $Run, [Parameter(Mandatory)][string] $StateRoot)
    Sync-ZkJobCaptures -Launch $Run.Launch -Registry $Run.Registry -ApplicationPath $Run.ApplicationPath -EnginePath $Run.EnginePath
    $matches = @($Run.Registry.Values | Where-Object {
        $_.Identity.ExecutablePath.EndsWith('\target\release\zombie-killer.exe', [StringComparison]::OrdinalIgnoreCase)
    })
    foreach ($record in $matches) {
        # Job capture supplies exact identity and rechecks membership. A matching name elsewhere
        # on the machine is never considered, and a job member outside our fresh root is rejected.
        Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $record.Identity -StateRoot $StateRoot | Out-Null
    }
    if ($matches.Count -gt 1) { throw 'Portable launch produced multiple native application identities.' }
    if ($matches.Count -eq 0) { return $null }
    $live = Get-ZkMatchingProcess -Identity $matches[0].Identity
    if ($null -eq $live) { throw 'The exact portable native child exited before readiness.' }
    $live.Dispose()
    return $matches[0]
}

function Remove-ZkPortableSmokeState {
    param([Parameter(Mandatory)][psobject] $OwnedState, [AllowEmptyCollection()][object[]] $Runs = @())
    foreach ($run in $Runs) {
        if (-not (Test-ZkLaunchSettled -Launch $run.Launch)) { return $false }
    }
    Remove-ZkOwnedStateRoot -StateRoot $OwnedState.Path -MarkerToken $OwnedState.MarkerToken
    return $true
}

function New-ZkPortableReadinessEvidence {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Names,
        [long] $MainWindowHandle = 0,
        [Nullable[bool]] $WindowOffscreen,
        [string] $WindowTitle,
        [string] $WindowObservationError,
        [bool] $CausalEngineObserved = $false
    )
    return [pscustomobject]@{
        UIState = (Get-ZkUiReadinessState -Names $Names)
        CreatorCredit = ($Names -contains 'Made by PhantomBugz')
        NameCount = $Names.Count; UiNames = @($Names)
        MainWindowHandle = $MainWindowHandle; WindowOffscreen = $WindowOffscreen
        WindowTitle = $WindowTitle; WindowObservationError = $WindowObservationError
        CausalEngineObserved = $CausalEngineObserved
    }
}

function New-ZkPortableWebView2StartInfo {
    param(
        [Parameter(Mandatory)][string] $ExecutablePath,
        [Parameter(Mandatory)][string] $StateRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]] $Runs
    )
    $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $ExecutablePath -StateRoot $StateRoot
    $folder = Assert-ZkPortableConfinedPath -Path (Join-Path $StateRoot ('webview2-user-data-' + [guid]::NewGuid().ToString('N'))) -StateRoot $StateRoot
    foreach ($run in $Runs) {
        if (Test-ZkPathEqual -Left $run.WebView2UserDataFolder -Right $folder) {
            throw 'Portable WebView2 user-data folder was reused across launches.'
        }
    }
    $startInfo.Environment['WEBVIEW2_USER_DATA_FOLDER'] = $folder
    return [pscustomobject]@{ StartInfo = $startInfo; UserDataFolder = $folder }
}

function Get-ZkPortableWebView2OverrideDistinctCount {
    param([Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]] $Runs)
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($run in $Runs) {
        $folder = [string] $run.WebView2UserDataFolder
        if (-not [string]::IsNullOrWhiteSpace($folder)) {
            [void] $unique.Add((Get-ZkNormalizedPath -Path $folder))
        }
    }
    return $unique.Count
}

function Start-ZkPortableRun {
    param(
        [Parameter(Mandatory)][string] $ExecutablePath,
        [Parameter(Mandatory)][string] $StateRoot,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]] $Runs,
        [Parameter(Mandatory)][psobject] $Inventory
    )
    $start = New-ZkPortableWebView2StartInfo -ExecutablePath $ExecutablePath -StateRoot $StateRoot -Runs $Runs
    $launch = Start-ZkJobBoundProcess -StartInfo $start.StartInfo
    $run = [pscustomobject]@{
        Launch = $launch; Registry = (New-ZkCaptureRegistry); WrapperIdentity = $null
        WebView2UserDataFolder = $start.UserDataFolder
        ApplicationPath = (Join-Path $StateRoot 'not-yet-discovered.exe')
        EnginePath = (Join-Path $StateRoot 'not-yet-discovered-engine.exe')
        NativeRecord = $null; RuntimeRoot = $null; UiNames = @(); InventoryVerified = $false
        Readiness = (New-ZkPortableReadinessEvidence -Names @()); ReadinessSamples = 0; LastReadinessUtc = $null
    }
    # Retain ownership immediately, including when initial identity capture fails.
    $Runs.Add($run)
    $wrapperProcess = Get-Process -Id ([int] $launch.ProcessId)
    try {
        $run.WrapperIdentity = Get-ZkProcessIdentity -Process $wrapperProcess
        Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $run.WrapperIdentity
        Add-ZkCapturedRecord -Registry $run.Registry -Identity $run.WrapperIdentity -Process $wrapperProcess -Kind descendant | Out-Null
    }
    catch { $wrapperProcess.Dispose(); throw }
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $native = Get-ZkPortableNativeRecord -Run $run -StateRoot $StateRoot
        if ($null -ne $native) {
            if ($null -eq $run.NativeRecord) {
                $run.NativeRecord = $native
                $run.RuntimeRoot = Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $native.Identity -StateRoot $StateRoot
                $layout = Resolve-ZkNativeLayout -ExecutablePath $native.Identity.ExecutablePath
                $run.ApplicationPath = $layout.ApplicationPath
                $run.EnginePath = $layout.EnginePath
            }
            # Early job snapshots can precede layout discovery; classify already retained records.
            foreach ($record in $run.Registry.Values) {
                if (Test-ZkPathEqual -Left $record.Identity.ExecutablePath -Right $run.ApplicationPath) { $record.Kind = 'application' }
                elseif (Test-ZkPathEqual -Left $record.Identity.ExecutablePath -Right $run.EnginePath) { $record.Kind = 'engine' }
            }
            Assert-ZkTrackedTcpListenersAbsent -Registry $run.Registry
            Update-ZkCapturedExitCodes -Registry $run.Registry
            $run.UiNames = @(Get-ZkUiAutomationNames -Identity $native.Identity)
            $ui = Get-ZkUiReadinessState -Names $run.UiNames
            $engines = @($run.Registry.Values | Where-Object Kind -eq engine)
            $causalEngine = Get-ZkCausalScanEngineRecord -EngineRecords $engines
            $windowHandle = [long] 0
            $windowTitle = $null
            $windowOffscreen = $null
            $windowError = $null
            try {
                $windowProcess = Get-ZkMatchingProcess -Identity $native.Identity
                if ($null -ne $windowProcess) {
                    try {
                        $windowProcess.Refresh()
                        $windowHandle = $windowProcess.MainWindowHandle.ToInt64()
                        $windowTitle = $windowProcess.MainWindowTitle
                    }
                    finally { $windowProcess.Dispose() }
                }
                if ($windowHandle -ne 0) {
                    $window = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr] $windowHandle)
                    if ($null -ne $window -and $window.Current.ProcessId -eq $native.Identity.Pid) {
                        $windowOffscreen = [bool] $window.Current.IsOffscreen
                    }
                }
            }
            catch { $windowError = $_.Exception.GetType().Name }
            $run.Readiness = New-ZkPortableReadinessEvidence -Names $run.UiNames -MainWindowHandle $windowHandle -WindowTitle $windowTitle -WindowOffscreen $windowOffscreen -WindowObservationError $windowError -CausalEngineObserved ($null -ne $causalEngine)
            $run.ReadinessSamples += 1
            $run.LastReadinessUtc = [DateTime]::UtcNow.ToString('O')
            if ($ui -eq 'error' -or @($engines | Where-Object { $_.ExitCodeObserved -and $_.ExitCode -ne 0 }).Count -gt 0) {
                throw 'Portable native renderer or engine reported a startup failure.'
            }
            if ($ui -eq 'ready' -and $run.UiNames -contains 'Made by PhantomBugz' -and
                $null -ne $causalEngine) {
                # Hashing the complete archive is slower than a short engine request. Finish
                # identity/TCP startup sampling before this full byte inventory comparison.
                Assert-ZkPortableRuntimeInventory -RuntimeRoot $run.RuntimeRoot -StateRoot $StateRoot -Inventory $Inventory
                $run.InventoryVerified = $true
                return $run
            }
        }
        if (-not $launch.IsLaunchedProcessActive()) { throw 'Portable wrapper exited before native readiness.' }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Portable startup timed out before native readiness, creator credit, and sampled scan engine (UIState=$($run.Readiness.UIState), CreatorCredit=$($run.Readiness.CreatorCredit), NameCount=$($run.Readiness.NameCount), MainWindowHandle=$($run.Readiness.MainWindowHandle), WindowOffscreen=$($run.Readiness.WindowOffscreen), CausalEngineObserved=$($run.Readiness.CausalEngineObserved))."
        }
        Start-Sleep -Milliseconds 50
    } while ($true)
}

function Get-ZkPortableSettlementDiagnostic {
    param([Parameter(Mandatory)][psobject] $Run)

    # These independent process and UI queries can race with process exit. Report clues
    # from the exact launch job, not an atomic snapshot or a machine-wide process list.
    $members = @($Run.Launch.GetProcessIds() | ForEach-Object { [long] $_ } | Sort-Object)
    $memberSample = @($members | Select-Object -First 16)
    $live = [Collections.Generic.List[string]]::new()
    $liveCount = 0
    $webview2NameCount = 0
    $otherDescendantCount = 0
    $wrapperKey = Get-ZkProcessIdentityKey -Identity $Run.WrapperIdentity
    foreach ($record in $Run.Registry.Values) {
        $record.Process.Refresh()
        if (-not $record.Process.HasExited) {
            $liveCount += 1
            if ([string] $record.Kind -ceq 'descendant' -and
                (Get-ZkProcessIdentityKey -Identity $record.Identity) -cne $wrapperKey) {
                if ([string]::Equals(
                    [IO.Path]::GetFileName([string] $record.Identity.ExecutablePath),
                    'msedgewebview2.exe',
                    [StringComparison]::OrdinalIgnoreCase
                )) { $webview2NameCount += 1 }
                else { $otherDescendantCount += 1 }
            }
            if ($live.Count -lt 16) {
                $kind = switch ([string] $record.Kind) {
                    'application' { 'application'; break }
                    'engine' { 'engine'; break }
                    'descendant' { 'descendant'; break }
                    default { 'other' }
                }
                $live.Add("$($record.Identity.Pid):$kind")
            }
        }
    }
    $wrapper = $Run.Registry[(Get-ZkProcessIdentityKey -Identity $Run.WrapperIdentity)]
    $windowPresent = $false
    $errorDialog = $false
    $windowProbeError = $false
    if ($null -ne $wrapper) {
        $wrapper.Process.Refresh()
        if (-not $wrapper.Process.HasExited) {
            try {
                $windowPresent = $wrapper.Process.MainWindowHandle -ne [IntPtr]::Zero
                $errorDialog = [string]::Equals(
                    [string] $wrapper.Process.MainWindowTitle,
                    'Zombie Killer — PhantomBugz',
                    [StringComparison]::Ordinal
                )
            }
            catch { $windowProbeError = $true }
        }
    }
    $native = $Run.Registry[(Get-ZkProcessIdentityKey -Identity $Run.NativeRecord.Identity)]
    return "snapshot_nonatomic=True; wrapper_active=$($Run.Launch.IsLaunchedProcessActive()); native_active=$($null -ne $native -and -not $native.Process.HasExited); job_member_count=$($members.Count); job_member_pids=$($memberSample -join ','); job_member_sample_truncated=$($members.Count -gt 16); captured_live_count=$liveCount; captured_live=$($live -join ','); captured_live_sample_truncated=$($liveCount -gt 16); webview2_name_count=$webview2NameCount; other_descendant_count=$otherDescendantCount; runtime_exists=$(Test-Path -LiteralPath $Run.RuntimeRoot); wrapper_window_present=$windowPresent; wrapper_error_dialog=$errorDialog; wrapper_window_probe_error=$windowProbeError"
}

function Close-ZkPortableRun {
    param([Parameter(Mandatory)][psobject] $Run)
    if ($null -eq $Run.NativeRecord -or -not (Send-ZkGracefulClose -Identity $Run.NativeRecord.Identity)) {
        throw 'Exact portable native child did not accept graceful close.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Sync-ZkJobCaptures -Launch $Run.Launch -Registry $Run.Registry -ApplicationPath $Run.ApplicationPath -EnginePath $Run.EnginePath
        Assert-ZkTrackedTcpListenersAbsent -Registry $Run.Registry
        Update-ZkCapturedExitCodes -Registry $Run.Registry
        if (Test-ZkLaunchSettled -Launch $Run.Launch) { break }
        if ([DateTime]::UtcNow -ge $deadline) {
            $diagnostic = try { Get-ZkPortableSettlementDiagnostic -Run $Run }
                catch { "diagnostic_error=$($_.Exception.GetType().Name)" }
            throw "Portable launch job did not settle after graceful native close ($diagnostic)."
        }
        Start-Sleep -Milliseconds 50
    } while ($true)
    Assert-ZkSuccessfulApplicationExit -Registry $Run.Registry -ApplicationIdentity $Run.NativeRecord.Identity
    $wrapper = $Run.Registry[(Get-ZkProcessIdentityKey -Identity $Run.WrapperIdentity)]
    if (-not $wrapper.ExitCodeObserved -or $wrapper.ExitCode -ne 0) { throw 'Portable wrapper did not exit successfully.' }
    if (Test-Path -LiteralPath $Run.RuntimeRoot) { throw 'Portable wrapper left its exact runtime directory after normal exit.' }
    foreach ($record in $Run.Registry.Values) {
        $live = Get-ZkMatchingProcess -Identity $record.Identity
        if ($null -ne $live) { $live.Dispose(); throw 'A captured portable process identity remained after job settlement.' }
    }
}

function Assert-ZkPortableSmokeComplete {
    param([Parameter(Mandatory)][Collections.IDictionary] $Report)

    if (-not $Report.state_removed) { throw 'Portable smoke state cleanup was not proven.' }
    if (-not $Report.passed -or -not $Report.native_readiness -or -not $Report.concurrent_isolation) {
        throw 'Portable smoke did not prove native readiness and concurrent launch isolation.'
    }
    $runs = @($Report.runs)
    if ($runs.Count -ne 4) { throw 'Portable smoke did not complete all four controlled launches.' }
    if ($Report.webview2_udf_override_distinct_count -ne 4) {
        throw 'Portable smoke did not prove WebView2 user-data overrides are distinct for four runs.'
    }
    foreach ($run in $runs) {
        if (-not $run.inventory_verified -or -not $run.settled) {
            throw 'Portable smoke could not prove inventory or process settlement for every launch.'
        }
    }
}

function Invoke-ZkPortableSmoke {
    param(
        [Parameter(Mandatory)][string] $ExecutablePath,
        [Parameter(Mandatory)][string] $ArchivePath,
        [Parameter(Mandatory)][string] $ReportPath,
        [string] $ExpectedPayloadSha256
    )
    if (-not $IsWindows) { throw 'Portable smoke requires PowerShell 7 on Windows.' }
    Assert-ZkDisposableWindowsProfile
    $executable = Get-ZkNormalizedPath -Path $ExecutablePath
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Portable wrapper executable is missing.' }
    $reportFile = Get-ZkNormalizedPath -Path $ReportPath
    $inventory = Get-ZkPortableArchiveInventory -ArchivePath $ArchivePath
    $owned = New-ZkOwnedStateRoot
    $runs = [Collections.Generic.List[object]]::new()
    $diagnosticSettled = $false
    $report = [ordered]@{
        passed = $false; executable = $executable; executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        archive = (Get-ZkNormalizedPath -Path $ArchivePath); archive_files = $inventory.Files.Count; archive_bytes = $inventory.TotalBytes
        payload_sha256_independently_supplied = (-not [string]::IsNullOrWhiteSpace($ExpectedPayloadSha256))
        diagnostic = $null; runs = @(); native_readiness = $false; concurrent_isolation = $false
        webview2_udf_override_distinct_count = 0
        state_root = $owned.Path; state_removed = $false; error = $null
    }
    try {
        Initialize-ZkNativeJobType
        Initialize-ZkUiAutomation
        Get-ZkTcpListenerSnapshot | Out-Null
        # Copy only the wrapper into an owned directory with spaces to exercise real path quoting.
        $copy = Join-Path $owned.Path 'portable launch with spaces\Zombie Killer.exe'
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($copy)) | Out-Null
        Copy-Item -LiteralPath $executable -Destination $copy
        $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $copy -StateRoot $owned.Path
        $startInfo.ArgumentList.Add('--check')
        $diagnostic = Invoke-ZkPortableDiagnosticProcess -StartInfo $startInfo
        $diagnosticSettled = $diagnostic.Settled
        if ($diagnostic.GuiObserved) { throw 'Portable --check showed a GUI window.' }
        if (-not [string]::IsNullOrWhiteSpace($diagnostic.Stderr)) { throw 'Successful portable diagnostic wrote unexpected stderr.' }
        $report.diagnostic = Assert-ZkPortableCheckResult -Json $diagnostic.Stdout -ExitCode $diagnostic.ExitCode -StateRoot $owned.Path -Inventory $inventory -ExpectedPayloadSha256 $ExpectedPayloadSha256
        $first = Start-ZkPortableRun -ExecutablePath $copy -StateRoot $owned.Path -Runs $runs -Inventory $inventory
        # Keep the exact job settlement gate before starting a second wrapper.
        $report.native_readiness = $true
        Close-ZkPortableRun -Run $first
        $second = Start-ZkPortableRun -ExecutablePath $copy -StateRoot $owned.Path -Runs $runs -Inventory $inventory
        if (Test-ZkPathEqual -Left $first.RuntimeRoot -Right $second.RuntimeRoot) { throw 'Relaunch reused a prior runtime path.' }
        Close-ZkPortableRun -Run $second
        $left = Start-ZkPortableRun -ExecutablePath $copy -StateRoot $owned.Path -Runs $runs -Inventory $inventory
        $right = Start-ZkPortableRun -ExecutablePath $copy -StateRoot $owned.Path -Runs $runs -Inventory $inventory
        if (Test-ZkPathEqual -Left $left.RuntimeRoot -Right $right.RuntimeRoot) { throw 'Concurrent wrappers shared a runtime path.' }
        Close-ZkPortableRun -Run $left
        $other = Get-ZkMatchingProcess -Identity $right.NativeRecord.Identity
        if ($null -eq $other) { throw 'Closing first concurrent wrapper ended the other exact native instance.' }
        $other.Dispose()
        if (-not $right.Launch.IsLaunchedProcessActive() -or -not (Test-Path -LiteralPath $right.RuntimeRoot)) {
            throw 'Other concurrent wrapper or its runtime was removed.'
        }
        Assert-ZkPortableRuntimeInventory -RuntimeRoot $right.RuntimeRoot -StateRoot $owned.Path -Inventory $inventory
        $report.concurrent_isolation = $true
        Close-ZkPortableRun -Run $right
        $report.passed = $true
    }
    catch { $report.error = $_.Exception.Message; throw }
    finally {
        foreach ($run in $runs) {
            try {
                if (-not (Test-ZkLaunchSettled -Launch $run.Launch)) {
                    if ($null -eq $run.WrapperIdentity) { $run.Launch.TerminateLaunchedProcess(5000) | Out-Null }
                    Stop-ZkTrackedLaunchExactly -Launch $run.Launch -Registry $run.Registry -ApplicationPath $run.ApplicationPath -EnginePath $run.EnginePath | Out-Null
                }
            }
            catch { Write-Warning "Exact portable cleanup could not settle a launch: $($_.Exception.Message)" }
        }
        try {
            if ($diagnosticSettled) { $report.state_removed = Remove-ZkPortableSmokeState -OwnedState $owned -Runs @($runs.ToArray()) }
            if (-not $report.state_removed) { Write-Warning "Portable smoke state retained at '$($owned.Path)' because lifecycle settlement was not proven." }
            $report.webview2_udf_override_distinct_count = Get-ZkPortableWebView2OverrideDistinctCount -Runs $runs
            $report.runs = @($runs | ForEach-Object {
                [pscustomobject]@{
                    wrapper = $_.WrapperIdentity; native = $(if ($null -ne $_.NativeRecord) { $_.NativeRecord.Identity } else { $null })
                    runtime_root = $_.RuntimeRoot; inventory_verified = $_.InventoryVerified; settled = (Test-ZkLaunchSettled -Launch $_.Launch)
                    readiness = $_.Readiness; readiness_samples = $_.ReadinessSamples; last_readiness_utc = $_.LastReadinessUtc
                    processes = @($_.Registry.Values | ForEach-Object { [pscustomobject]@{ identity = $_.Identity; kind = $_.Kind; tcp_samples = $_.ListenerSamples; exit_code = $_.ExitCode } })
                }
            })
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($reportFile)) | Out-Null
            [IO.File]::WriteAllText($reportFile, ($report | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
        }
        finally {
            foreach ($run in $runs) { Dispose-ZkCaptureRegistry -Registry $run.Registry; $run.Launch.Dispose() }
        }
    }
    Assert-ZkPortableSmokeComplete -Report $report
    Write-Host "PASS: portable diagnostic, two sequential runs, two independent concurrent runs, original ZIP bytes, native readiness/branding, no TCP listeners, and normal cleanup ($($inventory.Files.Count) files)"
    return [pscustomobject] $report
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-ZkPortableSmoke @portableEntryParameters | Out-Null
        exit 0
    }
    catch { Write-Error "Portable smoke failed: $($_.Exception.Message)"; exit 1 }
}
