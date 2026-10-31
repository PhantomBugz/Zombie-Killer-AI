[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\native-smoke.ps1')
$harness = Join-Path $PSScriptRoot '..\portable-smoke.ps1'
if (Test-Path -LiteralPath $harness) { . $harness }
$script:Passed = 0
$script:Failed = 0

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Equal($Expected, $Actual, [string] $Message) {
    if ($Expected -ne $Actual) { throw "$Message (expected '$Expected', got '$Actual')" }
}
function Assert-Throws([scriptblock] $Body, [string] $Pattern) {
    try { & $Body }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw "Expected '$Pattern', got '$($_.Exception.Message)'" }
        return
    }
    throw "Expected error matching '$Pattern'."
}
function Invoke-Test([string] $Name, [scriptblock] $Body) {
    try { & $Body; $script:Passed++; Write-Host "PASS: $Name" }
    catch { $script:Failed++; Write-Host "FAIL: $Name"; Write-Host $_.Exception.Message }
}
function New-TestArchive([string] $Path, [hashtable] $Files) {
    $zip = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Files.Keys) {
            $entry = $zip.CreateEntry($name)
            $stream = $entry.Open()
            try { $bytes = [Text.Encoding]::UTF8.GetBytes($Files[$name]); $stream.Write($bytes) }
            finally { $stream.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}
function Write-TestFiles([string] $Root, [hashtable] $Files) {
    foreach ($name in $Files.Keys) {
        $path = Join-Path $Root $name
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
        [IO.File]::WriteAllText($path, $Files[$name], [Text.UTF8Encoding]::new($false))
    }
}
function Start-TestOwnedJob([Diagnostics.ProcessStartInfo] $StartInfo, [Collections.Generic.List[object]] $Runs, [string] $ApplicationPath) {
    $launch = Start-ZkJobBoundProcess -StartInfo $StartInfo
    $run = [pscustomobject]@{
        Launch = $launch; Registry = (New-ZkCaptureRegistry); WrapperIdentity = $null
        ApplicationPath = $ApplicationPath; EnginePath = (Join-Path ([IO.Path]::GetDirectoryName($ApplicationPath)) 'engine\zombie-killer-engine.exe')
        NativeRecord = $null; RuntimeRoot = $null
    }
    $Runs.Add($run)
    return $run
}
function Stop-TestOwnedJobs([psobject] $OwnedState, [Collections.Generic.List[object]] $Runs) {
    try {
        foreach ($run in $Runs) {
            if ($null -eq $run.WrapperIdentity) { $run.Launch.TerminateLaunchedProcess(5000) | Out-Null }
            Stop-ZkTrackedLaunchExactly -Launch $run.Launch -Registry $run.Registry -ApplicationPath $run.ApplicationPath -EnginePath $run.EnginePath | Out-Null
        }
        return Remove-ZkPortableSmokeState -OwnedState $OwnedState -Runs @($Runs.ToArray())
    }
    finally {
        foreach ($run in $Runs) { Dispose-ZkCaptureRegistry -Registry $run.Registry; $run.Launch.Dispose() }
    }
}
function New-TestSettlementSnapshot([uint32[]] $MemberPids, [int] $CapturedCount, [string] $WindowTitle) {
    $process = [pscustomobject]@{
        HasExited = $false; MainWindowTitle = $WindowTitle; MainWindowHandle = [IntPtr] 42
    }
    $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
    $launch = [pscustomobject]@{ MemberPids = $MemberPids }
    $launch | Add-Member -MemberType ScriptMethod -Name GetProcessIds -Value { return $this.MemberPids }
    $launch | Add-Member -MemberType ScriptMethod -Name IsLaunchedProcessActive -Value { return $true }
    $registry = New-ZkCaptureRegistry
    $wrapperIdentity = $null
    $wrapperRecord = $null
    for ($index = 1; $index -le $CapturedCount; $index++) {
        $identity = [pscustomobject]@{
            Pid = $index; StartTimeUtcTicks = 1
            ExecutablePath = (Join-Path $PSScriptRoot 'secret-image-name.exe')
        }
        $record = [pscustomobject]@{
            Identity = $identity; Kind = $(if ($index -eq 2) { 'secret-kind' } else { 'descendant' })
            Process = $process
        }
        $registry.Add((Get-ZkProcessIdentityKey -Identity $identity), $record)
        if ($index -eq 1) { $wrapperIdentity = $identity; $wrapperRecord = $record }
    }
    return [pscustomobject]@{
        Launch = $launch; Registry = $registry; WrapperIdentity = $wrapperIdentity
        NativeRecord = $wrapperRecord; RuntimeRoot = $PSScriptRoot
    }
}

Invoke-Test 'portable smoke requires a disposable Windows profile before reading any artifact' {
    $previous = $env:ZK_DISPOSABLE_WINDOWS_PROFILE
    try {
        Remove-Item Env:ZK_DISPOSABLE_WINDOWS_PROFILE -ErrorAction SilentlyContinue
        Assert-Throws {
            Invoke-ZkPortableSmoke -ExecutablePath 'missing.exe' -ArchivePath 'missing.zip' -ReportPath 'missing.json'
        } 'ZK_DISPOSABLE_WINDOWS_PROFILE'
    }
    finally {
        if ($null -eq $previous) { Remove-Item Env:ZK_DISPOSABLE_WINDOWS_PROFILE -ErrorAction SilentlyContinue }
        else { $env:ZK_DISPOSABLE_WINDOWS_PROFILE = $previous }
    }
}

Invoke-Test 'portable smoke does not report success if owned state remains' {
    Assert-Throws {
        Assert-ZkPortableSmokeComplete -Report ([ordered]@{ passed = $true; state_removed = $false })
    } 'state.*not removed|state.*cleanup'
}

Invoke-Test 'portable report requires native readiness and four settled launches' {
    $runs = @(1..4 | ForEach-Object { [pscustomobject]@{ inventory_verified = $true; settled = $true } })
    $report = [ordered]@{
        passed = $true; state_removed = $true; native_readiness = $false
        concurrent_isolation = $true; runs = $runs
    }
    Assert-Throws { Assert-ZkPortableSmokeComplete -Report $report } 'native readiness'
    $report.native_readiness = $true
    Assert-ZkPortableSmokeComplete -Report $report
    $runs[0].settled = $false
    Assert-Throws { Assert-ZkPortableSmokeComplete -Report $report } 'settlement'
}

Invoke-Test 'archive inventory measures file bytes and rejects source or debug artifacts' {
    $owned = New-ZkOwnedStateRoot
    try {
        $archive = Join-Path $owned.Path 'fixture.zip'
        New-TestArchive $archive @{ 'LICENSE' = 'abc'; 'target/release/zombie-killer.exe' = 'xyz' }
        $inventory = Get-ZkPortableArchiveInventory -ArchivePath $archive
        Assert-Equal 2 $inventory.Files.Count 'two files must be inventoried'
        Assert-Equal 6 $inventory.TotalBytes 'byte count must come from actual ZIP files'
        Assert-Equal 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' $inventory.Files['LICENSE'].Sha256 'SHA256 must hash actual archive bytes'
        foreach ($name in @('app.pdb', 'renderer.js.map', 'src/app.rs', 'tests/fixture.txt', 'engine/app.py', '.env')) {
            $bad = Join-Path $owned.Path ([guid]::NewGuid().ToString('N') + '.zip')
            New-TestArchive $bad @{ $name = 'project artifact' }
            Assert-Throws { Get-ZkPortableArchiveInventory -ArchivePath $bad } 'source|debug|credential|fixture'
        }
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

Invoke-Test 'archive inventory rejects duplicate Windows paths and path escape' {
    $owned = New-ZkOwnedStateRoot
    try {
        $archive = Join-Path $owned.Path 'duplicates.zip'
        $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
        try { $zip.CreateEntry('NOTICE') | Out-Null; $zip.CreateEntry('notice') | Out-Null }
        finally { $zip.Dispose() }
        Assert-Throws { Get-ZkPortableArchiveInventory -ArchivePath $archive } 'duplicate'
        foreach ($name in @('../outside', '/absolute', 'C:/absolute', 'target/../outside', 'engine/file:stream')) {
            $archive = Join-Path $owned.Path ([guid]::NewGuid().ToString('N') + '.zip')
            New-TestArchive $archive @{ $name = 'bad' }
            Assert-Throws { Get-ZkPortableArchiveInventory -ArchivePath $archive } 'unsafe|relative'
        }
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

Invoke-Test 'runtime inventory compares bytes and detects additions, omissions, and same-size corruption' {
    $owned = New-ZkOwnedStateRoot
    try {
        $files = @{ 'LICENSE' = 'abc'; 'target/release/zombie-killer.exe' = 'xyz' }
        $archive = Join-Path $owned.Path 'fixture.zip'
        New-TestArchive $archive $files
        $inventory = Get-ZkPortableArchiveInventory -ArchivePath $archive
        $runtime = Join-Path $owned.Path 'PhantomBugz\runtime with spaces'
        Write-TestFiles $runtime $files
        Assert-ZkPortableRuntimeInventory -RuntimeRoot $runtime -StateRoot $owned.Path -Inventory $inventory
        [IO.File]::WriteAllText((Join-Path $runtime 'LICENSE'), 'bad')
        Assert-Throws { Assert-ZkPortableRuntimeInventory -RuntimeRoot $runtime -StateRoot $owned.Path -Inventory $inventory } 'bytes|hash'
        [IO.File]::WriteAllText((Join-Path $runtime 'LICENSE'), 'abc')
        [IO.File]::WriteAllText((Join-Path $runtime 'extra.txt'), 'unexpected')
        Assert-Throws { Assert-ZkPortableRuntimeInventory -RuntimeRoot $runtime -StateRoot $owned.Path -Inventory $inventory } 'unexpected|inventory'
        Remove-Item -LiteralPath (Join-Path $runtime 'extra.txt')
        Remove-Item -LiteralPath (Join-Path $runtime 'LICENSE')
        Assert-Throws { Assert-ZkPortableRuntimeInventory -RuntimeRoot $runtime -StateRoot $owned.Path -Inventory $inventory } 'missing|inventory'
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

Invoke-Test 'runtime root is derived from exact packaged layout and refuses a sibling prefix' {
    $owned = New-ZkOwnedStateRoot
    try {
        $runtime = Join-Path $owned.Path 'PhantomBugz\a'
        $identity = [pscustomobject]@{ ExecutablePath = Join-Path $runtime 'target\release\zombie-killer.exe' }
        Assert-Equal $runtime (Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $identity -StateRoot $owned.Path) 'runtime ancestor must be exact'
        $outside = [pscustomobject]@{ ExecutablePath = Join-Path ($owned.Path + '-sibling') 'target\release\zombie-killer.exe' }
        Assert-Throws { Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $outside -StateRoot $owned.Path } 'outside|confined'
        $wrong = [pscustomobject]@{ ExecutablePath = Join-Path $runtime 'zombie-killer.exe' }
        Assert-Throws { Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $wrong -StateRoot $owned.Path } 'layout'
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

Invoke-Test 'diagnostic acceptance requires exact metadata, successful exit, and removed confined runtime' {
    $owned = New-ZkOwnedStateRoot
    try {
        $archive = Join-Path $owned.Path 'fixture.zip'
        New-TestArchive $archive @{ 'LICENSE' = 'abc' }
        $inventory = Get-ZkPortableArchiveInventory -ArchivePath $archive
        $expectedHash = 'a' * 64
        $metadata = @{ runtime_root = (Join-Path $owned.Path 'PhantomBugz\check'); files = 1; total_bytes = 3; payload_sha256 = $expectedHash; cleanup = $true }
        $json = $metadata | ConvertTo-Json -Compress
        $result = Assert-ZkPortableCheckResult -Json $json -ExitCode 0 -StateRoot $owned.Path -Inventory $inventory -ExpectedPayloadSha256 $expectedHash
        Assert-Equal 1 $result.files 'successful diagnostic must preserve count'
        Assert-Throws { Assert-ZkPortableCheckResult -Json $json -ExitCode 7 -StateRoot $owned.Path -Inventory $inventory } 'exit'
        Assert-Throws { Assert-ZkPortableCheckResult -Json $json -ExitCode 0 -StateRoot $owned.Path -Inventory $inventory -ExpectedPayloadSha256 ('b' * 64) } 'payload'
        foreach ($change in @(@{ files = 2 }, @{ total_bytes = 4 }, @{ cleanup = $false }, @{ cleanup = 'true' }, @{ payload_sha256 = 'invalid' }, @{ runtime_root = ($owned.Path + '-sibling\x') })) {
            $bad = $metadata.Clone()
            foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
            Assert-Throws { Assert-ZkPortableCheckResult -Json ($bad | ConvertTo-Json -Compress) -ExitCode 0 -StateRoot $owned.Path -Inventory $inventory } 'metadata|cleanup|payload|confined|outside'
        }
        [IO.Directory]::CreateDirectory($metadata.runtime_root) | Out-Null
        Assert-Throws { Assert-ZkPortableCheckResult -Json $json -ExitCode 0 -StateRoot $owned.Path -Inventory $inventory } 'cleanup|remain'
        Assert-Throws { Assert-ZkPortableCheckResult -Json 'not json' -ExitCode 0 -StateRoot $owned.Path -Inventory $inventory } 'JSON'
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

Invoke-Test 'readiness report preserves each UI gate and window observation through JSON' {
    $names = @('Local engine · native actions', 'Coverage status', 'Made by PhantomBugz')
    $evidence = New-ZkPortableReadinessEvidence -Names $names -MainWindowHandle 42 -WindowOffscreen $false -CausalEngineObserved $true
    $roundTrip = $evidence | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    Assert-Equal 'ready' $roundTrip.UIState 'native readiness must be preserved'
    Assert-True $roundTrip.CreatorCredit 'creator credit must be recorded independently'
    Assert-Equal 3 $roundTrip.NameCount 'name count must reflect the actual observation'
    Assert-Equal 42 $roundTrip.MainWindowHandle 'exact sampled window handle must be retained'
    Assert-Equal $false $roundTrip.WindowOffscreen 'available offscreen observation must be preserved'
    Assert-True $roundTrip.CausalEngineObserved 'engine gate must be recorded independently'
    Assert-Equal 'Made by PhantomBugz' $roundTrip.UiNames[2] 'UI name evidence must survive report serialization'
    $missing = New-ZkPortableReadinessEvidence -Names @()
    Assert-Equal 'pending' $missing.UIState 'empty accessibility observation must remain pending'
    Assert-True (-not $missing.CreatorCredit) 'empty observation must not claim creator credit'
    Assert-Equal 0 $missing.NameCount 'empty observation count must be zero'
    Assert-Equal 0 $missing.MainWindowHandle 'unknown window must not invent a handle'
    Assert-True ($null -eq $missing.WindowOffscreen) 'unavailable offscreen status must remain unknown'
    $withoutCredit = New-ZkPortableReadinessEvidence -Names @('Local engine · native actions', 'Coverage status')
    Assert-Equal 'ready' $withoutCredit.UIState 'native readiness must not be combined with credit gate'
    Assert-True (-not $withoutCredit.CreatorCredit) 'missing creator credit must be visible despite native readiness'
}

Invoke-Test 'failed diagnostic process captures stderr, exit code, and remains isolated from user state' {
    $owned = New-ZkOwnedStateRoot
    try {
        $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $owned.Path
        foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', '[Console]::Error.WriteLine("controlled failure"); exit 9')) { $startInfo.ArgumentList.Add($argument) }
        $result = Invoke-ZkPortableDiagnosticProcess -StartInfo $startInfo -TimeoutSeconds 10
        Assert-Equal 9 $result.ExitCode 'diagnostic nonzero exit must be retained'
        Assert-True ($result.Stderr -match 'controlled failure') 'diagnostic stderr must be captured'
        Assert-True (-not $result.GuiObserved) 'noninteractive diagnostic must not show GUI'
        Assert-True $result.Settled 'all diagnostic job members must have exited before returning'
    }
    finally { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
}

if ($IsWindows) {
    Invoke-Test 'settlement diagnostic bounds membership and omits child and window text' {
        $run = New-TestSettlementSnapshot -MemberPids ([uint32[]] (1..40)) -CapturedCount 40 -WindowTitle "secret-window`ntext"
        $diagnostic = Get-ZkPortableSettlementDiagnostic -Run $run
        Assert-True ($diagnostic.Contains('job_member_count=40')) 'complete job count must remain visible'
        Assert-True ($diagnostic.Contains('captured_live_count=40')) 'complete captured live count must remain visible'
        Assert-True ($diagnostic.Contains('job_member_sample_truncated=True')) 'job sample must declare truncation'
        Assert-True ($diagnostic.Contains('captured_live_sample_truncated=True')) 'captured sample must declare truncation'
        $memberSample = [regex]::Match($diagnostic, 'job_member_pids=([^;]*)').Groups[1].Value
        $capturedSample = [regex]::Match($diagnostic, 'captured_live=([^;]*)').Groups[1].Value
        Assert-Equal 16 @($memberSample.Split(',')).Count 'at most 16 job PIDs may enter a log'
        Assert-Equal 16 @($capturedSample.Split(',')).Count 'at most 16 captured identities may enter a log'
        Assert-True ($diagnostic -notmatch 'secret|image-name') 'child names, unknown kinds, and window text must not enter a log'
    }

    Invoke-Test 'settlement diagnostic handles DWORD PID and classifies only known wrapper dialog' {
        $run = New-TestSettlementSnapshot -MemberPids ([uint32[]] @([uint32]::MaxValue)) -CapturedCount 1 -WindowTitle 'Zombie Killer — PhantomBugz'
        $diagnostic = Get-ZkPortableSettlementDiagnostic -Run $run
        Assert-True ($diagnostic.Contains('job_member_pids=4294967295')) 'DWORD PID must not overflow signed int'
        Assert-True ($diagnostic.Contains('wrapper_window_present=True')) 'wrapper window presence must be visible'
        Assert-True ($diagnostic.Contains('wrapper_error_dialog=True')) 'only the exact fixed wrapper title may be classified'
        $run.Registry.Values | ForEach-Object { $_.Process.MainWindowTitle = 'Zombie Killer — PhantomBugz altered' }
        $diagnostic = Get-ZkPortableSettlementDiagnostic -Run $run
        Assert-True ($diagnostic.Contains('wrapper_error_dialog=False')) 'a near-match title must not be classified as the fixed dialog'
    }

    Invoke-Test 'settlement diagnostic classifies only exact live descendant image names without logging them' {
        $run = New-TestSettlementSnapshot -MemberPids ([uint32[]] (1..4)) -CapturedCount 4 -WindowTitle 'secret-window'
        foreach ($record in $run.Registry.Values) {
            if ($record.Identity.Pid -in @(1, 2, 3)) {
                $record.Identity.ExecutablePath = Join-Path $PSScriptRoot 'msedgewebview2.exe'
            }
        }
        $diagnostic = Get-ZkPortableSettlementDiagnostic -Run $run
        Assert-True ($diagnostic.Contains('webview2_name_count=1')) 'only non-wrapper descendants with exact WebView2 image name count'
        Assert-True ($diagnostic.Contains('other_descendant_count=1')) 'other descendants remain visible as a count'
        Assert-True ($diagnostic -notmatch 'msedgewebview2.exe|secret-image-name.exe|secret-window') 'names and window text must not enter a log'
    }

    Invoke-Test 'settlement diagnostic reports exact retained job member state' {
        $owned = New-ZkOwnedStateRoot
        $launch = $null
        $process = $null
        $identity = $null
        $registry = New-ZkCaptureRegistry
        try {
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $owned.Path
            foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) { $startInfo.ArgumentList.Add($argument) }
            $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
            $process = Get-Process -Id ([int] $launch.ProcessId)
            $identity = Get-ZkProcessIdentity -Process $process
            Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $identity
            $record = Add-ZkCapturedRecord -Registry $registry -Identity $identity -Process $process -Kind descendant
            $run = [pscustomobject]@{
                Launch = $launch; Registry = $registry; WrapperIdentity = $identity
                NativeRecord = $record; RuntimeRoot = $owned.Path
            }
            $diagnostic = Get-ZkPortableSettlementDiagnostic -Run $run
            Assert-True ($diagnostic.Contains('wrapper_active=True')) 'live exact wrapper must be reported'
            Assert-True ($diagnostic.Contains('native_active=True')) 'live exact native record must be reported'
            Assert-True ($diagnostic.Contains("job_member_pids=$($identity.Pid)")) 'job member PID must come from the retained job'
            Assert-True ($diagnostic.Contains("captured_live=$($identity.Pid):descendant")) 'captured member must be reported with exact identity and kind'
            Assert-True ($diagnostic.Contains('runtime_exists=True')) 'owned runtime existence must be reported'
        }
        finally {
            if ($null -ne $identity) { Stop-ZkExactProcess -Identity $identity | Out-Null }
            elseif ($null -ne $launch) { $launch.TerminateLaunchedProcess(5000) | Out-Null }
            if ($null -ne $process -and $registry.Count -eq 0) { $process.Dispose() }
            if ($null -ne $launch) {
                Assert-True (Test-ZkLaunchSettled -Launch $launch) 'diagnostic fixture must fully settle'
                $launch.Dispose()
            }
            Dispose-ZkCaptureRegistry -Registry $registry
            Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken
        }
    }

    Invoke-Test 'portable CLI preserves the explicitly supplied executable while importing native helpers' {
        $owned = New-ZkOwnedStateRoot
        $result = $null
        try {
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $owned.Path
            $startInfo.Environment['ZK_DISPOSABLE_WINDOWS_PROFILE'] = '1'
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $harness,
                '-ExecutablePath', (Join-Path $owned.Path 'missing wrapper.exe'),
                '-ArchivePath', (Join-Path $owned.Path 'unused.zip'), '-ReportPath', (Join-Path $owned.Path 'unused.json'))) {
                $startInfo.ArgumentList.Add($argument)
            }
            $result = Invoke-ZkPortableDiagnosticProcess -StartInfo $startInfo -TimeoutSeconds 10
            Assert-True ($result.ExitCode -ne 0) 'missing wrapper must fail the real CLI'
            Assert-True ($result.Stderr -match 'Portable wrapper executable is missing') 'CLI must reach executable validation with the supplied nonempty path'
            Assert-True ($result.Stderr -notmatch 'empty string') 'native helper import must not clobber portable CLI parameters'
        }
        finally {
            if ($null -ne $result -and $result.Settled) { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
        }
    }

    Invoke-Test 'diagnostic rejects and exactly cleans a lingering child with closed output pipes' {
        $owned = New-ZkOwnedStateRoot
        $otherLaunch = $null
        $otherProcess = $null
        $otherIdentity = $null
        $childIdentity = $null
        $identityFile = Join-Path $owned.Path 'diagnostic-child.json'
        try {
            $pwsh = (Get-Process -Id $PID).Path
            $otherStart = New-ZkSanitizedStartInfo -ExecutablePath $pwsh -StateRoot $owned.Path
            foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) { $otherStart.ArgumentList.Add($argument) }
            $otherLaunch = Start-ZkJobBoundProcess -StartInfo $otherStart
            $otherProcess = Get-Process -Id ([int] $otherLaunch.ProcessId)
            $otherIdentity = Get-ZkProcessIdentity -Process $otherProcess
            Assert-ZkRetainedLaunchIdentity -Launch $otherLaunch -Identity $otherIdentity
            $escapedPwsh = $pwsh.Replace("'", "''")
            $escapedFile = $identityFile.Replace("'", "''")
            $readyFile = Join-Path $owned.Path 'child-pipes-closed'
            $childCode = @'
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class PipeFixture { [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int kind); [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle); }'
[PipeFixture]::CloseHandle([PipeFixture]::GetStdHandle(-11)) | Out-Null
[PipeFixture]::CloseHandle([PipeFixture]::GetStdHandle(-12)) | Out-Null
[IO.File]::WriteAllText((Join-Path $env:LOCALAPPDATA 'child-pipes-closed'), 'closed')
Start-Sleep -Seconds 60
'@
            $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode))
            $escapedHelper = (Join-Path $PSScriptRoot '..\native-smoke.ps1').Replace("'", "''")
            # JobLaunch uses bInheritHandles=false. Its nested child job is also a member of
            # the diagnostic's outer job, but cannot retain the target's stdout/stderr pipes.
            $command = '. ''' + $escapedHelper + '''; $s=New-ZkSanitizedStartInfo -ExecutablePath ''' + $escapedPwsh + ''' -StateRoot $env:LOCALAPPDATA; foreach($a in @(''-NoProfile'',''-NonInteractive'',''-EncodedCommand'',''' + $encodedChild + ''')){$s.ArgumentList.Add($a)}; $childLaunch=Start-ZkJobBoundProcess -StartInfo $s; $p=Get-Process -Id ([int]$childLaunch.ProcessId); $id=Get-ZkProcessIdentity -Process $p; [IO.File]::WriteAllText(''' + $escapedFile + ''',($id | ConvertTo-Json)); $deadline=[DateTime]::UtcNow.AddSeconds(5); while(-not(Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA ''child-pipes-closed''))){ if([DateTime]::UtcNow -gt $deadline){throw ''Child did not close pipes''}; Start-Sleep -Milliseconds 20 }; [Console]::Out.Write(''{"cleanup":true}''); exit 0'
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $pwsh -StateRoot $owned.Path
            foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', $command)) { $startInfo.ArgumentList.Add($argument) }
            Assert-Throws { Invoke-ZkPortableDiagnosticProcess -StartInfo $startInfo -TimeoutSeconds 10 } 'descendant|settle|job'
            Assert-True (Test-Path -LiteralPath $identityFile) 'controlled target must have spawned its child'
            Assert-True (Test-Path -LiteralPath $readyFile) 'controlled child must explicitly close its stdout/stderr handles'
            $hostResults = @(Get-ChildItem -LiteralPath $owned.Path -Recurse -Filter result.json)
            Assert-Equal 1 $hostResults.Count 'closed target pipes must allow a completed host result before descendant rejection'
            $hostResult = [IO.File]::ReadAllText($hostResults[0].FullName) | ConvertFrom-Json
            Assert-Equal 0 $hostResult.ExitCode 'target must complete successfully even while its closed-pipe child lingers'
            $childIdentity = [IO.File]::ReadAllText($identityFile) | ConvertFrom-Json
            $child = Get-ZkMatchingProcess -Identity $childIdentity
            if ($null -ne $child) { $child.Dispose(); throw 'diagnostic rejection must clean its exact lingering child' }
            $other = Get-ZkMatchingProcess -Identity $otherIdentity
            Assert-True ($null -ne $other) 'diagnostic cleanup must leave the separate job untouched'
            $other.Dispose()
        }
        finally {
            if ($null -eq $childIdentity -and (Test-Path -LiteralPath $identityFile)) { $childIdentity = [IO.File]::ReadAllText($identityFile) | ConvertFrom-Json }
            if ($null -ne $childIdentity) { Stop-ZkExactProcess -Identity $childIdentity | Out-Null }
            if ($null -ne $otherIdentity) { Stop-ZkExactProcess -Identity $otherIdentity | Out-Null }
            elseif ($null -ne $otherLaunch) { $otherLaunch.TerminateLaunchedProcess(5000) | Out-Null }
            $otherSettled = $null -eq $otherLaunch -or (Test-ZkLaunchSettled -Launch $otherLaunch)
            if ($otherSettled) { Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken }
            if ($null -ne $otherProcess) { $otherProcess.Dispose() }
            if ($null -ne $otherLaunch) { $otherLaunch.Dispose() }
        }
    }

    Invoke-Test 'first portable run accepts an empty ownership list and retains a failed controlled launch' {
        $owned = New-ZkOwnedStateRoot
        $runs = [Collections.Generic.List[object]]::new()
        try {
            $inventory = [pscustomobject]@{ Files = @{}; TotalBytes = 0 }
            # rundll32.exe with no arguments silently exits without loading a DLL or showing UI.
            Assert-Throws {
                Start-ZkPortableRun -ExecutablePath (Join-Path $env:SystemRoot 'System32\rundll32.exe') -StateRoot $owned.Path -Runs $runs -Inventory $inventory
            } 'process|exited'
            Assert-Equal 1 $runs.Count 'ownership must be registered even if the fixture exits before readiness'
            foreach ($run in $runs) {
                if (-not (Test-ZkLaunchSettled -Launch $run.Launch)) {
                    $run.Launch.TerminateLaunchedProcess(5000) | Out-Null
                }
            }
        }
        finally {
            foreach ($run in $runs) {
                Stop-ZkTrackedLaunchExactly -Launch $run.Launch -Registry $run.Registry -ApplicationPath $run.ApplicationPath -EnginePath $run.EnginePath | Out-Null
            }
            Remove-ZkPortableSmokeState -OwnedState $owned -Runs @($runs.ToArray()) | Out-Null
            foreach ($run in $runs) { Dispose-ZkCaptureRegistry -Registry $run.Registry; $run.Launch.Dispose() }
        }
    }

    Invoke-Test 'test ownership survives a capture failure and exactly settles its retained launch' {
        $owned = New-ZkOwnedStateRoot
        $runs = [Collections.Generic.List[object]]::new()
        try {
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $owned.Path
            foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) { $startInfo.ArgumentList.Add($argument) }
            $run = Start-TestOwnedJob -StartInfo $startInfo -Runs $runs -ApplicationPath $startInfo.FileName
            Assert-Throws { throw 'controlled identity capture failure' } 'capture failure'
            Assert-Equal 1 $runs.Count 'launch ownership must precede any fallible identity capture'
            Assert-True $run.Launch.IsLaunchedProcessActive() 'controlled retained launch must be live before fallback cleanup'
            Assert-True (-not (Remove-ZkPortableSmokeState -OwnedState $owned -Runs @($runs.ToArray()))) 'unbound but live launch must retain state'
        }
        finally {
            Assert-True (Stop-TestOwnedJobs -OwnedState $owned -Runs $runs) 'retained launch fallback must settle before removing state'
        }
    }

    Invoke-Test 'job discovery captures only its own confined native fixture and cleanup leaves other job alive' {
        $owned = New-ZkOwnedStateRoot
        $runs = [Collections.Generic.List[object]]::new()
        try {
            Initialize-ZkNativeJobType
            foreach ($name in @('first', 'second')) {
                $runtime = Join-Path $owned.Path "PhantomBugz\$name"
                $native = Join-Path $runtime 'target\release\zombie-killer.exe'
                [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($native)) | Out-Null
                Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $native
                $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $owned.Path
                $escapedNative = $native.Replace("'", "''")
                $command = '$p=Start-Process -FilePath ''' + $escapedNative + ''' -ArgumentList ''/d /c powershell.exe -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"'' -PassThru -WindowStyle Hidden; $p.WaitForExit()'
                foreach ($argument in @('-NoProfile', '-NonInteractive', '-Command', $command)) { $startInfo.ArgumentList.Add($argument) }
                $run = Start-TestOwnedJob -StartInfo $startInfo -Runs $runs -ApplicationPath $native
                $process = Get-Process -Id ([int] $run.Launch.ProcessId)
                try {
                    $identity = Get-ZkProcessIdentity -Process $process
                    Assert-ZkRetainedLaunchIdentity -Launch $run.Launch -Identity $identity
                    Add-ZkCapturedRecord -Registry $run.Registry -Identity $identity -Process $process -Kind descendant | Out-Null
                    $run.WrapperIdentity = $identity
                }
                catch { $process.Dispose(); throw }
                $deadline = [DateTime]::UtcNow.AddSeconds(10)
                do {
                    $record = Get-ZkPortableNativeRecord -Run $run -StateRoot $owned.Path
                    if ($null -ne $record) { break }
                    Start-Sleep -Milliseconds 50
                } while ([DateTime]::UtcNow -lt $deadline)
                Assert-True ($null -ne $record) 'live confined native fixture must be discovered'
                Assert-Equal $native $record.Identity.ExecutablePath 'discovery must use the exact fixture path'
                $run.NativeRecord = $record
                $run.RuntimeRoot = Resolve-ZkPortableRuntimeRoot -ApplicationIdentity $record.Identity -StateRoot $owned.Path
            }
            Assert-True ($runs[0].NativeRecord.Identity.Pid -ne $runs[1].NativeRecord.Identity.Pid) 'jobs must discover distinct instances'
            Assert-True (-not (Test-ZkPathEqual -Left $runs[0].RuntimeRoot -Right $runs[1].RuntimeRoot)) 'concurrent fixtures must have distinct runtime roots'
            Assert-True (-not (Remove-ZkPortableSmokeState -OwnedState $owned -Runs @($runs.ToArray()))) 'live launch must preserve owned state'
            Assert-True (Test-Path -LiteralPath $owned.Path) 'unsettled state must remain'
            $first = $runs[0]
            Assert-True (Stop-ZkTrackedLaunchExactly -Launch $first.Launch -Registry $first.Registry -ApplicationPath $first.ApplicationPath -EnginePath $first.EnginePath) 'first exact job must settle'
            $other = Get-ZkMatchingProcess -Identity $runs[1].NativeRecord.Identity
            Assert-True ($null -ne $other) 'cleanup must leave independent job native process live'
            $other.Dispose()
            $second = $runs[1]
            Assert-True (Stop-ZkTrackedLaunchExactly -Launch $second.Launch -Registry $second.Registry -ApplicationPath $second.ApplicationPath -EnginePath $second.EnginePath) 'second exact job must settle'
            Assert-True (Remove-ZkPortableSmokeState -OwnedState $owned -Runs @($runs.ToArray())) 'settled jobs allow marked state removal'
            Assert-True (-not (Test-Path -LiteralPath $owned.Path)) 'settled owned state must be removed'
        }
        finally {
            if (-not (Stop-TestOwnedJobs -OwnedState $owned -Runs $runs)) { Write-Warning "Controlled fixture state retained at '$($owned.Path)' because its launch did not settle." }
        }
    }
}

Write-Host "RESULT: $script:Passed passed, $script:Failed failed"
if ($script:Failed -gt 0) { exit 1 }
