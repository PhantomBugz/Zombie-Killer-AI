[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\native-smoke.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool] $Condition,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [AllowNull()]
        [object] $Expected,

        [AllowNull()]
        [object] $Actual,

        [Parameter(Mandatory)]
        [string] $Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message (expected '$Expected', got '$Actual')"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Body,

        [Parameter(Mandatory)]
        [string] $MessagePattern
    )

    try {
        & $Body
    }
    catch {
        if ($_.Exception.Message -notmatch $MessagePattern) {
            throw "Expected error matching '$MessagePattern', got '$($_.Exception.Message)'"
        }
        return
    }
    throw "Expected an error matching '$MessagePattern'."
}

function Invoke-Test {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [scriptblock] $Body
    )

    try {
        & $Body
        $script:Passed += 1
        Write-Host "PASS: $Name"
    }
    catch {
        $script:Failed += 1
        Write-Host "FAIL: $Name"
        Write-Host $_.Exception.Message
    }
}

if ($IsWindows) {
    Invoke-Test 'native smoke requires a declared disposable Windows profile' {
        $previous = [Environment]::GetEnvironmentVariable('ZK_DISPOSABLE_WINDOWS_PROFILE', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('ZK_DISPOSABLE_WINDOWS_PROFILE', $null, 'Process')
            Assert-Throws { Assert-ZkDisposableWindowsProfile } 'disposable Windows profile'
            [Environment]::SetEnvironmentVariable('ZK_DISPOSABLE_WINDOWS_PROFILE', '0', 'Process')
            Assert-Throws { Assert-ZkDisposableWindowsProfile } 'disposable Windows profile'
            [Environment]::SetEnvironmentVariable('ZK_DISPOSABLE_WINDOWS_PROFILE', '1', 'Process')
            Assert-ZkDisposableWindowsProfile
        }
        finally {
            [Environment]::SetEnvironmentVariable('ZK_DISPOSABLE_WINDOWS_PROFILE', $previous, 'Process')
        }
    }
}

function Start-Sleeper {
    $pwshPath = (Get-Process -Id $PID).Path
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshPath
    $startInfo.UseShellExecute = $false
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) {
        $startInfo.ArgumentList.Add($argument)
    }
    return [Diagnostics.Process]::Start($startInfo)
}

function Stop-TestProcess {
    param(
        [AllowNull()]
        [System.Diagnostics.Process] $Process
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if (-not $Process.HasExited) {
            $Process.Kill()
            $Process.WaitForExit(5000) | Out-Null
        }
    }
    catch {
        # Best-effort cleanup for a process created and retained by this test only.
    }
    finally {
        $Process.Dispose()
    }
}

Invoke-Test 'captures and revalidates PID, creation time, and executable path' {
    $child = $null
    try {
        $child = Start-Sleeper
        $identity = Get-ZkProcessIdentity -Process $child

        Assert-Equal $child.Id $identity.Pid 'identity must contain the child PID'
        Assert-True ($identity.StartTimeUtcTicks -gt 0) 'identity must contain a creation timestamp'
        Assert-True ([IO.Path]::IsPathFullyQualified($identity.ExecutablePath)) 'identity path must be absolute'

        $matched = Get-ZkMatchingProcess -Identity $identity
        Assert-True ($null -ne $matched) 'the live exact identity must match'
        try {
            Assert-Equal $child.Id $matched.Id 'the matching handle must reference the exact PID'
        }
        finally {
            $matched.Dispose()
        }

        $wrongTime = [pscustomobject]@{
            Pid = $identity.Pid
            StartTimeUtcTicks = $identity.StartTimeUtcTicks + 1
            ExecutablePath = $identity.ExecutablePath
        }
        Assert-True ($null -eq (Get-ZkMatchingProcess -Identity $wrongTime)) 'a changed creation time must fail closed'

        $wrongPath = [pscustomobject]@{
            Pid = $identity.Pid
            StartTimeUtcTicks = $identity.StartTimeUtcTicks
            ExecutablePath = (Join-Path ([IO.Path]::GetDirectoryName($identity.ExecutablePath)) 'not-the-process.exe')
        }
        Assert-True ($null -eq (Get-ZkMatchingProcess -Identity $wrongPath)) 'a changed executable path must fail closed'
    }
    finally {
        Stop-TestProcess -Process $child
    }
}

Invoke-Test 'exact cleanup refuses a mismatched identity and stops only a matching instance' {
    $child = $null
    try {
        $child = Start-Sleeper
        $identity = Get-ZkProcessIdentity -Process $child
        $wrongIdentity = [pscustomobject]@{
            Pid = $identity.Pid
            StartTimeUtcTicks = $identity.StartTimeUtcTicks + 1
            ExecutablePath = $identity.ExecutablePath
        }

        Assert-True (-not (Stop-ZkExactProcess -Identity $wrongIdentity)) 'cleanup must refuse a changed process instance'
        $child.Refresh()
        Assert-True (-not $child.HasExited) 'mismatch refusal must leave the process running'

        Assert-True (Stop-ZkExactProcess -Identity $identity) 'cleanup must stop the exact captured instance'
        Assert-True ($child.WaitForExit(5000)) 'the exact child must exit after cleanup'
    }
    finally {
        Stop-TestProcess -Process $child
    }
}

Invoke-Test 'exact cleanup never tree-kills an uncaptured descendant' {
    $parent = $null
    $childIdentity = $null
    try {
        $pwshPath = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'fixtures\native-smoke-process-tree.ps1'
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $pwshPath
        $startInfo.UseShellExecute = $false
        foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fixture)) {
            $startInfo.ArgumentList.Add($argument)
        }
        $parent = [Diagnostics.Process]::Start($startInfo)
        $parentIdentity = Get-ZkProcessIdentity -Process $parent

        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $matches = @(Get-ZkDescendantIdentitySnapshot -RootIdentity $parentIdentity |
                Where-Object { Test-ZkPathEqual -Left $_.ExecutablePath -Right $pwshPath } |
                Select-Object -First 1)
            if ($matches.Count -gt 0) {
                $childIdentity = $matches[0]
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        Assert-True ($null -ne $childIdentity) 'the fixture must expose its PowerShell child'

        Assert-True (Stop-ZkExactProcess -Identity $parentIdentity) 'the exact parent must stop'
        $childMatch = Get-ZkMatchingProcess -Identity $childIdentity
        Assert-True ($null -ne $childMatch) 'stopping one identity must leave an uncaptured child alive'
        if ($null -ne $childMatch) {
            $childMatch.Dispose()
        }
    }
    finally {
        if ($null -ne $childIdentity) {
            Stop-ZkExactProcess -Identity $childIdentity | Out-Null
        }
        Stop-TestProcess -Process $parent
    }
}

Invoke-Test 'descendant graph excludes unrelated PIDs and terminates on cycles' {
    $created = [DateTime]::SpecifyKind([DateTime]'2026-08-13T12:00:00', [DateTimeKind]::Utc)
    $rows = @(
        [pscustomobject]@{ ProcessId = 20; ParentProcessId = 10; CreationDate = $created; ExecutablePath = 'C:\fixture\child.exe' },
        [pscustomobject]@{ ProcessId = 30; ParentProcessId = 20 },
        [pscustomobject]@{ ProcessId = 40; ParentProcessId = 10 },
        [pscustomobject]@{ ProcessId = 50; ParentProcessId = 999 },
        [pscustomobject]@{ ProcessId = 60; ParentProcessId = 70 },
        [pscustomobject]@{ ProcessId = 70; ParentProcessId = 60 }
    )

    $descendants = @(Get-ZkDescendantPidDepth -RootPid 10 -ProcessRows $rows)
    Assert-Equal 3 $descendants.Count 'only the root lineage must be selected'
    Assert-Equal '20:1,30:2,40:1' (($descendants | Sort-Object Pid | ForEach-Object { "$($_.Pid):$($_.Depth)" }) -join ',') 'depth must follow the parent graph'
    $first = $descendants | Where-Object Pid -eq 20
    Assert-Equal $created.Ticks $first.SnapshotStartTimeUtcTicks 'CIM creation identity must travel with the graph node'
    Assert-Equal 'C:\fixture\child.exe' $first.SnapshotExecutablePath 'CIM executable identity must travel with the graph node'
}

Invoke-Test 'descendant graph rejects a child older than a reused parent instance' {
    $rootStart = [DateTime]'2026-08-13T12:00:00Z'
    $parentStart = $rootStart.AddSeconds(10)
    $rows = @(
        [pscustomobject]@{ ProcessId = 20; ParentProcessId = 10; CreationDate = $parentStart; ExecutablePath = 'C:\fixture\parent.exe' },
        [pscustomobject]@{ ProcessId = 30; ParentProcessId = 20; CreationDate = $rootStart.AddSeconds(5); ExecutablePath = 'C:\fixture\stale-child.exe' },
        [pscustomobject]@{ ProcessId = 31; ParentProcessId = 20; CreationDate = $parentStart.AddSeconds(1); ExecutablePath = 'C:\fixture\valid-child.exe' }
    )

    $descendants = @(Get-ZkDescendantPidDepth -RootPid 10 -RootStartTimeUtcTicks $rootStart.ToUniversalTime().Ticks -ProcessRows $rows)
    Assert-Equal '20,31' (($descendants | Sort-Object Pid | ForEach-Object Pid) -join ',') 'stale ParentProcessId edges must not cross a reused parent instance'
}

Invoke-Test 'live descendant snapshot binds every child to an exact process identity' {
    $parent = $null
    $identities = @()
    try {
        $pwshPath = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'fixtures\native-smoke-process-tree.ps1'
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $pwshPath
        $startInfo.UseShellExecute = $false
        $startInfo.ArgumentList.Add('-NoLogo')
        $startInfo.ArgumentList.Add('-NoProfile')
        $startInfo.ArgumentList.Add('-NonInteractive')
        $startInfo.ArgumentList.Add('-File')
        $startInfo.ArgumentList.Add($fixture)
        $parent = [Diagnostics.Process]::Start($startInfo)
        $rootIdentity = Get-ZkProcessIdentity -Process $parent

        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        $identities = @()
        do {
            $identities = @(Get-ZkDescendantIdentitySnapshot -RootIdentity $rootIdentity)
            if ($identities.Count -gt 0) {
                break
            }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)

        Assert-True ($identities.Count -gt 0) 'the retained parent fixture must expose at least one descendant'
        foreach ($identity in $identities) {
            $matched = Get-ZkMatchingProcess -Identity $identity
            Assert-True ($null -ne $matched) 'every returned descendant must still match PID, time, and path'
            if ($null -ne $matched) {
                $matched.Dispose()
            }
            Assert-True ($identity.Depth -gt 0) 'every descendant must have positive depth'
        }
    }
    finally {
        foreach ($identity in @($identities | Sort-Object Depth -Descending)) {
            Stop-ZkExactProcess -Identity $identity | Out-Null
        }
        Stop-TestProcess -Process $parent
    }
}

if ($IsWindows) {
    Invoke-Test 'job-bound launch records a late descendant before it can escape observation' {
        $launch = $null
        $parent = $null
        $childIdentity = $null
        $stateRoot = $null
        $captured = $null
        try {
            $pwshPath = (Get-Process -Id $PID).Path
            $fixture = Join-Path $PSScriptRoot 'fixtures\native-smoke-process-tree.ps1'
            $stateRoot = Join-Path ([IO.Path]::GetTempPath()) "zk-job-launch-test-$([guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $stateRoot | Out-Null
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $pwshPath -StateRoot $stateRoot
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fixture, '-ChildDelayMilliseconds', '500')) {
                $startInfo.ArgumentList.Add($argument)
            }

            $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
            $parent = Get-Process -Id $launch.ProcessId -ErrorAction Stop
            $parentIdentity = Get-ZkProcessIdentity -Process $parent
            $captured = New-ZkCaptureRegistry
            Add-ZkCapturedRecord -Registry $captured -Identity $parentIdentity -Process $parent -Kind 'application' | Out-Null

            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                Sync-ZkJobCaptures -Launch $launch -Registry $captured -ApplicationPath $pwshPath -EnginePath 'C:\not-an-engine.exe'
                $childRecord = @($captured.Values | Where-Object {
                    $_.Identity.Pid -ne $parentIdentity.Pid -and
                    (Test-ZkPathEqual -Left $_.Identity.ExecutablePath -Right $pwshPath)
                } | Select-Object -First 1)
                if ($childRecord.Count -gt 0) { $childIdentity = $childRecord[0].Identity }
                if ($null -ne $childIdentity) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)

            Assert-True ($null -ne $childIdentity) 'the delayed PowerShell child must appear in the job membership ledger'
            Assert-True (Stop-ZkExactProcess -Identity $parentIdentity) 'the exact parent fixture must stop'
            $childMatch = Get-ZkMatchingProcess -Identity $childIdentity
            Assert-True ($null -ne $childMatch) 'the late child must remain independently observable after its parent exits'
            if ($null -ne $childMatch) { $childMatch.Dispose() }
            Assert-True (@($launch.GetProcessIds()) -contains [uint32] $childIdentity.Pid) 'the job must continue reporting the surviving late child'
            Assert-True (-not (Test-ZkLaunchSettled -Launch $launch)) 'a surviving late descendant must prevent launch settlement'
            Assert-True (Stop-ZkExactProcess -Identity $childIdentity) 'the exact late child fixture must stop independently'
            $settleDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while (-not (Test-ZkLaunchSettled -Launch $launch) -and [DateTime]::UtcNow -lt $settleDeadline) {
                Start-Sleep -Milliseconds 20
            }
            Assert-True (Test-ZkLaunchSettled -Launch $launch) 'an empty job and ended retained launch must prove settlement'
        }
        finally {
            if ($null -ne $childIdentity) { Stop-ZkExactProcess -Identity $childIdentity | Out-Null }
            if ($null -ne $captured) { Dispose-ZkCaptureRegistry -Registry $captured }
            if ($null -ne $launch) {
                $launch.TerminateLaunchedProcess(5000) | Out-Null
                $launch.Dispose()
            }
            if ($null -eq $captured) { Stop-TestProcess -Process $parent }
            if ($null -ne $stateRoot -and (Test-Path -LiteralPath $stateRoot)) {
                Remove-Item -LiteralPath $stateRoot -Recurse -Force
            }
        }
    }

    Invoke-Test 'retained launch handle recovers an initial identity-capture failure without touching a sibling' {
        $launch = $null
        $sibling = $null
        $launched = $null
        $stateRoot = $null
        try {
            $sibling = Start-Sleeper
            $siblingIdentity = Get-ZkProcessIdentity -Process $sibling
            $pwshPath = (Get-Process -Id $PID).Path
            $stateRoot = Join-Path ([IO.Path]::GetTempPath()) "zk-job-recovery-test-$([guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $stateRoot | Out-Null
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $pwshPath -StateRoot $stateRoot
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) {
                $startInfo.ArgumentList.Add($argument)
            }
            $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
            $launched = Get-Process -Id $launch.ProcessId -ErrorAction Stop

            # Simulate the bind path throwing before an identity can be entered in the registry.
            Assert-True (-not (Test-ZkLaunchSettled -Launch $launch)) 'live unbound launch must prevent state cleanup'
            Assert-True ($launch.TerminateLaunchedProcess(5000)) 'the original retained process handle must stop the unbound launch'
            Assert-True $launched.WaitForExit(5000) 'the unbound launched process must exit'
            # Process exit and Job Object membership are separate observations.
            # The exact job must drain within a bound before state can be removed.
            $settleDeadline = [DateTime]::UtcNow.AddSeconds(5)
            while (-not (Test-ZkLaunchSettled -Launch $launch) -and [DateTime]::UtcNow -lt $settleDeadline) {
                Start-Sleep -Milliseconds 20
            }
            Assert-True (Test-ZkLaunchSettled -Launch $launch) 'terminated unbound launch with no children must settle'
            $siblingMatch = Get-ZkMatchingProcess -Identity $siblingIdentity
            Assert-True ($null -ne $siblingMatch) 'same-runtime sibling must remain alive'
            if ($null -ne $siblingMatch) { $siblingMatch.Dispose() }
        }
        finally {
            if ($null -ne $launch) { $launch.Dispose() }
            Stop-TestProcess -Process $launched
            Stop-TestProcess -Process $sibling
            if ($null -ne $stateRoot -and (Test-Path -LiteralPath $stateRoot)) {
                Remove-Item -LiteralPath $stateRoot -Recurse -Force
            }
        }
    }

    Invoke-Test 'initial application binding must match the retained native launch handle' {
        $launch = $null
        $process = $null
        $stateRoot = $null
        try {
            $pwshPath = (Get-Process -Id $PID).Path
            $stateRoot = Join-Path ([IO.Path]::GetTempPath()) "zk-job-bind-test-$([guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $stateRoot | Out-Null
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $pwshPath -StateRoot $stateRoot
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60')) {
                $startInfo.ArgumentList.Add($argument)
            }
            $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
            $process = Get-Process -Id $launch.ProcessId -ErrorAction Stop
            $identity = Get-ZkProcessIdentity -Process $process

            Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $identity
            $reusedPidIdentity = [pscustomobject]@{
                Pid = $identity.Pid
                StartTimeUtcTicks = $identity.StartTimeUtcTicks + 1
                ExecutablePath = $identity.ExecutablePath
            }
            Assert-Throws -Body {
                Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $reusedPidIdentity
            } -MessagePattern 'retained native launch handle'
            $replacedPathIdentity = [pscustomobject]@{
                Pid = $identity.Pid
                StartTimeUtcTicks = $identity.StartTimeUtcTicks
                ExecutablePath = Join-Path ([IO.Path]::GetDirectoryName($identity.ExecutablePath)) 'replacement.exe'
            }
            Assert-Throws -Body {
                Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $replacedPathIdentity
            } -MessagePattern 'retained native launch handle'
        }
        finally {
            if ($null -ne $launch) {
                $launch.TerminateLaunchedProcess(5000) | Out-Null
                $launch.Dispose()
            }
            if ($null -ne $process) { $process.Dispose() }
            if ($null -ne $stateRoot -and (Test-Path -LiteralPath $stateRoot)) {
                Remove-Item -LiteralPath $stateRoot -Recurse -Force
            }
        }
    }

    Invoke-Test 'failure cleanup captures and settles a late persistent job descendant exactly' {
        $launch = $null
        $parent = $null
        $registry = $null
        $stateRoot = $null
        try {
            $pwshPath = (Get-Process -Id $PID).Path
            $fixture = Join-Path $PSScriptRoot 'fixtures\native-smoke-process-tree.ps1'
            $stateRoot = Join-Path ([IO.Path]::GetTempPath()) "zk-job-cleanup-test-$([guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $stateRoot | Out-Null
            $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $pwshPath -StateRoot $stateRoot
            foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $fixture, '-ChildDelayMilliseconds', '300')) {
                $startInfo.ArgumentList.Add($argument)
            }
            $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
            $parent = Get-Process -Id $launch.ProcessId -ErrorAction Stop
            $parentIdentity = Get-ZkProcessIdentity -Process $parent
            $registry = New-ZkCaptureRegistry
            Add-ZkCapturedRecord -Registry $registry -Identity $parentIdentity -Process $parent -Kind 'application' | Out-Null

            $childDeadline = [DateTime]::UtcNow.AddSeconds(10)
            while (@($launch.GetProcessIds()).Count -lt 2 -and [DateTime]::UtcNow -lt $childDeadline) {
                Start-Sleep -Milliseconds 20
            }
            Assert-True (@($launch.GetProcessIds()).Count -ge 2) 'the late persistent child must exist before failure cleanup starts'
            Assert-True (Stop-ZkTrackedLaunchExactly -Launch $launch -Registry $registry -ApplicationPath $pwshPath -EnginePath 'C:\not-an-engine.exe' -TimeoutSeconds 10 -PollMilliseconds 20) 'exact cleanup must settle the launch-assigned job'
            Assert-True ($registry.Count -ge 2) 'cleanup must capture the previously untracked late child before stopping it'
            foreach ($record in $registry.Values) {
                $match = Get-ZkMatchingProcess -Identity $record.Identity
                Assert-True ($null -eq $match) 'every exact identity captured by failure cleanup must be gone'
                if ($null -ne $match) { $match.Dispose() }
            }
            Assert-True (Test-ZkLaunchSettled -Launch $launch) 'no process may remain in the launch job after cleanup'
        }
        finally {
            if ($null -ne $registry) {
                foreach ($record in $registry.Values) { Stop-ZkExactProcess -Identity $record.Identity | Out-Null }
                Dispose-ZkCaptureRegistry -Registry $registry
            }
            if ($null -ne $launch) {
                $launch.TerminateLaunchedProcess(5000) | Out-Null
                $launch.Dispose()
            }
            if ($null -eq $registry) { Stop-TestProcess -Process $parent }
            if ($null -ne $stateRoot -and (Test-Path -LiteralPath $stateRoot)) {
                Remove-Item -LiteralPath $stateRoot -Recurse -Force
            }
        }
    }
}

Invoke-Test 'release layout resolves only the expected app and packaged engine files' {
    $root = Join-Path ([IO.Path]::GetTempPath()) "zk-native-layout-test-$([guid]::NewGuid().ToString('N'))"
    try {
        $engineDirectory = Join-Path $root 'engine'
        New-Item -ItemType Directory -Path $engineDirectory -Force | Out-Null
        $app = Join-Path $root 'zombie-killer.exe'
        $engine = Join-Path $engineDirectory 'zombie-killer-engine.exe'
        Set-Content -LiteralPath $app -Value 'fixture' -NoNewline
        Set-Content -LiteralPath $engine -Value 'fixture' -NoNewline

        $layout = Resolve-ZkNativeLayout -ExecutablePath $app
        Assert-True (Test-ZkPathEqual -Left $app -Right $layout.ApplicationPath) 'the exact app path must be retained'
        Assert-True (Test-ZkPathEqual -Left $engine -Right $layout.EnginePath) 'the engine must resolve under the adjacent engine resource directory'

        Remove-Item -LiteralPath $engine -Force
        Assert-Throws -Body { Resolve-ZkNativeLayout -ExecutablePath $app | Out-Null } -MessagePattern 'packaged engine'
    }
    finally {
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}

Invoke-Test 'owned state cleanup requires the exact marker and never removes a sibling' {
    $owned = New-ZkOwnedStateRoot
    $sibling = "$($owned.Path)-sibling"
    New-Item -ItemType Directory -Path $sibling | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $owned.Path 'state.txt') -Value 'owned state'
        Assert-Throws -Body {
            Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken 'not-the-marker'
        } -MessagePattern 'marker'
        Assert-True (Test-Path -LiteralPath $owned.Path) 'a wrong marker must leave the owned root intact'

        Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken
        Assert-True (-not (Test-Path -LiteralPath $owned.Path)) 'the exact marked root must be removed'
        Assert-True (Test-Path -LiteralPath $sibling) 'cleanup must not remove a same-prefix sibling'
    }
    finally {
        if (Test-Path -LiteralPath $owned.Path) {
            Remove-ZkOwnedStateRoot -StateRoot $owned.Path -MarkerToken $owned.MarkerToken
        }
        if (Test-Path -LiteralPath $sibling) {
            Remove-Item -LiteralPath $sibling -Force
        }
    }
}

Invoke-Test 'bounded exit wait distinguishes a live exact instance from an ended one' {
    $child = $null
    try {
        $child = Start-Sleeper
        $identity = Get-ZkProcessIdentity -Process $child
        Assert-True (-not (Wait-ZkProcessIdentityExit -Identity $identity -TimeoutMilliseconds 100)) 'a live exact instance must not be reported ended'
        Assert-True (Stop-ZkExactProcess -Identity $identity) 'the fixture instance must stop exactly'
        Assert-True (Wait-ZkProcessIdentityExit -Identity $identity -TimeoutMilliseconds 1000) 'the ended exact instance must be reported ended'
    }
    finally {
        Stop-TestProcess -Process $child
    }
}

Invoke-Test 'process identity keys distinguish PID reuse and path changes' {
    $identity = [pscustomobject]@{
        Pid = 4242
        StartTimeUtcTicks = 638000000000000000
        ExecutablePath = 'C:\fixture\agent.exe'
    }
    $changedTime = [pscustomobject]@{
        Pid = $identity.Pid
        StartTimeUtcTicks = $identity.StartTimeUtcTicks + 1
        ExecutablePath = $identity.ExecutablePath
    }
    $changedPath = [pscustomobject]@{
        Pid = $identity.Pid
        StartTimeUtcTicks = $identity.StartTimeUtcTicks
        ExecutablePath = 'C:\fixture\other.exe'
    }

    $key = Get-ZkProcessIdentityKey -Identity $identity
    Assert-True ($key -ne (Get-ZkProcessIdentityKey -Identity $changedTime)) 'creation time must participate in the identity key'
    Assert-True ($key -ne (Get-ZkProcessIdentityKey -Identity $changedPath)) 'executable path must participate in the identity key'
    Assert-Equal $key (Get-ZkProcessIdentityKey -Identity $identity) 'the exact identity key must be stable'
}

Invoke-Test 'engine recognition requires the exact packaged executable path' {
    $expected = 'C:\release\engine\zombie-killer-engine.exe'
    $exact = [pscustomobject]@{ ExecutablePath = $expected }
    $sameNameElsewhere = [pscustomobject]@{ ExecutablePath = 'C:\unrelated\zombie-killer-engine.exe' }
    Assert-True (Test-ZkEngineIdentity -Identity $exact -ExpectedEnginePath $expected) 'the exact packaged path must match'
    Assert-True (-not (Test-ZkEngineIdentity -Identity $sameNameElsewhere -ExpectedEnginePath $expected)) 'a same-name executable elsewhere must not match'
}

Invoke-Test 'retained exact process handle reports a successful bounded exit' {
    $process = $null
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = (Get-Command python -ErrorAction Stop).Source
        $startInfo.UseShellExecute = $false
        $startInfo.ArgumentList.Add('-I')
        $startInfo.ArgumentList.Add('-c')
        $startInfo.ArgumentList.Add('import time; time.sleep(0.2)')
        $process = [Diagnostics.Process]::Start($startInfo)
        $identity = Get-ZkProcessIdentity -Process $process

        $outcome = Wait-ZkCapturedExitCode -Process $process -Identity $identity -TimeoutMilliseconds 5000
        Assert-True $outcome.Observed 'the retained exact process exit must be observable'
        Assert-Equal 0 $outcome.ExitCode 'the successful fixture exit code must be retained'
    }
    finally {
        Stop-TestProcess -Process $process
    }
}

Invoke-Test 'final graceful-exit validation refreshes an exit that raced with settlement' {
    $process = $null
    $registry = New-ZkCaptureRegistry
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = (Get-Command python -ErrorAction Stop).Source
        $startInfo.UseShellExecute = $false
        $startInfo.ArgumentList.Add('-I')
        $startInfo.ArgumentList.Add('-c')
        $startInfo.ArgumentList.Add('import time; time.sleep(0.15)')
        $process = [Diagnostics.Process]::Start($startInfo)
        $identity = Get-ZkProcessIdentity -Process $process
        Add-ZkCapturedRecord -Registry $registry -Identity $identity -Process $process -Kind 'application' | Out-Null
        Assert-True $process.WaitForExit(5000) 'the fixture must exit before final validation'
        Assert-True (-not $registry[(Get-ZkProcessIdentityKey -Identity $identity)].ExitCodeObserved) 'the prior sampling pass must still be stale'
        Assert-ZkSuccessfulApplicationExit -Registry $registry -ApplicationIdentity $identity
        Assert-True $registry[(Get-ZkProcessIdentityKey -Identity $identity)].ExitCodeObserved 'final validation must refresh the retained handle after settlement'
    }
    finally {
        if ($registry.Count -gt 0) { Dispose-ZkCaptureRegistry -Registry $registry }
        elseif ($null -ne $process) { $process.Dispose() }
    }
}

Invoke-Test 'graceful close refusal never force-kills a console process' {
    $child = $null
    try {
        $child = Start-Sleeper
        $identity = Get-ZkProcessIdentity -Process $child
        Assert-True (-not (Request-ZkGracefulClose -Identity $identity -TimeoutMilliseconds 100)) 'a process without a main window must refuse graceful close'
        Assert-True (-not (Send-ZkGracefulClose -Identity $identity)) 'a nonblocking close request must also refuse a process without a main window'
        $child.Refresh()
        Assert-True (-not $child.HasExited) 'graceful-close refusal must not terminate the process'
    }
    finally {
        Stop-TestProcess -Process $child
    }
}

Invoke-Test 'an application that already exited is not reported as gracefully closed' {
    $child = $null
    try {
        $child = Start-Sleeper
        $identity = Get-ZkProcessIdentity -Process $child
        Assert-True (Stop-ZkExactProcess -Identity $identity) 'the exact fixture must exit first'
        Assert-True (-not (Request-ZkGracefulClose -Identity $identity -TimeoutMilliseconds 100)) 'spontaneous exit must not count as a graceful close request'
    }
    finally {
        Stop-TestProcess -Process $child
    }
}

Invoke-Test 'sanitized launch environment omits provider and network credential variables' {
    $originalOpenAi = [Environment]::GetEnvironmentVariable('OPENAI_API_KEY', 'Process')
    $originalAwsSecret = [Environment]::GetEnvironmentVariable('AWS_SECRET_ACCESS_KEY', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('OPENAI_API_KEY', 'must-not-propagate', 'Process')
        [Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY', 'must-not-propagate', 'Process')
        $stateRoot = Join-Path ([IO.Path]::GetTempPath()) "zk-native-smoke-test-$([guid]::NewGuid().ToString('N'))"
        $startInfo = New-ZkSanitizedStartInfo -ExecutablePath (Get-Process -Id $PID).Path -StateRoot $stateRoot

        Assert-True (-not $startInfo.Environment.ContainsKey('OPENAI_API_KEY')) 'OpenAI credentials must not propagate'
        Assert-True (-not $startInfo.Environment.ContainsKey('AWS_SECRET_ACCESS_KEY')) 'AWS credentials must not propagate'
        Assert-Equal $stateRoot $startInfo.Environment['APPDATA'] 'APPDATA must be isolated'
        Assert-Equal $stateRoot $startInfo.Environment['LOCALAPPDATA'] 'LOCALAPPDATA must be isolated'
        Assert-True (-not $startInfo.UseShellExecute) 'the sanitized environment requires direct process creation'
    }
    finally {
        [Environment]::SetEnvironmentVariable('OPENAI_API_KEY', $originalOpenAi, 'Process')
        [Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY', $originalAwsSecret, 'Process')
    }
}

Invoke-Test 'UI readiness requires accepted native scan content and rejects startup errors' {
    Assert-Equal 'pending' (Get-ZkUiReadinessState -Names @()) 'an empty startup accessibility tree must remain pending'
    Assert-Equal 'pending' (Get-ZkUiReadinessState -Names @('Swarm', 'Loading coverage and agent evidence…')) 'loading UI must remain pending'
    Assert-Equal 'error' (Get-ZkUiReadinessState -Names @('Swarm', 'Scan incomplete', 'Retry scan')) 'scan error UI must fail readiness'
    Assert-Equal 'error' (Get-ZkUiReadinessState -Names @('Retry settings')) 'settings error UI must fail readiness'
    Assert-Equal 'ready' (Get-ZkUiReadinessState -Names @('Local engine · native actions', 'Coverage status', '3 coverage blind spots')) 'post-scan native coverage UI must prove readiness'
}

Invoke-Test 'a zero-exit engine cannot prove startup without renderer-accepted scan content' {
    $pending = Get-ZkStartupEvidenceState -UiState 'pending' -EngineObserved $true -EngineExited $true -EngineExitCode 0
    Assert-Equal 'pending' $pending 'engine exit zero with a still-loading UI must not count as startup success'

    $invalid = Get-ZkStartupEvidenceState -UiState 'error' -EngineObserved $true -EngineExited $true -EngineExitCode 0
    Assert-Equal 'error' $invalid 'an invalid engine response surfaced by the renderer must fail even when the process exits zero'

    $ready = Get-ZkStartupEvidenceState -UiState 'ready' -EngineObserved $true -EngineExited $true -EngineExitCode 0
    Assert-Equal 'ready' $ready 'only renderer-accepted native coverage plus a real engine observation proves startup'
}

Invoke-Test 'startup engine evidence requires a sampled request after settings load' {
    $settings = [pscustomobject]@{
        Identity = [pscustomobject]@{ Pid = 10; StartTimeUtcTicks = 100; ExecutablePath = 'C:\release\engine.exe' }
        ListenerSamples = 2
    }
    $scan = [pscustomobject]@{
        Identity = [pscustomobject]@{ Pid = 11; StartTimeUtcTicks = 200; ExecutablePath = 'C:\release\engine.exe' }
        ListenerSamples = 0
    }
    Assert-True ($null -eq (Get-ZkCausalScanEngineRecord -EngineRecords @($settings))) 'the settings request alone must not prove scan startup'
    Assert-True ($null -eq (Get-ZkCausalScanEngineRecord -EngineRecords @($settings, $scan))) 'an unsampled scan request must not prove listener ownership'
    $scan.ListenerSamples = 1
    Assert-Equal 11 (Get-ZkCausalScanEngineRecord -EngineRecords @($scan, $settings)).Identity.Pid 'the first sampled post-settings engine must prove the causal scan request'
}

Invoke-Test 'numeric TCP state mapping is locale independent and fails closed on format drift' {
    $rows = @(
        [pscustomobject]@{ State = 2; LocalEndpoint = '127.0.0.1:43123'; OwningProcess = 1234 },
        [pscustomobject]@{ State = 5; LocalEndpoint = '127.0.0.1:43124'; OwningProcess = 5678 }
    )
    $listeners = @(ConvertFrom-ZkNativeTcpRows -Rows $rows)
    Assert-Equal 1 $listeners.Count 'only numeric MIB_TCP_STATE_LISTEN rows must be returned'
    Assert-Equal 1234 $listeners[0].OwningProcess 'the numeric row must retain its owner PID'
    Assert-Throws -Body {
        ConvertFrom-ZkNativeTcpRows -Rows @([pscustomobject]@{ State = 'ABHÖREN'; LocalEndpoint = '127.0.0.1:1'; OwningProcess = 99 }) | Out-Null
    } -MessagePattern 'numeric TCP state'
}

if ($IsWindows) {
Invoke-Test 'TCP listener snapshot detects a listener owned by the exact process' {
        $listener = $null
        try {
            # Use the base interpreter rather than a venv launcher so the tested PID is
            # the socket owner instead of a launcher whose child owns the listener.
            $pythonPath = (Get-Command python -ErrorAction Stop).Source
            $listener = Start-Process -FilePath $pythonPath -ArgumentList @(
                '-I',
                '-m',
                'http.server',
                '0',
                '--bind',
                '127.0.0.1'
            ) -PassThru
            $identity = Get-ZkProcessIdentity -Process $listener

            $deadline = [DateTime]::UtcNow.AddSeconds(10)
            $records = @()
            do {
                $records = @(Get-ZkTcpListeners -Identity $identity)
                if ($records.Count -gt 0) {
                    break
                }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $deadline)

            Assert-True ($records.Count -gt 0) 'the listener table must report the exact owner PID'
            Assert-True (($records | Where-Object OwningProcess -eq $identity.Pid).Count -gt 0) 'reported listener must retain the owner PID'
        }
        finally {
            Stop-TestProcess -Process $listener
        }
    }


    Invoke-Test 'tracked listener sampling catches a listener opened after startup' {
        $process = $null
        $identity = $null
        $registry = New-ZkCaptureRegistry
        try {
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = (Get-Command python -ErrorAction Stop).Source
            $startInfo.UseShellExecute = $false
            $startInfo.ArgumentList.Add('-I')
            $startInfo.ArgumentList.Add('-c')
            $startInfo.ArgumentList.Add('import socket,time; time.sleep(.3); s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); time.sleep(3)')
            $process = [Diagnostics.Process]::Start($startInfo)
            $identity = Get-ZkProcessIdentity -Process $process
            Add-ZkCapturedRecord -Registry $registry -Identity $identity -Process $process -Kind 'engine' | Out-Null

            $detected = $false
            $deadline = [DateTime]::UtcNow.AddSeconds(5)
            do {
                try {
                    Assert-ZkTrackedTcpListenersAbsent -Registry $registry
                }
                catch {
                    if ($_.Exception.Message -match 'TCP listener') { $detected = $true; break }
                    throw
                }
                Start-Sleep -Milliseconds 50
            } while ([DateTime]::UtcNow -lt $deadline)
            Assert-True $detected 'repeated exact-identity sampling must catch the delayed listener'
        }
        finally {
            if ($null -ne $identity) { Stop-ZkExactProcess -Identity $identity | Out-Null }
            if ($registry.Count -gt 0) { Dispose-ZkCaptureRegistry -Registry $registry }
            if ($null -eq $identity -and $null -ne $process) { Stop-TestProcess -Process $process }
        }
    }

    Invoke-Test 'UI automation refuses an application identity that already ended' {
        $child = $null
        try {
            $child = Start-Sleeper
            $identity = Get-ZkProcessIdentity -Process $child
            Assert-True (Stop-ZkExactProcess -Identity $identity) 'the exact fixture must end before UI inspection'
            Assert-Throws -Body { Get-ZkUiAutomationNames -Identity $identity | Out-Null } -MessagePattern 'not live'
        }
        finally {
            Stop-TestProcess -Process $child
        }
    }


    Invoke-Test 'TCP listener inspection refuses an identity that already ended' {
        $child = $null
        try {
            $child = Start-Sleeper
            $identity = Get-ZkProcessIdentity -Process $child
            Assert-True (Stop-ZkExactProcess -Identity $identity) 'the exact fixture must end before inspection'
            Assert-Throws -Body { Get-ZkTcpListeners -Identity $identity | Out-Null } -MessagePattern 'not live'
        }
        finally {
            Stop-TestProcess -Process $child
        }
    }
}
else {
    Write-Host 'SKIP: Windows TCP owner test requires Get-NetTCPConnection'
}

Invoke-Test 'direct entry point fails closed when the release executable is absent' {
    $pwshPath = (Get-Process -Id $PID).Path
    $scriptPath = Join-Path $PSScriptRoot '..\native-smoke.ps1'
    $missing = Join-Path ([IO.Path]::GetTempPath()) "zk-missing-$([guid]::NewGuid().ToString('N'))\zombie-killer.exe"
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['ZK_DISPOSABLE_WINDOWS_PROFILE'] = '1'
    $startInfo.ArgumentList.Add('-NoLogo')
    $startInfo.ArgumentList.Add('-NoProfile')
    $startInfo.ArgumentList.Add('-NonInteractive')
    $startInfo.ArgumentList.Add('-File')
    $startInfo.ArgumentList.Add($scriptPath)
    $startInfo.ArgumentList.Add('-ExecutablePath')
    $startInfo.ArgumentList.Add($missing)
    $process = [Diagnostics.Process]::Start($startInfo)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        Assert-True ($process.WaitForExit(10000)) 'missing-artifact validation must finish promptly'
        Assert-True ($process.ExitCode -ne 0) 'missing release artifact must produce a failing exit code'
        Assert-True ("$stdout`n$stderr" -match 'release executable not found') 'failure must explain how the native artifact is missing'
    }
    finally {
        Stop-TestProcess -Process $process
    }
}

Write-Host "RESULT: $script:Passed passed, $script:Failed failed"
if ($script:Failed -ne 0) {
    exit 1
}
