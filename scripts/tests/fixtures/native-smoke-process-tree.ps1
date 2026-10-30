[CmdletBinding()]
param(
    [ValidateRange(5, 300)]
    [int] $LifetimeSeconds = 60,

    [ValidateRange(0, 10000)]
    [int] $ChildDelayMilliseconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$current = Get-Process -Id $PID
if ($ChildDelayMilliseconds -gt 0) {
    Start-Sleep -Milliseconds $ChildDelayMilliseconds
}
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $current.Path
$startInfo.UseShellExecute = $false
$startInfo.ArgumentList.Add('-NoLogo')
$startInfo.ArgumentList.Add('-NoProfile')
$startInfo.ArgumentList.Add('-NonInteractive')
$startInfo.ArgumentList.Add('-Command')
$startInfo.ArgumentList.Add("Start-Sleep -Seconds $LifetimeSeconds")
$child = [Diagnostics.Process]::Start($startInfo)
try {
    Start-Sleep -Seconds $LifetimeSeconds
}
finally {
    try {
        if (-not $child.HasExited) {
            $child.Kill()
            $child.WaitForExit(5000) | Out-Null
        }
    }
    catch {
        # The parent owns this exact retained handle; teardown remains best effort.
    }
    $child.Dispose()
    $current.Dispose()
}
