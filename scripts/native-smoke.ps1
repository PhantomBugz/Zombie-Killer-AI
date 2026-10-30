<#
.SYNOPSIS
Runs the identity-safe Windows smoke test for an unbundled Zombie Killer release build.

.DESCRIPTION
Launches the Tauri release executable from a disposable Windows profile with a credential-free environment,
captures the application and descendants by PID, creation time, and executable path, observes the
packaged engine, checks TCP-listener ownership, requests a graceful close, and verifies every
captured process instance ended. Failure cleanup acts only on revalidated captured identities.

.PARAMETER ExecutablePath
Path to zombie-killer.exe. By default, uses the standard Tauri release target produced by
`pnpm --filter @zombie-killer/desktop tauri build --no-bundle`.

.EXAMPLE
$env:ZK_DISPOSABLE_WINDOWS_PROFILE = '1' # Only in a disposable Windows account or hosted CI runner.
pwsh -NoProfile -File scripts/native-smoke.ps1

.EXAMPLE
pwsh -NoProfile -File scripts/native-smoke.ps1 -ExecutablePath C:\build\zombie-killer.exe
#>
[CmdletBinding()]
param(
    [string] $ExecutablePath,

    [ValidateRange(5, 300)]
    [int] $StartupTimeoutSeconds = 45,

    [ValidateRange(5, 120)]
    [int] $CloseTimeoutSeconds = 20,

    [ValidateRange(20, 1000)]
    [int] $PollMilliseconds = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ZkNormalizedPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
}

function Test-ZkPathEqual {
    param(
        [Parameter(Mandatory)]
        [string] $Left,

        [Parameter(Mandatory)]
        [string] $Right
    )

    $comparison = if ($IsWindows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    return [string]::Equals(
        (Get-ZkNormalizedPath -Path $Left),
        (Get-ZkNormalizedPath -Path $Right),
        $comparison
    )
}

function Assert-ZkDisposableWindowsProfile {
    if (-not $IsWindows) {
        throw 'Native UI smoke requires Windows.'
    }
    if ($env:ZK_DISPOSABLE_WINDOWS_PROFILE -ne '1') {
        throw 'Native UI smoke can write to the OS-known current-user app state. Run in a disposable Windows profile and set ZK_DISPOSABLE_WINDOWS_PROFILE=1.'
    }
}

function Initialize-ZkNativeJobType {
    if ($null -ne ('ZombieKiller.NativeSmoke.JobLaunch' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ZombieKiller.NativeSmoke
{
    public sealed class JobLaunch : IDisposable
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 258;
        private const int JobObjectBasicProcessIdList = 3;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr hJob,
            int jobObjectInformationClass,
            IntPtr lpJobObjectInformation,
            uint cbJobObjectInformationLength,
            out uint lpReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out FILETIME lpCreationTime,
            out FILETIME lpExitTime,
            out FILETIME lpKernelTime,
            out FILETIME lpUserTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr hProcess,
            uint dwFlags,
            StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private IntPtr jobHandle;
        private IntPtr processHandle;
        private bool disposed;

        public uint ProcessId { get; private set; }

        private JobLaunch(IntPtr job, IntPtr process, uint processId)
        {
            jobHandle = job;
            processHandle = process;
            ProcessId = processId;
        }

        public static JobLaunch Start(
            string applicationPath,
            string workingDirectory,
            string[] arguments,
            string[] environment)
        {
            if (String.IsNullOrWhiteSpace(applicationPath))
                throw new ArgumentException("Application path is required.", nameof(applicationPath));
            if (String.IsNullOrWhiteSpace(workingDirectory))
                throw new ArgumentException("Working directory is required.", nameof(workingDirectory));

            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed.");

            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            IntPtr environmentBlock = IntPtr.Zero;
            try
            {
                string commandLine = QuoteArgument(applicationPath);
                foreach (string argument in arguments ?? Array.Empty<string>())
                    commandLine += " " + QuoteArgument(argument ?? String.Empty);

                string[] entries = environment ?? Array.Empty<string>();
                foreach (string entry in entries)
                {
                    if (entry == null || entry.IndexOf('\0') >= 0 || entry.IndexOf('=') <= 0)
                        throw new ArgumentException("Invalid environment entry.", nameof(environment));
                }
                string block = String.Join("\0", entries.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)) + "\0\0";
                environmentBlock = Marshal.StringToHGlobalUni(block);

                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = (uint)Marshal.SizeOf<STARTUPINFO>();
                if (!CreateProcessW(
                    applicationPath,
                    new StringBuilder(commandLine),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environmentBlock,
                    workingDirectory,
                    ref startup,
                    out process))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess failed.");
                }
                if (!AssignProcessToJobObject(job, process.hProcess))
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(process.hProcess, 0xEE);
                    WaitForSingleObject(process.hProcess, 5000);
                    throw new Win32Exception(error, "AssignProcessToJobObject failed.");
                }
                if (ResumeThread(process.hThread) == UInt32.MaxValue)
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(process.hProcess, 0xEE);
                    WaitForSingleObject(process.hProcess, 5000);
                    throw new Win32Exception(error, "ResumeThread failed.");
                }

                CloseHandle(process.hThread);
                process.hThread = IntPtr.Zero;
                JobLaunch result = new JobLaunch(job, process.hProcess, process.dwProcessId);
                job = IntPtr.Zero;
                process.hProcess = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (environmentBlock != IntPtr.Zero)
                    Marshal.FreeHGlobal(environmentBlock);
                if (process.hThread != IntPtr.Zero)
                    CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero)
                    CloseHandle(process.hProcess);
                if (job != IntPtr.Zero)
                    CloseHandle(job);
            }
        }

        public uint[] GetProcessIds()
        {
            ThrowIfDisposed();
            int capacity = 64;
            while (capacity <= 16384)
            {
                int size = checked(8 + capacity * IntPtr.Size);
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint returned;
                    if (QueryInformationJobObject(jobHandle, JobObjectBasicProcessIdList, buffer, (uint)size, out returned))
                    {
                        int listed = Marshal.ReadInt32(buffer, 4);
                        List<uint> result = new List<uint>(listed);
                        for (int index = 0; index < listed; index++)
                        {
                            long value = Marshal.ReadIntPtr(buffer, 8 + index * IntPtr.Size).ToInt64();
                            if (value > 0 && value <= UInt32.MaxValue)
                                result.Add((uint)value);
                        }
                        return result.ToArray();
                    }
                    int error = Marshal.GetLastWin32Error();
                    if (error != 24 && error != 122 && error != 234)
                        throw new Win32Exception(error, "QueryInformationJobObject failed.");
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
                capacity *= 2;
            }
            throw new InvalidOperationException("Job process list exceeded its bounded capacity.");
        }

        public long GetCreationTimeUtcTicks()
        {
            ThrowIfDisposed();
            FILETIME creation;
            FILETIME exit;
            FILETIME kernel;
            FILETIME user;
            if (!GetProcessTimes(processHandle, out creation, out exit, out kernel, out user))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed.");
            long fileTime = ((long)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
            return DateTime.FromFileTimeUtc(fileTime).Ticks;
        }

        public string GetExecutablePath()
        {
            ThrowIfDisposed();
            uint length = 32768;
            StringBuilder path = new StringBuilder((int)length);
            if (!QueryFullProcessImageNameW(processHandle, 0, path, ref length))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageName failed.");
            return path.ToString();
        }

        public bool IsLaunchedProcessActive()
        {
            ThrowIfDisposed();
            uint wait = WaitForSingleObject(processHandle, 0);
            if (wait == WAIT_TIMEOUT)
                return true;
            if (wait == WAIT_OBJECT_0)
                return false;
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed.");
        }

        public bool TerminateLaunchedProcess(int timeoutMilliseconds)
        {
            ThrowIfDisposed();
            if (timeoutMilliseconds < 0)
                throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
            if (!IsLaunchedProcessActive())
                return true;
            if (!TerminateProcess(processHandle, 0xEE))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TerminateProcess failed.");
            uint wait = WaitForSingleObject(processHandle, (uint)timeoutMilliseconds);
            if (wait == WAIT_OBJECT_0)
                return true;
            if (wait == WAIT_TIMEOUT)
                return false;
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject failed.");
        }

        private static string QuoteArgument(string value)
        {
            if (value.Length == 0)
                return "\"\"";
            if (!value.Any(character => Char.IsWhiteSpace(character) || character == '\"'))
                return value;
            StringBuilder result = new StringBuilder();
            result.Append('\"');
            int slashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    slashes++;
                    continue;
                }
                if (character == '\"')
                {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('\"');
                    slashes = 0;
                    continue;
                }
                result.Append('\\', slashes);
                slashes = 0;
                result.Append(character);
            }
            result.Append('\\', slashes * 2);
            result.Append('\"');
            return result.ToString();
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
                throw new ObjectDisposedException(nameof(JobLaunch));
        }

        public void Dispose()
        {
            if (disposed)
                return;
            disposed = true;
            if (processHandle != IntPtr.Zero)
            {
                CloseHandle(processHandle);
                processHandle = IntPtr.Zero;
            }
            if (jobHandle != IntPtr.Zero)
            {
                // No KILL_ON_JOB_CLOSE limit is configured. Membership is observational only.
                CloseHandle(jobHandle);
                jobHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~JobLaunch()
        {
            Dispose();
        }
    }
}
'@
}

function Start-ZkJobBoundProcess {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.ProcessStartInfo] $StartInfo
    )

    if (-not $IsWindows) {
        throw 'Job-bound native launch is currently supported only on Windows.'
    }
    if ($StartInfo.UseShellExecute) {
        throw 'Job-bound native launch requires direct process creation.'
    }
    $applicationPath = Get-ZkNormalizedPath -Path $StartInfo.FileName
    if (-not (Test-Path -LiteralPath $applicationPath -PathType Leaf)) {
        throw 'Job-bound native launch executable is unavailable.'
    }
    $workingDirectory = Get-ZkNormalizedPath -Path $StartInfo.WorkingDirectory
    $arguments = @($StartInfo.ArgumentList | ForEach-Object { [string] $_ })
    $environment = @(
        $StartInfo.Environment.GetEnumerator() |
            ForEach-Object { "$($_.Key)=$($_.Value)" }
    )
    Initialize-ZkNativeJobType
    return [ZombieKiller.NativeSmoke.JobLaunch]::Start(
        $applicationPath,
        $workingDirectory,
        [string[]] $arguments,
        [string[]] $environment
    )
}

function Assert-ZkRetainedLaunchIdentity {
    param(
        [Parameter(Mandatory)]
        [ZombieKiller.NativeSmoke.JobLaunch] $Launch,

        [Parameter(Mandatory)]
        [psobject] $Identity
    )

    $retainedPath = Get-ZkNormalizedPath -Path $Launch.GetExecutablePath()
    $retainedStartTimeUtcTicks = [long] $Launch.GetCreationTimeUtcTicks()
    if ([int] $Identity.Pid -ne [int] $Launch.ProcessId -or
        [long] $Identity.StartTimeUtcTicks -ne $retainedStartTimeUtcTicks -or
        -not (Test-ZkPathEqual -Left ([string] $Identity.ExecutablePath) -Right $retainedPath)) {
        throw 'The captured application identity does not match the retained native launch handle.'
    }
}

function Get-ZkProcessIdentity {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process,

        [int] $ParentPid = 0,

        [int] $Depth = 0,

        [ValidateRange(0, 5000)]
        [int] $CaptureTimeoutMilliseconds = 1000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($CaptureTimeoutMilliseconds)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Process $($Process.Id) exited before its identity could be captured."
        }
        try {
            $path = $Process.Path
            $startTicks = [long] $Process.StartTime.ToUniversalTime().Ticks
            $hasExecutableImage = -not [string]::IsNullOrWhiteSpace($path)
            if ($IsWindows -and $hasExecutableImage) {
                # Immediately after CreateProcess, Process.Path can transiently report ntdll.dll
                # before the executable image is initialized. Never bind an identity to that loader.
                $hasExecutableImage = [string]::Equals(
                    [IO.Path]::GetExtension($path),
                    '.exe',
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
            if ($hasExecutableImage -and $startTicks -gt 0) {
                return [pscustomobject]@{
                    Pid = [int] $Process.Id
                    StartTimeUtcTicks = $startTicks
                    ExecutablePath = Get-ZkNormalizedPath -Path $path
                    ParentPid = [int] $ParentPid
                    Depth = [int] $Depth
                }
            }
        }
        catch [System.InvalidOperationException] {
            if ($Process.HasExited) {
                throw "Process $($Process.Id) exited before its identity could be captured."
            }
        }
        catch [System.ComponentModel.Win32Exception] {
            # Windows can briefly withhold MainModule metadata immediately after CreateProcess.
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "Executable identity is unavailable for process $($Process.Id)."
        }
        Start-Sleep -Milliseconds 20
    } while ($true)
}

function Get-ZkMatchingProcess {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity
    )

    if ($Identity.Pid -le 0 -or $Identity.StartTimeUtcTicks -le 0 -or [string]::IsNullOrWhiteSpace($Identity.ExecutablePath)) {
        throw 'A process identity requires a positive PID, creation timestamp, and executable path.'
    }

    $candidate = Get-Process -Id ([int] $Identity.Pid) -ErrorAction SilentlyContinue
    if ($null -eq $candidate) {
        return $null
    }

    try {
        $actual = Get-ZkProcessIdentity -Process $candidate
        if ($actual.StartTimeUtcTicks -ne [long] $Identity.StartTimeUtcTicks) {
            $candidate.Dispose()
            return $null
        }
        if (-not (Test-ZkPathEqual -Left $actual.ExecutablePath -Right ([string] $Identity.ExecutablePath))) {
            $candidate.Dispose()
            return $null
        }
        return $candidate
    }
    catch {
        try {
            $candidate.Refresh()
            if ($candidate.HasExited) {
                $candidate.Dispose()
                return $null
            }
        }
        catch [System.InvalidOperationException] {
            $candidate.Dispose()
            return $null
        }
        $candidate.Dispose()
        throw "Unable to revalidate the exact process identity for PID $($Identity.Pid)."
    }
}

function Stop-ZkExactProcess {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity,

        [ValidateRange(1, 30)]
        [int] $WaitSeconds = 5
    )

    $candidate = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $candidate) {
        return $false
    }

    try {
        # Kill only this revalidated handle. Captured descendants are cleaned individually after
        # their own identity checks; an uncaptured process is never reached through tree-kill.
        $candidate.Kill()
        if (-not $candidate.WaitForExit($WaitSeconds * 1000)) {
            throw "Exact process $($Identity.Pid) did not exit during bounded cleanup."
        }
        return $true
    }
    catch [System.InvalidOperationException] {
        # It exited after revalidation and before Kill; the captured instance is gone.
        return $true
    }
    finally {
        $candidate.Dispose()
    }
}

function Get-ZkDescendantPidDepth {
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $RootPid,

        [ValidateRange(0, [long]::MaxValue)]
        [long] $RootStartTimeUtcTicks = 0,

        [Parameter(Mandatory)]
        [object[]] $ProcessRows
    )

    $childrenByParent = @{}
    foreach ($row in $ProcessRows) {
        $processId = [int] $row.ProcessId
        $parentPid = [int] $row.ParentProcessId
        if ($processId -le 0 -or $parentPid -le 0) {
            continue
        }
        if (-not $childrenByParent.ContainsKey($parentPid)) {
            $childrenByParent[$parentPid] = [System.Collections.Generic.List[object]]::new()
        }
        $snapshotStartTimeUtcTicks = [long] 0
        $creationProperty = $row.PSObject.Properties['CreationDate']
        if ($null -ne $creationProperty -and $null -ne $creationProperty.Value) {
            $snapshotStartTimeUtcTicks = [long] ([DateTime] $creationProperty.Value).ToUniversalTime().Ticks
        }
        $snapshotExecutablePath = $null
        $pathProperty = $row.PSObject.Properties['ExecutablePath']
        if ($null -ne $pathProperty -and -not [string]::IsNullOrWhiteSpace([string] $pathProperty.Value)) {
            $snapshotExecutablePath = Get-ZkNormalizedPath -Path ([string] $pathProperty.Value)
        }
        $childrenByParent[$parentPid].Add([pscustomobject]@{
            Pid = $processId
            SnapshotStartTimeUtcTicks = $snapshotStartTimeUtcTicks
            SnapshotExecutablePath = $snapshotExecutablePath
        })
    }

    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $seen.Add($RootPid) | Out-Null
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([pscustomobject]@{
        Pid = $RootPid
        Depth = 0
        SnapshotStartTimeUtcTicks = $RootStartTimeUtcTicks
    })

    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        if (-not $childrenByParent.ContainsKey($parent.Pid)) {
            continue
        }
        foreach ($childSnapshot in $childrenByParent[$parent.Pid]) {
            $childPid = [int] $childSnapshot.Pid
            if ($parent.SnapshotStartTimeUtcTicks -gt 0 -and
                $childSnapshot.SnapshotStartTimeUtcTicks -gt 0 -and
                $childSnapshot.SnapshotStartTimeUtcTicks -lt $parent.SnapshotStartTimeUtcTicks) {
                # Win32_Process retains a numeric ParentProcessId after parent exit. A process that
                # predates the current parent instance belongs to an older owner of that PID.
                continue
            }
            if (-not $seen.Add($childPid)) {
                continue
            }
            $child = [pscustomobject]@{
                Pid = [int] $childPid
                ParentPid = [int] $parent.Pid
                Depth = [int] ($parent.Depth + 1)
                SnapshotStartTimeUtcTicks = [long] $childSnapshot.SnapshotStartTimeUtcTicks
                SnapshotExecutablePath = $childSnapshot.SnapshotExecutablePath
            }
            $queue.Enqueue($child)
            $child
        }
    }
}

function Get-ZkDescendantIdentitySnapshot {
    param(
        [Parameter(Mandatory)]
        [psobject] $RootIdentity
    )

    if (-not $IsWindows) {
        throw 'Native descendant inspection is currently supported only on Windows.'
    }

    $rootBefore = Get-ZkMatchingProcess -Identity $RootIdentity
    if ($null -eq $rootBefore) {
        throw 'The exact application process exited before descendant inspection.'
    }
    $rootBefore.Dispose()

    $rows = @(
        Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId, CreationDate, ExecutablePath -ErrorAction Stop |
            Select-Object ProcessId, ParentProcessId, CreationDate, ExecutablePath
    )
    $nodes = @(Get-ZkDescendantPidDepth -RootPid ([int] $RootIdentity.Pid) -RootStartTimeUtcTicks ([long] $RootIdentity.StartTimeUtcTicks) -ProcessRows $rows)
    $identities = [System.Collections.Generic.List[object]]::new()
    foreach ($node in $nodes) {
        $candidate = Get-Process -Id ([int] $node.Pid) -ErrorAction SilentlyContinue
        if ($null -eq $candidate) {
            continue
        }
        try {
            $identity = Get-ZkProcessIdentity -Process $candidate -ParentPid $node.ParentPid -Depth $node.Depth
            if ($node.SnapshotStartTimeUtcTicks -gt 0 -and
                [Math]::Abs([long] ($identity.StartTimeUtcTicks - $node.SnapshotStartTimeUtcTicks)) -gt 9) {
                # The PID was reused after the process-tree snapshot; never adopt the replacement.
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace([string] $node.SnapshotExecutablePath) -and
                -not (Test-ZkPathEqual -Left $identity.ExecutablePath -Right $node.SnapshotExecutablePath)) {
                # The path disagrees with the same CIM row that established the parent relation.
                continue
            }
            $identities.Add($identity)
        }
        catch {
            $candidate.Refresh()
            if (-not $candidate.HasExited) {
                throw "Unable to bind live descendant PID $($node.Pid) to an executable identity."
            }
            # A child may exit between the CIM snapshot and identity capture.
        }
        finally {
            $candidate.Dispose()
        }
    }

    $rootAfter = Get-ZkMatchingProcess -Identity $RootIdentity
    if ($null -eq $rootAfter) {
        throw 'The exact application process changed during descendant inspection.'
    }
    $rootAfter.Dispose()
    return $identities.ToArray()
}

function Resolve-ZkNativeLayout {
    param(
        [string] $ExecutablePath
    )

    if (-not $IsWindows) {
        throw 'The release native smoke test currently supports Windows only.'
    }

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        $ExecutablePath = Join-Path $PSScriptRoot '..\apps\desktop\src-tauri\target\release\zombie-killer.exe'
    }
    $applicationPath = Get-ZkNormalizedPath -Path $ExecutablePath
    if (-not (Test-Path -LiteralPath $applicationPath -PathType Leaf)) {
        throw "Native release executable not found at '$applicationPath'. Run the Tauri release build with --no-bundle first."
    }
    if ([IO.Path]::GetFileName($applicationPath) -cne 'zombie-killer.exe') {
        throw "Native release executable must be the exact 'zombie-killer.exe' artifact."
    }
    $applicationItem = Get-Item -LiteralPath $applicationPath -Force
    if (($applicationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Native release executable must not be a reparse point.'
    }

    $enginePath = Join-Path ([IO.Path]::GetDirectoryName($applicationPath)) 'engine\zombie-killer-engine.exe'
    $enginePath = Get-ZkNormalizedPath -Path $enginePath
    if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf)) {
        throw "Expected packaged engine not found at '$enginePath'. Run the Tauri release build with --no-bundle first."
    }
    $engineItem = Get-Item -LiteralPath $enginePath -Force
    if (($engineItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The packaged engine executable must not be a reparse point.'
    }

    return [pscustomobject]@{
        ApplicationPath = $applicationPath
        EnginePath = $enginePath
    }
}

function New-ZkOwnedStateRoot {
    $temporaryParent = Get-ZkNormalizedPath -Path ([IO.Path]::GetTempPath())
    $markerToken = [guid]::NewGuid().ToString('N')
    $stateRoot = Join-Path $temporaryParent "zombie-killer-native-smoke-$PID-$markerToken"
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    $stateRoot = Get-ZkNormalizedPath -Path $stateRoot
    $markerPath = Join-Path $stateRoot '.zombie-killer-native-smoke-owner'
    [IO.File]::WriteAllText($markerPath, $markerToken, [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{
        Path = $stateRoot
        MarkerToken = $markerToken
    }
}

function Remove-ZkOwnedStateRoot {
    param(
        [Parameter(Mandatory)]
        [string] $StateRoot,

        [Parameter(Mandatory)]
        [string] $MarkerToken
    )

    $root = Get-ZkNormalizedPath -Path $StateRoot
    if (-not (Test-Path -LiteralPath $root)) {
        return
    }
    $temporaryParent = Get-ZkNormalizedPath -Path ([IO.Path]::GetTempPath())
    $actualParent = Get-ZkNormalizedPath -Path ([IO.Path]::GetDirectoryName($root))
    if (-not (Test-ZkPathEqual -Left $temporaryParent -Right $actualParent)) {
        throw 'Owned state cleanup refused a path outside the exact temporary parent.'
    }
    $leaf = [IO.Path]::GetFileName($root)
    if ($leaf -notmatch '^zombie-killer-native-smoke-[0-9]+-[0-9a-f]{32}$') {
        throw 'Owned state cleanup refused an unexpected directory name.'
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Owned state cleanup refused a non-directory or reparse-point root.'
    }
    $markerPath = Join-Path $root '.zombie-killer-native-smoke-owner'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'Owned state cleanup marker is missing.'
    }
    $markerItem = Get-Item -LiteralPath $markerPath -Force
    if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Owned state cleanup marker must not be a reparse point.'
    }
    $actualMarker = [IO.File]::ReadAllText($markerPath, [Text.UTF8Encoding]::new($false))
    if (-not [string]::Equals($MarkerToken, $actualMarker, [StringComparison]::Ordinal)) {
        throw 'Owned state cleanup marker did not match.'
    }

    # PowerShell does not traverse directory links unless -FollowSymlink is supplied. Refuse any
    # reparse entry anyway so recursive removal never crosses an unexpected boundary.
    $reparseEntry = Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop |
        Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($null -ne $reparseEntry) {
        throw 'Owned state cleanup refused a tree containing a reparse point.'
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}

function Wait-ZkProcessIdentityExit {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity,

        [Parameter(Mandatory)]
        [ValidateRange(0, 300000)]
        [int] $TimeoutMilliseconds,

        [ValidateRange(10, 1000)]
        [int] $PollMilliseconds = 50
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $candidate = Get-ZkMatchingProcess -Identity $Identity
        if ($null -eq $candidate) {
            return $true
        }
        $candidate.Dispose()
        if ([DateTime]::UtcNow -ge $deadline) {
            return $false
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ($true)
}

function Get-ZkProcessIdentityKey {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity
    )

    $path = Get-ZkNormalizedPath -Path ([string] $Identity.ExecutablePath)
    if ($IsWindows) {
        $path = $path.ToUpperInvariant()
    }
    return "$([int] $Identity.Pid)|$([long] $Identity.StartTimeUtcTicks)|$path"
}

function New-ZkCaptureRegistry {
    return [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
}

function Add-ZkCapturedRecord {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry,

        [Parameter(Mandatory)]
        [psobject] $Identity,

        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process,

        [Parameter(Mandatory)]
        [ValidateSet('application', 'engine', 'descendant')]
        [string] $Kind
    )

    $key = Get-ZkProcessIdentityKey -Identity $Identity
    if ($Registry.ContainsKey($key)) {
        return $Registry[$key]
    }
    $record = [pscustomobject]@{
        Identity = $Identity
        Process = $Process
        Kind = $Kind
        ListenerSamples = 0
        ExitCodeObserved = $false
        ExitCode = $null
    }
    $Registry.Add($key, $record)
    return $record
}

function Sync-ZkJobCaptures {
    param(
        [Parameter(Mandatory)]
        [ZombieKiller.NativeSmoke.JobLaunch] $Launch,

        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry,

        [Parameter(Mandatory)]
        [string] $ApplicationPath,

        [Parameter(Mandatory)]
        [string] $EnginePath
    )

    $jobPids = @($Launch.GetProcessIds() | ForEach-Object { [int] $_ })
    foreach ($memberPid in $jobPids) {
        $alreadyCaptured = $false
        foreach ($record in $Registry.Values) {
            if ($record.Identity.Pid -ne $memberPid) {
                continue
            }
            $match = Get-ZkMatchingProcess -Identity $record.Identity
            if ($null -ne $match) {
                $match.Dispose()
                $alreadyCaptured = $true
                break
            }
        }
        if ($alreadyCaptured) {
            continue
        }

        $candidate = Get-Process -Id $memberPid -ErrorAction SilentlyContinue
        if ($null -eq $candidate) {
            # Job membership can briefly outlive the public process-table row. Retry on
            # the next pass; never bind whatever might later reuse this numeric PID.
            continue
        }
        $adopted = $false
        try {
            $identity = Get-ZkProcessIdentity -Process $candidate
            if (-not (@($Launch.GetProcessIds() | ForEach-Object { [int] $_ }) -contains $memberPid)) {
                # The member exited after the job snapshot. Never adopt a process that reused its PID.
                continue
            }
            $kind = if (Test-ZkPathEqual -Left $identity.ExecutablePath -Right $ApplicationPath) {
                'application'
            }
            elseif (Test-ZkPathEqual -Left $identity.ExecutablePath -Right $EnginePath) {
                'engine'
            }
            else {
                'descendant'
            }
            $identity.Depth = if ($kind -eq 'application') { 0 } else { 1 }
            Add-ZkCapturedRecord -Registry $Registry -Identity $identity -Process $candidate -Kind $kind | Out-Null
            $adopted = $true
        }
        catch {
            # Image metadata can be transient during startup/exit. A later pass either
            # captures the same live job member exactly or observes that it has ended.
        }
        finally {
            if (-not $adopted) {
                $candidate.Dispose()
            }
        }
    }
}

function Dispose-ZkCaptureRegistry {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry
    )

    foreach ($record in $Registry.Values) {
        $record.Process.Dispose()
    }
    $Registry.Clear()
}

function Test-ZkLaunchSettled {
    param(
        [Parameter(Mandatory)]
        [ZombieKiller.NativeSmoke.JobLaunch] $Launch
    )

    if ($Launch.IsLaunchedProcessActive()) {
        return $false
    }
    return @($Launch.GetProcessIds()).Count -eq 0
}

function Stop-ZkTrackedLaunchExactly {
    param(
        [Parameter(Mandatory)]
        [ZombieKiller.NativeSmoke.JobLaunch] $Launch,

        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry,

        [Parameter(Mandatory)]
        [string] $ApplicationPath,

        [Parameter(Mandatory)]
        [string] $EnginePath,

        [ValidateRange(1, 120)]
        [int] $TimeoutSeconds = 10,

        [ValidateRange(20, 1000)]
        [int] $PollMilliseconds = 50
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        # Query membership before every cleanup pass. A process created after an earlier
        # snapshot remains in the launch job and must acquire its own exact identity here.
        Sync-ZkJobCaptures -Launch $Launch -Registry $Registry -ApplicationPath $ApplicationPath -EnginePath $EnginePath

        # Stop the application first so it cannot create more workers, then stop every
        # other captured instance individually. Never ask Windows to terminate the job tree.
        $ordered = @(
            $Registry.Values |
                Sort-Object @{ Expression = { if ($_.Kind -eq 'application') { 0 } else { 1 } } },
                    @{ Expression = { $_.Identity.Pid } }
        )
        foreach ($record in $ordered) {
            try {
                Stop-ZkExactProcess -Identity $record.Identity -WaitSeconds 1 | Out-Null
            }
            catch {
                # Continue the pass so one slow process cannot prevent other exact job
                # members from being stopped. The bounded settlement check below remains
                # authoritative and the next pass revalidates this identity again.
            }
        }

        if (Test-ZkLaunchSettled -Launch $Launch) {
            return $true
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            return $false
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ($true)
}

function Test-ZkEngineIdentity {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity,

        [Parameter(Mandatory)]
        [string] $ExpectedEnginePath
    )

    return Test-ZkPathEqual -Left ([string] $Identity.ExecutablePath) -Right $ExpectedEnginePath
}

function Wait-ZkCapturedExitCode {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process,

        [Parameter(Mandatory)]
        [psobject] $Identity,

        [Parameter(Mandatory)]
        [ValidateRange(0, 300000)]
        [int] $TimeoutMilliseconds
    )

    if ($Process.Id -ne [int] $Identity.Pid) {
        throw 'Retained process handle does not match the captured PID.'
    }
    $Process.Refresh()
    if (-not $Process.HasExited) {
        $actual = Get-ZkProcessIdentity -Process $Process
        if ($actual.StartTimeUtcTicks -ne [long] $Identity.StartTimeUtcTicks -or
            -not (Test-ZkPathEqual -Left $actual.ExecutablePath -Right ([string] $Identity.ExecutablePath))) {
            throw 'Retained process handle does not match the captured process instance.'
        }
    }
    if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
        return [pscustomobject]@{
            Observed = $false
            ExitCode = $null
        }
    }
    return [pscustomobject]@{
        Observed = $true
        ExitCode = [int] $Process.ExitCode
    }
}

function Request-ZkGracefulClose {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity,

        [Parameter(Mandatory)]
        [ValidateRange(0, 300000)]
        [int] $TimeoutMilliseconds
    )

    $candidate = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $candidate) {
        return $false
    }
    try {
        $candidate.Refresh()
        if (-not $candidate.CloseMainWindow()) {
            return $false
        }
        return $candidate.WaitForExit($TimeoutMilliseconds)
    }
    finally {
        $candidate.Dispose()
    }
}

function Send-ZkGracefulClose {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity
    )

    $candidate = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $candidate) {
        return $false
    }
    try {
        $candidate.Refresh()
        return $candidate.CloseMainWindow()
    }
    finally {
        $candidate.Dispose()
    }
}

function New-ZkSanitizedStartInfo {
    param(
        [Parameter(Mandatory)]
        [string] $ExecutablePath,

        [Parameter(Mandatory)]
        [string] $StateRoot
    )

    $resolvedExecutable = Get-ZkNormalizedPath -Path $ExecutablePath
    $resolvedStateRoot = Get-ZkNormalizedPath -Path $StateRoot
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedExecutable
    $startInfo.WorkingDirectory = [IO.Path]::GetDirectoryName($resolvedExecutable)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $false
    $startInfo.Environment.Clear()

    $allowList = @(
        'COMSPEC',
        'CommonProgramFiles',
        'CommonProgramFiles(x86)',
        'HOMEDRIVE',
        'HOMEPATH',
        'OS',
        'PATH',
        'PATHEXT',
        'PROCESSOR_ARCHITECTURE',
        'ProgramData',
        'ProgramFiles',
        'ProgramFiles(x86)',
        'SystemDrive',
        'SystemRoot',
        'USERDOMAIN',
        'USERNAME',
        'USERPROFILE',
        'WINDIR'
    )
    foreach ($name in $allowList) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        if (-not [string]::IsNullOrEmpty($value)) {
            $startInfo.Environment[$name] = $value
        }
    }

    # Limit inherited environment and temp data. The production engine resolves its
    # persistent state from the OS-known user profile, so this smoke requires a
    # disposable Windows profile even with these environment overrides.
    $startInfo.Environment['APPDATA'] = $resolvedStateRoot
    $startInfo.Environment['LOCALAPPDATA'] = $resolvedStateRoot
    $startInfo.Environment['TEMP'] = $resolvedStateRoot
    $startInfo.Environment['TMP'] = $resolvedStateRoot
    return $startInfo
}

function Get-ZkUiReadinessState {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Names
    )

    $values = @($Names | ForEach-Object { [string] $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($values | Where-Object { $_ -match '^(Scan incomplete|Retry settings)' }) {
        return 'error'
    }
    $hasNative = $values -contains 'Local engine · native actions'
    $hasCoverage = $values -contains 'Coverage status'
    if ($hasNative -and $hasCoverage) {
        return 'ready'
    }
    return 'pending'
}

function Get-ZkStartupEvidenceState {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('pending', 'ready', 'error')]
        [string] $UiState,

        [Parameter(Mandatory)]
        [bool] $EngineObserved,

        [Parameter(Mandatory)]
        [bool] $EngineExited,

        [AllowNull()]
        [object] $EngineExitCode
    )

    if ($UiState -eq 'error') {
        return 'error'
    }
    if ($EngineExited -and $null -ne $EngineExitCode -and [int] $EngineExitCode -ne 0) {
        return 'error'
    }
    if ($UiState -eq 'ready' -and $EngineObserved) {
        return 'ready'
    }
    return 'pending'
}

function Get-ZkCausalScanEngineRecord {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $EngineRecords
    )

    $ordered = @($EngineRecords | Sort-Object { [long] $_.Identity.StartTimeUtcTicks })
    if ($ordered.Count -lt 2) {
        return $null
    }
    $candidate = @($ordered | Select-Object -Skip 1 | Where-Object ListenerSamples -gt 0 | Select-Object -First 1)
    if ($candidate.Count -eq 0) {
        return $null
    }
    return $candidate[0]
}

function Initialize-ZkUiAutomation {
    if (-not $IsWindows) {
        throw 'Native UI readiness inspection is currently supported only on Windows.'
    }
    if ($null -eq ('System.Windows.Automation.AutomationElement' -as [type])) {
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
    }
}

function Get-ZkUiAutomationNames {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity,

        [ValidateRange(1, 16384)]
        [int] $MaximumElements = 4096
    )

    if (-not $IsWindows) {
        throw 'Native UI readiness inspection is currently supported only on Windows.'
    }

    $candidate = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $candidate) {
        throw 'The exact application identity is not live before UI readiness inspection.'
    }
    try {
        $candidate.Refresh()
        $windowHandle = $candidate.MainWindowHandle
    }
    finally {
        $candidate.Dispose()
    }
    if ($windowHandle -eq [IntPtr]::Zero) {
        return @()
    }

    Initialize-ZkUiAutomation
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($windowHandle)
        if ($null -eq $root) {
            return @()
        }
        if ($root.Current.ProcessId -ne [int] $Identity.Pid) {
            # Window handles are reusable kernel values. Never read readiness from a
            # window that no longer belongs to the exact captured application PID.
            return @()
        }
        if (-not [string]::IsNullOrWhiteSpace($root.Current.Name)) {
            $names.Add([string] $root.Current.Name)
        }
        $elements = $root.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition
        )
        $count = [Math]::Min($elements.Count, $MaximumElements)
        for ($index = 0; $index -lt $count; $index += 1) {
            try {
                $name = [string] $elements.Item($index).Current.Name
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $names.Add($name)
                }
            }
            catch [System.Windows.Automation.ElementNotAvailableException] {
                # A renderer node can disappear while React updates the accessibility tree.
            }
        }
    }
    catch [System.Windows.Automation.ElementNotAvailableException] {
        return @()
    }

    $after = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $after) {
        throw 'The exact application identity changed during UI readiness inspection.'
    }
    $after.Dispose()
    return @($names)
}

function Initialize-ZkNativeTcpType {
    if (-not $IsWindows) {
        throw 'TCP owner inspection is currently supported only on Windows.'
    }
    if ($null -ne ('ZombieKiller.NativeSmoke.TcpTable' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace ZombieKiller.NativeSmoke
{
    public sealed class TcpRow
    {
        public uint State { get; set; }
        public string LocalEndpoint { get; set; }
        public int OwningProcess { get; set; }
    }

    public static class TcpTable
    {
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const uint ERROR_INSUFFICIENT_BUFFER = 122;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddress;
            public uint localPort;
            public uint remoteAddress;
            public uint remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddress;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddress;
            public uint remoteScopeId;
            public uint remotePort;
            public uint state;
            public uint owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr table,
            ref uint size,
            [MarshalAs(UnmanagedType.Bool)] bool order,
            int addressFamily,
            int tableClass,
            uint reserved);

        public static TcpRow[] GetRows()
        {
            List<TcpRow> rows = new List<TcpRow>();
            AppendIpv4(rows);
            AppendIpv6(rows);
            return rows.ToArray();
        }

        private static IntPtr ReadTable(int addressFamily, out uint size)
        {
            size = 0;
            uint result = GetExtendedTcpTable(
                IntPtr.Zero,
                ref size,
                false,
                addressFamily,
                TCP_TABLE_OWNER_PID_ALL,
                0);
            if (result != ERROR_INSUFFICIENT_BUFFER)
                throw new Win32Exception((int)result, "GetExtendedTcpTable sizing failed.");
            IntPtr buffer = IntPtr.Zero;
            try
            {
                for (int attempt = 0; attempt < 8; attempt++)
                {
                    if (size < sizeof(uint))
                        throw new InvalidOperationException("The native TCP table returned an invalid size.");
                    buffer = Marshal.AllocHGlobal(checked((int)size));
                    uint filledSize = size;
                    result = GetExtendedTcpTable(
                        buffer,
                        ref filledSize,
                        false,
                        addressFamily,
                        TCP_TABLE_OWNER_PID_ALL,
                        0);
                    if (result == 0)
                    {
                        size = filledSize;
                        IntPtr completed = buffer;
                        buffer = IntPtr.Zero;
                        return completed;
                    }

                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    if (result != ERROR_INSUFFICIENT_BUFFER)
                        throw new Win32Exception((int)result, "GetExtendedTcpTable failed.");
                    size = filledSize;
                }
                throw new InvalidOperationException("The native TCP table did not stabilize during bounded capture.");
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }

        private static int ReadCount(IntPtr buffer, uint size, int rowSize)
        {
            int count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > 1_000_000)
                throw new InvalidOperationException("The native TCP table returned an invalid row count.");
            long required = sizeof(uint) + checked((long)count * rowSize);
            if (required > size)
                throw new InvalidOperationException("The native TCP table was truncated.");
            return count;
        }

        private static void AppendIpv4(List<TcpRow> rows)
        {
            uint size;
            IntPtr buffer = ReadTable(AF_INET, out size);
            try
            {
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                int count = ReadCount(buffer, size, rowSize);
                for (int index = 0; index < count; index++)
                {
                    IntPtr current = IntPtr.Add(buffer, sizeof(uint) + checked(index * rowSize));
                    MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(current);
                    rows.Add(new TcpRow
                    {
                        State = row.state,
                        LocalEndpoint = new IPAddress(BitConverter.GetBytes(row.localAddress)) + ":" + Port(row.localPort),
                        OwningProcess = Pid(row.owningPid),
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void AppendIpv6(List<TcpRow> rows)
        {
            uint size;
            IntPtr buffer = ReadTable(AF_INET6, out size);
            try
            {
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                int count = ReadCount(buffer, size, rowSize);
                for (int index = 0; index < count; index++)
                {
                    IntPtr current = IntPtr.Add(buffer, sizeof(uint) + checked(index * rowSize));
                    MIB_TCP6ROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(current);
                    IPAddress address = new IPAddress(row.localAddress, row.localScopeId);
                    rows.Add(new TcpRow
                    {
                        State = row.state,
                        LocalEndpoint = "[" + address + "]:" + Port(row.localPort),
                        OwningProcess = Pid(row.owningPid),
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int Port(uint networkPort)
        {
            return (int)(((networkPort & 0xFF) << 8) | ((networkPort >> 8) & 0xFF));
        }

        private static int Pid(uint value)
        {
            if (value > Int32.MaxValue)
                throw new InvalidOperationException("The native TCP table returned an invalid owner PID.");
            return (int)value;
        }
    }
}
'@
}

function ConvertFrom-ZkNativeTcpRows {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Rows
    )

    foreach ($row in $Rows) {
        $stateProperty = $row.PSObject.Properties['State']
        if ($null -eq $stateProperty -or $null -eq $stateProperty.Value -or
            $stateProperty.Value -is [string] -or $stateProperty.Value -is [bool]) {
            throw 'The native TCP row did not expose a numeric TCP state.'
        }
        try {
            $state = [uint32] $stateProperty.Value
        }
        catch {
            throw 'The native TCP row did not expose a numeric TCP state.'
        }
        if ($state -ne 2) {
            continue
        }

        $endpoint = [string] $row.LocalEndpoint
        $owner = [int] $row.OwningProcess
        if ([string]::IsNullOrWhiteSpace($endpoint) -or $owner -le 0) {
            throw 'The native TCP listener row was incomplete.'
        }
        [pscustomobject]@{
            State = $state
            LocalEndpoint = $endpoint
            OwningProcess = $owner
        }
    }
}

function Get-ZkTcpListenerSnapshot {
    Initialize-ZkNativeTcpType
    $rows = [ZombieKiller.NativeSmoke.TcpTable]::GetRows()
    return @(ConvertFrom-ZkNativeTcpRows -Rows $rows)
}

function Get-ZkTcpListeners {
    param(
        [Parameter(Mandatory)]
        [psobject] $Identity
    )

    if (-not $IsWindows) {
        throw 'TCP owner inspection is currently supported only on Windows.'
    }

    $before = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $before) {
        throw 'The exact process identity is not live before TCP listener inspection.'
    }
    $before.Dispose()

    $listeners = @(Get-ZkTcpListenerSnapshot | Where-Object { $_.OwningProcess -eq [int] $Identity.Pid })

    $after = Get-ZkMatchingProcess -Identity $Identity
    if ($null -eq $after) {
        throw 'The exact process identity changed during TCP listener inspection.'
    }
    $after.Dispose()
    return $listeners
}

function Assert-ZkTrackedTcpListenersAbsent {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry
    )

    foreach ($record in @($Registry.Values)) {
        if ($record.Kind -notin @('application', 'engine')) {
            continue
        }

        $live = Get-ZkMatchingProcess -Identity $record.Identity
        if ($null -eq $live) {
            continue
        }
        $live.Dispose()

        try {
            $listeners = @(Get-ZkTcpListeners -Identity $record.Identity)
        }
        catch {
            $after = Get-ZkMatchingProcess -Identity $record.Identity
            if ($null -eq $after) {
                # The exact instance ended during the ownership snapshot. There is no
                # later live interval for this identity to sample.
                continue
            }
            $after.Dispose()
            throw
        }

        $record.ListenerSamples += 1
        if ($listeners.Count -gt 0) {
            throw "The exact $($record.Kind) process PID $($record.Identity.Pid) owns $($listeners.Count) TCP listener(s)."
        }
    }
}

function Update-ZkCapturedExitCodes {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry
    )

    foreach ($record in $Registry.Values) {
        if ($record.ExitCodeObserved) {
            continue
        }
        $record.Process.Refresh()
        if ($record.Process.HasExited) {
            $record.ExitCode = [int] $record.Process.ExitCode
            $record.ExitCodeObserved = $true
        }
    }
}

function Assert-ZkSuccessfulApplicationExit {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, object]] $Registry,

        [Parameter(Mandatory)]
        [psobject] $ApplicationIdentity
    )

    # The process can exit after the final shutdown-loop refresh but before job
    # settlement is observed. Refresh once more from the retained exact handle.
    Update-ZkCapturedExitCodes -Registry $Registry
    $key = Get-ZkProcessIdentityKey -Identity $ApplicationIdentity
    if (-not $Registry.ContainsKey($key)) {
        throw 'The exact application identity is absent from the capture registry.'
    }
    $applicationRecord = $Registry[$key]
    if (-not $applicationRecord.ExitCodeObserved -or $applicationRecord.ExitCode -ne 0) {
        throw "The native application did not report a successful exit after its graceful close request (exit code: $($applicationRecord.ExitCode))."
    }
}

function Invoke-ZkNativeSmoke {
    param(
        [string] $ExecutablePath,

        [ValidateRange(5, 300)]
        [int] $StartupTimeoutSeconds = 45,

        [ValidateRange(5, 120)]
        [int] $CloseTimeoutSeconds = 20,

        [ValidateRange(20, 1000)]
        [int] $PollMilliseconds = 50
    )

    Assert-ZkDisposableWindowsProfile
    $layout = Resolve-ZkNativeLayout -ExecutablePath $ExecutablePath
    $ownedState = $null
    $launch = $null
    $applicationProcess = $null
    $applicationIdentity = $null
    $applicationIdentityBound = $false
    $captured = New-ZkCaptureRegistry
    try {
        # Warm every inspection mechanism before the time-sensitive launch window.
        Initialize-ZkNativeJobType
        Initialize-ZkUiAutomation
        Get-ZkTcpListenerSnapshot | Out-Null

        $ownedState = New-ZkOwnedStateRoot
        $startInfo = New-ZkSanitizedStartInfo -ExecutablePath $layout.ApplicationPath -StateRoot $ownedState.Path
        $launch = Start-ZkJobBoundProcess -StartInfo $startInfo
        $applicationProcess = Get-Process -Id ([int] $launch.ProcessId) -ErrorAction Stop
        $applicationIdentity = Get-ZkProcessIdentity -Process $applicationProcess
        Assert-ZkRetainedLaunchIdentity -Launch $launch -Identity $applicationIdentity
        $applicationIdentity.Depth = 0
        $applicationIdentity.ParentPid = 0
        Add-ZkCapturedRecord -Registry $captured -Identity $applicationIdentity -Process $applicationProcess -Kind 'application' | Out-Null
        $applicationIdentityBound = $true
        Write-Host "PASS: launched release application PID $($applicationIdentity.Pid) with an exact creation-time and path identity"
        Write-Host 'PASS: launch environment is an explicit allowlist with no provider credentials; native state uses the disposable user profile'

        $startupDeadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
        $startupReady = $false
        do {
            Sync-ZkJobCaptures -Launch $launch -Registry $captured -ApplicationPath $layout.ApplicationPath -EnginePath $layout.EnginePath
            Assert-ZkTrackedTcpListenersAbsent -Registry $captured
            Update-ZkCapturedExitCodes -Registry $captured

            $applicationCheck = Get-ZkMatchingProcess -Identity $applicationIdentity
            if ($null -eq $applicationCheck) {
                throw 'The exact native application exited before renderer-accepted startup completed.'
            }
            $applicationCheck.Dispose()

            $engineRecords = @($captured.Values | Where-Object Kind -eq 'engine')
            $engineFailure = @($engineRecords | Where-Object { $_.ExitCodeObserved -and $_.ExitCode -ne 0 } | Select-Object -First 1)
            if ($engineFailure.Count -gt 0) {
                throw "A packaged engine request exited with code $($engineFailure[0].ExitCode)."
            }

            $uiNames = @(Get-ZkUiAutomationNames -Identity $applicationIdentity)
            $uiState = Get-ZkUiReadinessState -Names $uiNames
            $causalScanEngine = Get-ZkCausalScanEngineRecord -EngineRecords $engineRecords
            $firstExitedEngine = @($engineRecords | Where-Object ExitCodeObserved | Select-Object -First 1)
            $engineExited = $firstExitedEngine.Count -gt 0
            $engineExitCode = if ($engineExited) { $firstExitedEngine[0].ExitCode } else { $null }
            $startupEvidence = @{
                UiState = $uiState
                EngineObserved = $null -ne $causalScanEngine
                EngineExited = $engineExited
                EngineExitCode = $engineExitCode
            }
            $startupState = Get-ZkStartupEvidenceState @startupEvidence
            if ($startupState -eq 'error') {
                throw 'The native renderer reported a startup settings or scan error.'
            }
            if ($startupState -eq 'ready') {
                $startupReady = $true
                break
            }
            if ([DateTime]::UtcNow -ge $startupDeadline) {
                break
            }
            Start-Sleep -Milliseconds $PollMilliseconds
        } while ($true)

        if (-not $startupReady) {
            $engineCount = @($captured.Values | Where-Object Kind -eq 'engine').Count
            throw "Renderer-accepted native scan startup with a sampled packaged engine was not observed within $StartupTimeoutSeconds seconds (engines observed: $engineCount)."
        }

        $engineRecords = @($captured.Values | Where-Object Kind -eq 'engine')
        $unsampledEndedEngine = @($engineRecords | Where-Object { $_.ExitCodeObserved -and $_.ListenerSamples -eq 0 } | Select-Object -First 1)
        if ($unsampledEndedEngine.Count -gt 0) {
            throw "Packaged engine PID $($unsampledEndedEngine[0].Identity.Pid) exited before a coherent TCP ownership sample was captured."
        }
        $sampledEngine = Get-ZkCausalScanEngineRecord -EngineRecords $engineRecords
        Write-Host "PASS: observed causal scan engine PID $($sampledEngine.Identity.Pid) at its exact release resource path"
        Write-Host 'PASS: the native renderer accepted settings and displayed native scan coverage'
        Write-Host 'PASS: repeated exact-identity samples found no TCP listeners on the application or packaged engine'

        if (-not (Send-ZkGracefulClose -Identity $applicationIdentity)) {
            throw 'The native window refused the graceful main-window close request.'
        }
        Write-Host 'PASS: the native application accepted a graceful main-window close request'

        $exitDeadline = [DateTime]::UtcNow.AddSeconds($CloseTimeoutSeconds)
        do {
            Sync-ZkJobCaptures -Launch $launch -Registry $captured -ApplicationPath $layout.ApplicationPath -EnginePath $layout.EnginePath
            Assert-ZkTrackedTcpListenersAbsent -Registry $captured
            Update-ZkCapturedExitCodes -Registry $captured
            if (Test-ZkLaunchSettled -Launch $launch) {
                break
            }
            if ([DateTime]::UtcNow -ge $exitDeadline) {
                $remainingPids = @($launch.GetProcessIds() | Sort-Object)
                throw "The launch job did not settle after graceful close; remaining PIDs: $($remainingPids -join ', ')."
            }
            Start-Sleep -Milliseconds $PollMilliseconds
        } while ($true)

        foreach ($record in $captured.Values) {
            $candidate = Get-ZkMatchingProcess -Identity $record.Identity
            if ($null -ne $candidate) {
                $candidate.Dispose()
                throw "Captured exact PID $($record.Identity.Pid) remained after job settlement."
            }
        }
        Assert-ZkSuccessfulApplicationExit -Registry $captured -ApplicationIdentity $applicationIdentity
        Write-Host "PASS: all $($captured.Count) captured exact application/child identities exited and the launch job is empty"
    }
    finally {
        $settled = $null -eq $launch
        if ($null -ne $launch) {
            try {
                $settled = Test-ZkLaunchSettled -Launch $launch
            }
            catch {
                $settled = $false
            }

            if (-not $settled) {
                # If initial identity binding failed, the original native handle is the only
                # trustworthy authority for that launch. It cannot target a reused PID.
                if (-not $applicationIdentityBound) {
                    try {
                        $launch.TerminateLaunchedProcess(5000) | Out-Null
                    }
                    catch {
                        Write-Warning 'The retained launch handle could not confirm initial-process exit.'
                    }
                }
                try {
                    $cleanupParameters = @{
                        Launch = $launch
                        Registry = $captured
                        ApplicationPath = $layout.ApplicationPath
                        EnginePath = $layout.EnginePath
                        TimeoutSeconds = 10
                        PollMilliseconds = $PollMilliseconds
                    }
                    $settled = Stop-ZkTrackedLaunchExactly @cleanupParameters
                }
                catch {
                    Write-Warning "Exact launch cleanup failed: $($_.Exception.Message)"
                    $settled = $false
                }
            }
        }

        if ($null -ne $ownedState) {
            if ($settled) {
                Remove-ZkOwnedStateRoot -StateRoot $ownedState.Path -MarkerToken $ownedState.MarkerToken
            }
            else {
                $remainingPids = if ($null -ne $launch) { @($launch.GetProcessIds()) } else { @() }
                Write-Warning "Isolated smoke state was retained because the exact launch has not settled (job PIDs: $($remainingPids -join ', '))."
            }
        }

        if ($captured.Count -gt 0) {
            Dispose-ZkCaptureRegistry -Registry $captured
        }
        elseif ($null -ne $applicationProcess) {
            $applicationProcess.Dispose()
        }
        if ($null -ne $launch) {
            $launch.Dispose()
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $smokeParameters = @{
            ExecutablePath = $ExecutablePath
            StartupTimeoutSeconds = $StartupTimeoutSeconds
            CloseTimeoutSeconds = $CloseTimeoutSeconds
            PollMilliseconds = $PollMilliseconds
        }
        Invoke-ZkNativeSmoke @smokeParameters
        exit 0
    }
    catch {
        Write-Error "Native smoke failed: $($_.Exception.Message)"
        exit 1
    }
}
