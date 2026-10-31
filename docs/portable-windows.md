# Portable Windows executable

`Zombie Killer.exe` is the unsigned PhantomBugz alpha desktop app packaged as
one compressed executable. Double-click it to open the native local interface.
Windows x64 and an already installed Microsoft Edge WebView2 runtime are required.
It needs sufficient free space in your user local application data directory for
the complete native package. There is no installation wizard, elevation request,
autostart entry, updater, or prerequisite download.

Each launch creates a different `ZombieKiller-...` directory directly beneath
`%LOCALAPPDATA%`. The launcher checks the embedded payload SHA-256, validates
relative Windows filenames and the native/engine/legal layout, restores every ZIP
file byte, and verifies each restored file's size and SHA-256. It then starts only
`target/release/zombie-killer.exe`, with its original neighboring `engine/` directory,
waits for the app to exit, and removes only its own runtime directory. Ordinary
desktop environment variables are inherited. Command arguments are not forwarded.
Settings and memory use the application's existing persistent locations.

Concurrent launches have independent runtime directories. A crash or forced
termination can leave a runtime directory behind, and Windows file locks may
prevent cleanup even after bounded retries. The launcher reports normal cleanup
failures and never searches for or deletes old directories on later launches.
Close the app normally to allow cleanup. A leftover directory can be inspected
and removed manually once its processes have ended.

The only optional argument is `--check`. It verifies and extracts the complete
payload, removes that temporary runtime, prints one JSON object to stdout, and
exits without opening the app. Capture stdout when calling the GUI executable
from a script. The object contains `runtime_root` (the removed absolute path),
`files` (count), `total_bytes`, `payload_sha256`, and `cleanup: true`. A failure
writes to stderr and returns a nonzero status without opening an error dialog.
Every other argument, including payload or executable overrides, is rejected.
Invalid ordinary launches show an error dialog; any request containing `--check`
reports argument errors through stderr. If running the app and removing its
runtime both fail, the message includes both causes and the leftover runtime path.

The payload uses ordinary zlib compression. The launcher is optimized with stripped
symbols; the existing native app and frozen engine bytes are preserved exactly.
Frozen Python bytecode remains recoverable. Compression offers no encryption,
strong obfuscation, or promise that code cannot be extracted. All project and
third-party license/attribution files remain in the embedded package.

To reproduce the wrapper from the Windows x64 ZIP produced by this checkout's
native packaging step, run the following from the repository root. The archive
and executable must come from the same source revision. Run the portable lifecycle smoke
only in a disposable Windows user profile or an ephemeral runner: the engine
uses `SHGetKnownFolderPath` for some per-user state, so changing `APPDATA` or
`LOCALAPPDATA` alone does not isolate it.

```powershell
$archive = (Resolve-Path 'artifacts/native/unsigned-native-windows-amd64.zip').Path
$output = @(python -I scripts/build-portable-exe.py `
  --archive $archive `
  --output-dir artifacts/portable)
if ($LASTEXITCODE -ne 0) { throw 'Portable build failed.' }
$build = $output[-1] | ConvertFrom-Json
pwsh -NoProfile -File scripts/portable-smoke.ps1 `
  -ExecutablePath $build.executable `
  -ArchivePath $archive `
  -ReportPath artifacts/portable/smoke-report.json `
  -ExpectedPayloadSha256 $build.payload_sha256
if ($LASTEXITCODE -ne 0) { throw 'Portable lifecycle smoke failed.' }
```

The builder also runs `--check` on its staged executable with an owned scratch
`LOCALAPPDATA` before publication to the output directory; that diagnostic
does not start the native app. Its final JSON line gives the executable path, executable
SHA-256, and embedded payload SHA-256; the smoke report records the original ZIP
inventory, native readiness, and four exact-job lifecycle checks. The full native
ZIP smoke is a separate step of `pnpm verify` and the hosted Native build workflow.
`artifacts/portable/SHA256SUMS` records the executable
hash. Compare these against the release's independently supplied values before
using a downloaded artifact. A browser-demo screenshot is not a substitute for
the native and portable smoke reports.

The build needs Python 3.12+, the installed Rust 1.97.1 Windows MSVC toolchain,
and its Windows linker/resource tools. Cargo may access its ordinary dependency
registry. The builder uses the launcher's separate locked dependency graph and
does not rebuild or change the packaged native app or engine. The ZIP must contain
the complete sealed Windows x64 engine inventory, native executable, and legal
files. Source files, debug symbols, maps, special entries, unsafe names, and file
collisions are rejected. Payloads are bounded to 4096 files, 512 MiB uncompressed,
and a 4 MiB JSON manifest. Filenames use a conservative ASCII subset to avoid
ambiguous Windows Unicode case aliases.

The builder first compiles and runs `--check` on a staged executable. It replaces
an existing output executable only after that succeeds, then writes `SHA256SUMS`.
Publication holds an OS file lock across executable replacement and checksum
writing. A publisher already holding that output directory's lock causes a
concurrent publication to fail without changing either output. The small
`.portable-publication.lock` file stays in place; the OS releases the actual lock
when its handle closes or the publishing process ends, so no stale file deletion
is needed.
It does not publish, sign, install, or launch the app. Unsigned alpha builds may
trigger Windows download warnings. Verify the supplied checksum and build source;
this packaging does not establish production readiness or antivirus approval.
