# Unix boundary test harness

This small crate compiles the shared Rust engine boundary without Tauri's GTK/WebKit system
libraries and runs the Unix-specific runtime-bundle and broker-cancellation containment tests on
Linux. From this directory, run:

```text
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The ignored packaged-sidecar smoke requires an output from the pinned
`scripts/build-engine-sidecar.py` builder. Point it at that output and run:

```text
ZK_PACKAGED_ENGINE_TEST_ROOT=/absolute/path/to/resources/engine \
  cargo test --locked packaged_pyinstaller_onedir_runs_system_info_from_the_private_snapshot \
  -- --ignored --nocapture
```

That smoke authenticates and snapshots the full PyInstaller onedir tree, replaces the source
executable and source `_internal` directory, and requires `system.info` to succeed from the private
snapshot. The temporary execution tree must disappear when its verification guard drops.
