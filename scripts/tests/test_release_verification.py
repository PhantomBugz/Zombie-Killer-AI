from __future__ import annotations

import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
LEGAL_FILES = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
PACKAGES = (
    ("zombie-killer-engine", "zombie_killer_engine", "services/engine"),
    ("zombie-killer-sdk", "zombie_killer_sdk", "packages/sdk-python"),
)
VERSION = "0.1.0a1"


@pytest.fixture(scope="module")
def distribution_verifier() -> ModuleType:
    script = ROOT / "scripts" / "verify_python_distributions.py"
    spec = importlib.util.spec_from_file_location("verify_python_distributions", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def repository_state() -> ModuleType:
    script = ROOT / "scripts" / "repository_state.py"
    spec = importlib.util.spec_from_file_location("repository_state", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


@pytest.fixture
def git_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Verification Fixture")
    _git(repository, "config", "user.email", "fixture@example.invalid")
    (repository / ".gitignore").write_text("output/\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("committed\n", encoding="utf-8")
    _git(repository, "add", ".gitignore", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "fixture")
    return repository


def test_repository_snapshot_detects_content_changes_with_unchanged_dirty_status(
    repository_state: Any,
    git_repository: Path,
) -> None:
    tracked = git_repository / "tracked.txt"
    tracked.write_text("dirty-one\n", encoding="utf-8")
    status_before = _git(git_repository, "status", "--porcelain=v1")
    before = repository_state.snapshot_repository(git_repository)

    tracked.write_text("dirty-two\n", encoding="utf-8")
    status_after = _git(git_repository, "status", "--porcelain=v1")
    after = repository_state.snapshot_repository(git_repository)

    assert status_after == status_before
    assert after.digest != before.digest


def test_repository_snapshot_detects_untracked_content_changes(
    repository_state: Any,
    git_repository: Path,
) -> None:
    untracked = git_repository / "untracked.txt"
    untracked.write_text("untracked-one\n", encoding="utf-8")
    status_before = _git(git_repository, "status", "--porcelain=v1")
    before = repository_state.snapshot_repository(git_repository)

    untracked.write_text("untracked-two\n", encoding="utf-8")
    status_after = _git(git_repository, "status", "--porcelain=v1")
    after = repository_state.snapshot_repository(git_repository)

    assert status_after == status_before
    assert after.digest != before.digest


def test_repository_snapshot_detects_staged_content_changes(
    repository_state: Any,
    git_repository: Path,
) -> None:
    tracked = git_repository / "tracked.txt"
    tracked.write_text("staged-one\n", encoding="utf-8")
    _git(git_repository, "add", "tracked.txt")
    status_before = _git(git_repository, "status", "--porcelain=v1")
    before = repository_state.snapshot_repository(git_repository)

    tracked.write_text("staged-two\n", encoding="utf-8")
    _git(git_repository, "add", "tracked.txt")
    status_after = _git(git_repository, "status", "--porcelain=v1")
    after = repository_state.snapshot_repository(git_repository)

    assert status_after == status_before
    assert after.digest != before.digest


def test_repository_snapshot_ignores_declared_build_output(
    repository_state: Any,
    git_repository: Path,
) -> None:
    ignored = git_repository / "output" / "cache.bin"
    ignored.parent.mkdir()
    ignored.write_bytes(b"first")
    before = repository_state.snapshot_repository(git_repository)

    ignored.write_bytes(b"second")
    after = repository_state.snapshot_repository(git_repository)

    assert after == before


def test_repository_snapshot_rejects_a_change_between_complete_passes(
    repository_state: Any,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracked = git_repository / "tracked.txt"
    real_snapshot_once = repository_state._snapshot_once
    calls = 0

    def mutate_after_first_pass(repository: Path) -> Any:
        nonlocal calls
        snapshot = real_snapshot_once(repository)
        calls += 1
        if calls == 1:
            tracked.write_text("changed-between-passes\n", encoding="utf-8")
        return snapshot

    monkeypatch.setattr(repository_state, "_snapshot_once", mutate_after_first_pass)

    with pytest.raises(RuntimeError, match="changed during repository snapshot"):
        repository_state.snapshot_repository(git_repository)


def test_repository_snapshot_rejects_a_tracked_change_after_hashing(
    repository_state: Any,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracked = git_repository / "tracked.txt"
    real_hash_path = repository_state._hash_path
    changed = False

    def mutate_after_hash(*args: Any, **kwargs: Any) -> None:
        nonlocal changed
        real_hash_path(*args, **kwargs)
        raw_path = args[2]
        if raw_path == b"tracked.txt" and not changed:
            changed = True
            tracked.write_text("changed-after-hash\n", encoding="utf-8")

    monkeypatch.setattr(repository_state, "_hash_path", mutate_after_hash)

    with pytest.raises(RuntimeError, match="changed during repository snapshot"):
        repository_state.snapshot_repository(git_repository)


def _tar_add_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mtime = 0
    archive.addfile(member, io.BytesIO(content))


def _metadata(
    project_name: str,
    *,
    license_expression: str = "Apache-2.0",
    license_files: tuple[str, ...] = LEGAL_FILES,
) -> bytes:
    fields = (
        "Metadata-Version: 2.4\n"
        f"Name: {project_name}\n"
        f"Version: {VERSION}\n"
        f"License-Expression: {license_expression}\n"
    )
    fields += "".join(f"License-File: {name}\n" for name in license_files)
    return f"{fields}\n".encode()


def _write_repository_contract(repository: Path) -> None:
    for project_name, _artifact_name, source in PACKAGES:
        package_root = repository / source
        package_root.mkdir(parents=True)
        (package_root / "pyproject.toml").write_text(
            "[project]\n"
            f'name = "{project_name}"\n'
            f'version = "{VERSION}"\n'
            'license = "Apache-2.0"\n'
            f"license-files = [{', '.join(repr(name) for name in LEGAL_FILES)}]\n",
            encoding="utf-8",
        )
        for legal_name in LEGAL_FILES:
            (package_root / legal_name).write_bytes(f"{project_name}:{legal_name}\n".encode())


def _write_distributions(
    repository: Path,
    dist_dir: Path,
    *,
    omit_sdist_legal: tuple[str, str] | None = None,
    corrupt_wheel_legal: tuple[str, str] | None = None,
    license_expression: str = "Apache-2.0",
    license_files: tuple[str, ...] = LEGAL_FILES,
) -> None:
    dist_dir.mkdir()
    (dist_dir / ".gitignore").write_text("*", encoding="utf-8")
    for project_name, artifact_name, source in PACKAGES:
        source_root = repository / source
        wheel = dist_dir / f"{artifact_name}-{VERSION}-py3-none-any.whl"
        dist_info = f"{artifact_name}-{VERSION}.dist-info"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                f"{dist_info}/METADATA",
                _metadata(
                    project_name,
                    license_expression=license_expression,
                    license_files=license_files,
                ),
            )
            for legal_name in LEGAL_FILES:
                content = (source_root / legal_name).read_bytes()
                if corrupt_wheel_legal == (project_name, legal_name):
                    content = b"not the reviewed notice\n"
                archive.writestr(f"{dist_info}/licenses/{legal_name}", content)

        sdist = dist_dir / f"{artifact_name}-{VERSION}.tar.gz"
        sdist_root = f"{artifact_name}-{VERSION}"
        with tarfile.open(sdist, "w:gz") as archive:
            _tar_add_bytes(
                archive,
                f"{sdist_root}/PKG-INFO",
                _metadata(project_name, license_files=license_files),
            )
            for legal_name in LEGAL_FILES:
                if omit_sdist_legal == (project_name, legal_name):
                    continue
                _tar_add_bytes(
                    archive,
                    f"{sdist_root}/{legal_name}",
                    (source_root / legal_name).read_bytes(),
                )


@pytest.fixture
def distribution_fixture(tmp_path: Path) -> Iterator[tuple[Path, Path]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_repository_contract(repository)
    dist_dir = tmp_path / "dist"
    _write_distributions(repository, dist_dir)
    yield repository, dist_dir


def test_distribution_validator_accepts_exact_wheels_and_sdists(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture

    report = distribution_verifier.verify_distributions(dist_dir, repository)

    assert report.artifact_count == 4
    assert report.legal_file_count == 12


def test_distribution_validator_rejects_a_missing_sdist_notice(
    distribution_verifier: Any,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_repository_contract(repository)
    dist_dir = tmp_path / "dist"
    _write_distributions(
        repository,
        dist_dir,
        omit_sdist_legal=("zombie-killer-sdk", "NOTICE"),
    )

    with pytest.raises(RuntimeError, match="zombie-killer-sdk.*NOTICE"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_modified_wheel_legal_text(
    distribution_verifier: Any,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_repository_contract(repository)
    dist_dir = tmp_path / "dist"
    _write_distributions(
        repository,
        dist_dir,
        corrupt_wheel_legal=("zombie-killer-engine", "THIRD_PARTY_NOTICES.md"),
    )

    with pytest.raises(RuntimeError, match="zombie-killer-engine.*THIRD_PARTY_NOTICES"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_unreviewed_wheel_license_member(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    dist_info = f"zombie_killer_engine-{VERSION}.dist-info"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(f"{dist_info}/licenses/UNREVIEWED.txt", b"not reviewed\n")

    with pytest.raises(RuntimeError, match="license directory.*exactly"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_extra_wheel_metadata_tree(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "unreviewed-1.0.dist-info/METADATA",
            _metadata("unreviewed"),
        )

    with pytest.raises(RuntimeError, match="exactly one.*dist-info/METADATA"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_case_colliding_wheel_metadata(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    alias = f"zombie_killer_engine-{VERSION}.DIST-INFO/METADATA"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(alias, _metadata("zombie-killer-engine"))

    with pytest.raises(RuntimeError, match="case-insensitive path collision"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_mixed_case_wheel_license_alias(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    dist_info = f"zombie_killer_engine-{VERSION}.dist-info"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(f"{dist_info}/Licenses/UNREVIEWED.txt", b"not reviewed\n")

    with pytest.raises(RuntimeError, match="license directory.*exactly"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_backslash_wheel_member_alias(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    dist_info = f"zombie_killer_engine-{VERSION}.dist-info"
    canonical = f"{dist_info}/licenses/UNREVIEWED.txt"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(canonical, b"not reviewed\n")
    wheel_bytes = wheel.read_bytes()
    assert wheel_bytes.count(canonical.encode()) == 2
    wheel.write_bytes(
        wheel_bytes.replace(canonical.encode(), canonical.replace("/", "\\").encode())
    )

    with pytest.raises(RuntimeError, match="backslash"):
        distribution_verifier.verify_distributions(dist_dir, repository)


@pytest.mark.parametrize(
    "alias_suffix",
    (
        "./METADATA",
        "./licenses/UNREVIEWED.txt",
        "licenses/../licenses/UNREVIEWED.txt",
        "licenses//UNREVIEWED.txt",
    ),
)
def test_distribution_validator_rejects_dot_segment_wheel_alias(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
    alias_suffix: str,
) -> None:
    repository, dist_dir = distribution_fixture
    wheel = dist_dir / f"zombie_killer_engine-{VERSION}-py3-none-any.whl"
    dist_info = f"zombie_killer_engine-{VERSION}.dist-info"
    content = _metadata("zombie-killer-engine") if alias_suffix.endswith("METADATA") else b"x"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(f"{dist_info}/{alias_suffix}", content)

    with pytest.raises(RuntimeError, match="noncanonical"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_wrong_license_metadata(
    distribution_verifier: Any,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_repository_contract(repository)
    dist_dir = tmp_path / "dist"
    _write_distributions(repository, dist_dir, license_expression="MIT")

    with pytest.raises(RuntimeError, match="License-Expression"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_incomplete_license_file_metadata(
    distribution_verifier: Any,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_repository_contract(repository)
    dist_dir = tmp_path / "dist"
    _write_distributions(repository, dist_dir, license_files=("LICENSE", "NOTICE"))

    with pytest.raises(RuntimeError, match="License-File"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_distribution_validator_rejects_unreviewed_artifacts(
    distribution_verifier: Any,
    distribution_fixture: tuple[Path, Path],
) -> None:
    repository, dist_dir = distribution_fixture
    (dist_dir / "unexpected-package-1.0.0.tar.gz").write_bytes(b"unreviewed")

    with pytest.raises(RuntimeError, match="unexpected distribution artifact"):
        distribution_verifier.verify_distributions(dist_dir, repository)


def test_package_scripts_delegate_full_verification_without_recursion() -> None:
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    scripts = package["scripts"]

    assert scripts["verify"] == "pwsh -NoProfile -File scripts/verify.ps1"
    assert scripts["verify:web"] == (
        "pnpm run toolchain:check && pnpm run lint:docs && pnpm run lint && "
        "pnpm run typecheck && pnpm run test:docs && pnpm run test && pnpm run build"
    )
    assert "verify" not in scripts["verify:web"].split()


def test_release_workflow_installs_linux_native_prerequisites_before_verify() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    prerequisite_position = workflow.find("Install Linux WebView prerequisites")
    verification_position = workflow.find("pnpm verify")
    assert prerequisite_position >= 0
    assert prerequisite_position < verification_position
    for package in (
        "libwebkit2gtk-4.1-dev",
        "libappindicator3-dev",
        "librsvg2-dev",
        "patchelf",
    ):
        assert package in workflow
    assert "uv run pytest" not in workflow[verification_position:]
    assert "cargo test" not in workflow[verification_position:]
    assert "pnpm secret:scan" not in workflow[verification_position:]


def test_release_workflow_rejects_bad_confirmation_as_first_mandatory_step() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    job = workflow.split("\n  verify-source:", maxsplit=1)[1]

    assert re.search(r"(?m)^    if:", job) is None
    steps_position = job.index("\n    steps:")
    validation_position = job.index("\n      - name: Validate manual release confirmation")
    checkout_position = job.index("\n      - name: Check out complete source")
    assert steps_position < validation_position < checkout_position
    assert "- name:" not in job[steps_position:validation_position]

    validation = job[validation_position:checkout_position]
    assert "RELEASE_CONFIRMATION: ${{ inputs.confirm }}" in validation
    assert 'if [ "$RELEASE_CONFIRMATION" != "VERIFY_ONLY" ]; then' in validation
    assert "exit 1" in validation
    assert re.search(r"(?m)^        if:", validation) is None


def test_native_workflow_verifies_portable_exe_before_sbom_only_upload() -> None:
    workflow = (ROOT / ".github" / "workflows" / "native-build.yml").read_text(encoding="utf-8")
    package_position = workflow.index("Package complete unsigned native verification archive")
    helper_position = workflow.index("Verify portable builder and smoke helpers")
    portable_position = workflow.index("Verify unsigned portable Windows executable")
    sbom_position = workflow.index("Generate lock and sidecar file-inventory SBOMs")
    upload_position = workflow.index("Upload native SBOM verification evidence")

    assert package_position < helper_position < portable_position < sbom_position < upload_position
    helper_step = workflow[helper_position:portable_position]
    assert "scripts/tests/native-smoke.tests.ps1" in helper_step
    assert "scripts/tests/portable-smoke.tests.ps1" in helper_step
    portable_step = workflow[portable_position:upload_position]
    assert "ZK_DISPOSABLE_WINDOWS_PROFILE: '1'" in portable_step
    assert "scripts/build-portable-exe.py" in portable_step
    assert "scripts/portable-smoke.ps1" in portable_step
    assert "-ExpectedPayloadSha256" in portable_step
    assert "state_removed" in portable_step
    assert "payload_sha256_independently_supplied" in portable_step
    upload_step = workflow[upload_position:]
    assert "path: artifacts/sbom/**" in upload_step
    assert "artifacts/native/" not in upload_step
    assert "artifacts/portable/" not in upload_step


def test_powershell_orchestrator_has_strict_release_contract() -> None:
    script = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8")
    script_lower = script.casefold()

    assert "Set-StrictMode -Version Latest" in script
    assert "$ErrorActionPreference = 'Stop'" in script
    assert "Invoke-Expression" not in script
    assert "NON-RELEASE" in script
    assert "AllowDirty" in script
    for skip_flag in (
        "SkipDependencyInstall",
        "SkipDocs",
        "SkipWeb",
        "SkipPython",
        "SkipRust",
        "SkipNativeBuild",
        "SkipReleaseFixture",
        "SkipNativeSmoke",
        "SkipPortableExe",
        "SkipSecretScan",
        "SkipSbom",
    ):
        assert skip_flag in script

    for command_contract in (
        "scripts/check-toolchain.mjs",
        "uv sync --frozen",
        "pnpm install --frozen-lockfile",
        "ruff format --check",
        "ruff check",
        "mypy",
        "services/engine/tests",
        "packages/sdk-python/tests",
        "packages/protocol/tests",
        "scripts/tests",
        "package-native-artifact.py",
        "collect-sidecar-legal.py",
        "repository_state.py",
        "verify_python_distributions.py",
        "cargo fmt",
        "cargo clippy",
        "cargo test",
        "tauri build --no-bundle",
        "scripts/release-fixture.py",
        "scripts/native-smoke.ps1",
        "secret:scan",
        "generate-sbom.mjs",
        "BUILD-MANIFEST.json",
        "git diff --check",
        "git status --porcelain=v1 --untracked-files=all",
    ):
        assert command_contract.casefold() in script_lower

    assert "[System.Diagnostics.Stopwatch]::StartNew()" in script
    assert "[AllowEmptyCollection()]" in script
    assert "$IsWindows" in script
    assert "N/A: native smoke is Windows-only" in script
    assert "$manifestBeforeBuild" in script
    assert "LastWriteTimeUtc.Ticks" in script
    assert "$script:InitialStateDigest" in script
    assert "$script:SnapshotPython" in script
    assert "python3" in script
    assert "uv lock --check" in script
    assert "uv run --frozen python --version" in script
    assert "'build', '--frozen'" not in script
    assert "'build', '--package'" in script
    assert "Remove-OwnedTempRoot" in script
    assert "& $FilePath @ArgumentList" in script


def test_pnpm_install_is_noninteractive_in_headless_verification() -> None:
    script = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8")
    marker = "Add-Step -Steps $steps -Name 'pnpm install --frozen-lockfile'"
    start = script.index(marker)
    end = script.index("Add-Step -Steps $steps", start + len(marker))
    install_step = script[start:end]

    assert "'--config.confirmModulesPurge=false'" in install_step
    assert "$pnpmStore = Join-Path $script:TempRoot 'pnpm-store'" in install_step
    assert "'--store-dir', $pnpmStore" in install_step


def test_cargo_registry_is_isolated_under_owned_temp_root() -> None:
    script = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8")
    temp_root_position = script.index("$script:TempRoot = New-VerificationTempRoot")
    cargo_home_position = script.index("$env:CARGO_HOME = Join-Path $script:TempRoot 'cargo-home'")
    step_loop_position = script.index("for ($index = 0; $index -lt $steps.Count; $index += 1)")

    assert temp_root_position < cargo_home_position < step_loop_position


def test_unix_harness_declares_shared_engine_windows_dependencies() -> None:
    main_manifest = tomllib.loads(
        (ROOT / "apps" / "desktop" / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    )
    harness_manifest = tomllib.loads(
        (
            ROOT
            / "apps"
            / "desktop"
            / "src-tauri"
            / "build_support"
            / "unix-test-harness"
            / "Cargo.toml"
        ).read_text(encoding="utf-8")
    )

    expected = main_manifest["target"]["cfg(windows)"]["dependencies"]["windows-sys"]
    observed = harness_manifest["target"]["cfg(windows)"]["dependencies"]["windows-sys"]
    assert observed == expected


def test_powershell_mypy_gate_covers_ci_and_release_tooling_union() -> None:
    script = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8")
    marker = "Add-Step -Steps $steps -Name 'mypy strict type checking'"
    start = script.index(marker)
    end = script.index("Add-Step -Steps $steps", start + len(marker))
    mypy_step = script[start:end]

    for target in (
        "services/engine/src",
        "packages/sdk-python/src",
        "scripts/package-native-artifact.py",
        "scripts/collect-sidecar-legal.py",
        "scripts/python_package_artifacts.py",
        "scripts/repository_state.py",
        "scripts/verify_python_distributions.py",
        "scripts/tests",
    ):
        assert f"'{target}'" in mypy_step


def test_release_verification_docs_record_verified_identity_bound_cli_gate() -> None:
    document = (ROOT / "docs" / "release-verification.md").read_text(encoding="utf-8")

    assert "Fix and test the current `zk action plan`" not in document
    assert (
        "verified identity-bound `zk action plan` PID/process-instance CLI regression gate"
        in document
    )


def test_scoped_orchestrator_run_is_loud_and_never_returns_success() -> None:
    if shutil.which("pwsh") is None or shutil.which("node") is None:
        pytest.skip("PowerShell and Node are required for the orchestrator smoke test")
    node_version = subprocess.run(
        ["node", "--version"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if node_version.returncode != 0 or node_version.stdout.strip() != "v24.18.0":
        pytest.skip("orchestrator smoke requires the repository-pinned Node")

    completed = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            "scripts/verify.ps1",
            "-AllowDirty",
            "-SkipDependencyInstall",
            "-SkipDocs",
            "-SkipWeb",
            "-SkipPython",
            "-SkipRust",
            "-SkipNativeBuild",
            "-SkipReleaseFixture",
            "-SkipNativeSmoke",
            "-SkipPortableExe",
            "-SkipSecretScan",
            "-SkipSbom",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 2, output
    assert "NON-RELEASE" in output
    assert "-SkipPortableExe" in output
    assert "[29/29]" in output
    assert "not release approval" in output


def test_skipping_native_build_requires_explicit_portable_skip() -> None:
    if sys.platform != "win32" or shutil.which("pwsh") is None:
        pytest.skip("Windows PowerShell is required for portable skip preflight")

    completed = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            "scripts/verify.ps1",
            "-AllowDirty",
            "-SkipNativeBuild",
            "-SkipNativeSmoke",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 1, output
    assert "-SkipNativeBuild requires -SkipPortableExe" in output
