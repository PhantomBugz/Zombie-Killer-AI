from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest


@pytest.fixture(scope="module")
def sidecar_builder() -> ModuleType:
    script = Path(__file__).parents[1] / "build-engine-sidecar.py"
    spec = importlib.util.spec_from_file_location("build_engine_sidecar", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    (tmp_path / "apps" / "desktop" / "src-tauri" / "resources").mkdir(parents=True)
    return tmp_path


def generated(repository: Path, name: str) -> Path:
    tauri_root = repository / "apps" / "desktop" / "src-tauri"
    if name == ".sidecar-build":
        return tauri_root / name
    return tauri_root / "resources" / name


def create_directory_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")


def create_file_symlink(link: Path, target: str) -> None:
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")


def create_windows_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {completed.stderr}")


@pytest.fixture
def removable_junctions() -> Iterator[list[Path]]:
    junctions: list[Path] = []
    yield junctions
    for junction in reversed(junctions):
        if junction.exists():
            os.rmdir(junction)


def test_cleanup_accepts_only_the_exact_generated_child(
    sidecar_builder: Any, repository: Path
) -> None:
    unexpected = repository / "unrelated" / ".engine-next"
    unexpected.mkdir(parents=True)
    sentinel = unexpected / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(RuntimeError, match="exact generated sidecar path"):
        sidecar_builder._remove_generated(unexpected, repository)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cleanup_rejects_a_hardlinked_generated_leaf(
    sidecar_builder: Any, repository: Path
) -> None:
    outside = repository / "outside.txt"
    outside.write_text("last-good", encoding="utf-8")
    generated_file = generated(repository, ".sidecar-build")
    os.link(outside, generated_file)

    with pytest.raises(RuntimeError, match="hard link"):
        sidecar_builder._remove_generated(generated_file, repository)

    assert generated_file.exists()
    assert outside.read_text(encoding="utf-8") == "last-good"


def test_cleanup_rejects_a_final_symbolic_link(sidecar_builder: Any, repository: Path) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    candidate = generated(repository, ".engine-next")
    create_directory_symlink(candidate, outside)

    with pytest.raises(RuntimeError, match="symbolic link or reparse point"):
        sidecar_builder._remove_generated(candidate, repository)

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_resources_directory_is_created_only_beneath_direct_ancestors(
    sidecar_builder: Any, tmp_path: Path
) -> None:
    repository = tmp_path / "repository"
    (repository / "apps" / "desktop" / "src-tauri").mkdir(parents=True)

    resources = sidecar_builder._ensure_resources_directory(repository)

    assert resources == repository / "apps" / "desktop" / "src-tauri" / "resources"
    assert resources.is_dir()


def test_resources_creation_rejects_an_unsafe_ancestor(
    sidecar_builder: Any,
    tmp_path: Path,
    removable_junctions: list[Path],
) -> None:
    repository = tmp_path / "repository"
    desktop = repository / "apps" / "desktop"
    desktop.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    tauri_link = desktop / "src-tauri"
    if os.name == "nt":
        create_windows_junction(tauri_link, outside)
        removable_junctions.append(tauri_link)
    else:
        tauri_link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="ancestor"):
        sidecar_builder._ensure_resources_directory(repository)

    assert not (outside / "resources").exists()


def test_cleanup_does_not_follow_a_nested_directory_symlink(
    sidecar_builder: Any, repository: Path
) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    candidate = generated(repository, ".engine-next")
    candidate.mkdir()
    create_directory_symlink(candidate / "escape", outside)

    sidecar_builder._remove_generated(candidate, repository)

    assert not candidate.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_cleanup_detects_a_directory_swap_before_traversal(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    removable_junctions: list[Path],
) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    candidate = generated(repository, ".engine-next")
    candidate.mkdir()
    victim = candidate / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("ordinary", encoding="utf-8")
    displaced = repository / "displaced"
    swapped = False
    phase_hook = None

    if os.name == "nt":
        real_open_relative = sidecar_builder._open_windows_relative_handle

        def windows_swap_before_open(
            parent_handle: int,
            name: str,
            **kwargs: object,
        ) -> int:
            nonlocal swapped
            if not swapped and name == victim.name:
                swapped = True
                victim.rename(displaced)
                create_windows_junction(victim, outside)
                removable_junctions.append(victim)
            return cast(
                int,
                real_open_relative(parent_handle, name, **kwargs),
            )

        monkeypatch.setattr(
            sidecar_builder,
            "_open_windows_relative_handle",
            windows_swap_before_open,
        )
    else:

        def posix_swap_before_open(phase: str, path: Path) -> None:
            nonlocal swapped
            if not swapped and phase == "before-entry-quarantine" and path == victim:
                swapped = True
                private_victim = next(candidate.parent.glob(".zk-delete-*/entry/victim"))
                private_victim.rename(displaced)
                private_victim.symlink_to(outside, target_is_directory=True)

        phase_hook = posix_swap_before_open

    with pytest.raises((OSError, RuntimeError)):
        sidecar_builder._remove_generated(candidate, repository, phase_hook=phase_hook)

    assert swapped is True
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX renameat2 semantics")
def test_posix_leaf_swap_never_deletes_the_replacement(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate = generated(repository, ".engine-next")
    candidate.mkdir()
    leaf = candidate / "leaf.txt"
    leaf.write_text("original", encoding="utf-8")
    displaced = repository / "displaced-leaf.txt"
    swapped = False

    def swap(phase: str, path: Path) -> None:
        nonlocal swapped
        if phase == "before-entry-quarantine" and path == leaf:
            swapped = True
            private_leaf = next(candidate.parent.glob(".zk-delete-*/entry/leaf.txt"))
            private_leaf.rename(displaced)
            private_leaf.write_text("replacement", encoding="utf-8")

    with pytest.raises(RuntimeError, match="identity changed"):
        sidecar_builder._remove_generated(
            candidate,
            repository,
            phase_hook=swap,
        )

    assert swapped is True
    assert leaf.read_text(encoding="utf-8") == "replacement"
    assert displaced.read_text(encoding="utf-8") == "original"
    assert not list(candidate.parent.glob(".zk-delete-*"))


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_cleanup_does_not_follow_a_nested_windows_junction(
    sidecar_builder: Any,
    repository: Path,
    removable_junctions: list[Path],
) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    candidate = generated(repository, ".engine-next")
    candidate.mkdir()
    junction = candidate / "escape"
    create_windows_junction(junction, outside)
    removable_junctions.append(junction)

    sidecar_builder._remove_generated(candidate, repository)

    removable_junctions.remove(junction)
    assert not candidate.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_cleanup_rejects_a_final_windows_junction(
    sidecar_builder: Any,
    repository: Path,
    removable_junctions: list[Path],
) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    candidate = generated(repository, ".engine-next")
    create_windows_junction(candidate, outside)
    removable_junctions.append(candidate)

    with pytest.raises(RuntimeError, match="reparse point"):
        sidecar_builder._remove_generated(candidate, repository)

    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_inventory_rejects_and_does_not_follow_a_windows_junction(
    sidecar_builder: Any,
    repository: Path,
    removable_junctions: list[Path],
) -> None:
    outside = repository / "outside"
    outside.mkdir()
    sentinel = outside / "secret.txt"
    sentinel.write_text("outside", encoding="utf-8")
    staging = repository / "staging"
    staging.mkdir()
    junction = staging / "escape"
    create_windows_junction(junction, outside)
    removable_junctions.append(junction)

    with pytest.raises(RuntimeError, match="junction or unsupported reparse point"):
        sidecar_builder._inventory(staging)

    assert sentinel.read_text(encoding="utf-8") == "outside"


def test_inventory_preserves_a_safe_relative_symbolic_link(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    target = staging / "target.txt"
    target.write_text("payload", encoding="utf-8")
    link = staging / "relative-link"
    try:
        link.symlink_to("target.txt")
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")

    inventory = sidecar_builder._inventory(staging)

    assert {entry["path"] for entry in inventory} == {"relative-link", "target.txt"}
    assert next(entry for entry in inventory if entry["path"] == "relative-link") == {
        "path": "relative-link",
        "type": "symlink",
        "target": "target.txt",
    }


def test_inventory_accepts_a_safe_multihop_symbolic_link_chain(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "payload.txt").write_text("payload", encoding="utf-8")
    create_file_symlink(staging / "hop", "payload.txt")
    create_file_symlink(staging / "entry", "hop")

    inventory = sidecar_builder._inventory(staging)

    assert {entry["path"] for entry in inventory} == {"entry", "hop", "payload.txt"}


def test_inventory_accepts_a_safe_lexical_pullback_after_symbolic_link_expansion(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "p" / "q" / "deep" / "deeper").mkdir(parents=True)
    (staging / "payload").write_bytes(b"payload")
    create_file_symlink(staging / "p" / "q" / "pull", "deep/deeper")
    # The raw target has four parent components and is lexically outside the
    # root.  Expanding pull first leaves the final payload inside the root.
    create_file_symlink(staging / "p" / "q" / "entry", "pull/../../../../payload")

    inventory = sidecar_builder._inventory(staging)

    assert {entry["path"] for entry in inventory} == {
        "p/q/entry",
        "p/q/pull",
        "payload",
    }


def test_inventory_allows_repeated_safe_symbolic_link_traversal(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "b").mkdir()
    # Resolving b/../a/../a visits a twice with different pending state and
    # terminates at b.  A link-path-only visited set rejects this safe path.
    create_file_symlink(staging / "a", "b")
    create_file_symlink(staging / "b" / "entry", "../a/../a")

    inventory = sidecar_builder._inventory(staging)

    assert {entry["path"] for entry in inventory} == {"a", "b/entry"}


@pytest.mark.parametrize("hop_target", ["dir/", "dir/."])
def test_inventory_scopes_nested_directory_requirements_to_the_link_target(
    sidecar_builder: Any, repository: Path, hop_target: str
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "dir").mkdir()
    (staging / "dir" / "file").write_bytes(b"payload")
    create_file_symlink(staging / "hop", hop_target)
    create_file_symlink(staging / "entry", "hop/file")

    inventory = sidecar_builder._inventory(staging)

    assert {entry["path"] for entry in inventory} == {
        "dir/file",
        "entry",
        "hop",
    }


def test_inventory_bounds_a_growing_symbolic_link_cycle(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    create_file_symlink(staging / "a", "a/x")

    with pytest.raises(RuntimeError, match="too many symbolic links"):
        sidecar_builder._inventory(staging)


@pytest.mark.parametrize("target", ["hop/", "hop/."])
def test_inventory_preserves_terminal_directory_requirement_through_multihop_links(
    sidecar_builder: Any, repository: Path, target: str
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "payload").write_bytes(b"payload")
    create_file_symlink(staging / "hop", "payload")
    create_file_symlink(staging / "entry", target)

    with pytest.raises(RuntimeError, match="not a directory"):
        sidecar_builder._inventory(staging)


@pytest.mark.parametrize(
    "links",
    [
        (("entry", "entry"),),
        (("entry", "hop"), ("hop", "entry")),
    ],
    ids=["self-cycle", "two-node-cycle"],
)
def test_inventory_rejects_symbolic_link_cycles(
    sidecar_builder: Any, repository: Path, links: tuple[tuple[str, str], ...]
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    for name, target in links:
        create_file_symlink(staging / name, target)

    with pytest.raises(RuntimeError, match="symbolic-link cycle"):
        sidecar_builder._inventory(staging)


def test_symbolic_link_graph_validator_rejects_cycle_without_symlink_privileges(
    sidecar_builder: Any,
) -> None:
    with pytest.raises(RuntimeError, match="symbolic-link cycle"):
        sidecar_builder._validate_symbolic_link_graph(
            {"entry": "hop", "hop": "entry"},
            {"entry", "hop"},
        )


@pytest.mark.skipif(os.name != "nt", reason="requires Windows normalized path semantics")
def test_symbolic_link_resolver_rejects_windows_normalized_path_collisions(
    sidecar_builder: Any, repository: Path
) -> None:
    root = repository / "staging"
    upper = os.fspath(root / "Payload")
    lower = os.fspath(root / "payload")
    node_types = {os.path.normcase(upper): "symlink"}

    with pytest.raises(RuntimeError, match="normalized path collision"):
        sidecar_builder._resolve_symbolic_link_target(
            root,
            root / "entry",
            "Payload",
            {upper: "one", lower: "two"},
            node_types,
        )


def test_inventory_rejects_a_dangling_multihop_symbolic_link(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    create_file_symlink(staging / "entry", "hop")
    create_file_symlink(staging / "hop", "missing.txt")

    with pytest.raises(RuntimeError, match="target does not exist directly"):
        sidecar_builder._inventory(staging)


def test_inventory_rejects_symlink_component_expansion_that_changes_lexical_root(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "p" / "q").mkdir(parents=True)
    (staging / "p" / "outside.so").write_bytes(b"lexical decoy")
    external = repository / "outside.so"
    external.write_bytes(b"must not be opened")
    create_file_symlink(staging / "p" / "q" / "hop", "..")
    create_file_symlink(staging / "p" / "q" / "escape", "hop/../../outside.so")

    with pytest.raises(RuntimeError, match="symbolic link|target"):
        sidecar_builder._inventory(staging)
    assert external.read_bytes() == b"must not be opened"


def test_inventory_rejects_nested_directory_swapped_to_link_before_open(
    sidecar_builder: Any,
    repository: Path,
    removable_junctions: list[Path],
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    inner = staging / "inner"
    inner.mkdir()
    (inner / "inside.txt").write_text("inside", encoding="utf-8")
    displaced = repository / "displaced-inner"
    outside = repository / "outside"
    outside.mkdir()
    (outside / "outside.txt").write_text("outside", encoding="utf-8")
    swapped = False

    def swap(phase: str, path: Path) -> None:
        nonlocal swapped
        if phase == "before-directory-open" and path == inner:
            swapped = True
            inner.rename(displaced)
            if os.name == "nt":
                create_windows_junction(inner, outside)
                removable_junctions.append(inner)
            else:
                inner.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="identity|reparse|symbolic link"):
        sidecar_builder._inventory(staging, phase_hook=swap)

    assert swapped is True
    assert (outside / "outside.txt").read_text(encoding="utf-8") == "outside"


def test_inventory_rejects_root_swapped_to_link_before_open(
    sidecar_builder: Any,
    repository: Path,
    removable_junctions: list[Path],
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    (staging / "inside.txt").write_text("inside", encoding="utf-8")
    displaced = repository / "displaced-staging"
    outside = repository / "outside-root"
    outside.mkdir()
    (outside / "outside.txt").write_text("outside", encoding="utf-8")

    def swap(phase: str, path: Path) -> None:
        if phase == "before-root-open" and path == staging:
            staging.rename(displaced)
            if os.name == "nt":
                create_windows_junction(staging, outside)
                removable_junctions.append(staging)
            else:
                staging.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="identity|reparse|symbolic link"):
        sidecar_builder._inventory(staging, phase_hook=swap)

    assert (outside / "outside.txt").read_text(encoding="utf-8") == "outside"


def test_inventory_rejects_file_swap_instead_of_mixing_old_size_and_new_hash(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    payload = staging / "payload.bin"
    payload.write_bytes(b"a")
    displaced = repository / "displaced-payload.bin"

    def swap(phase: str, path: Path) -> None:
        if phase == "before-file-open" and path == payload:
            payload.rename(displaced)
            payload.write_bytes(b"replaced")

    with pytest.raises(RuntimeError, match="identity changed"):
        sidecar_builder._inventory(staging, phase_hook=swap)

    assert payload.read_bytes() == b"replaced"


@pytest.mark.skipif(os.name != "nt", reason="requires Windows share-mode enforcement")
def test_inventory_denies_a_concurrent_writer_while_file_identity_is_pinned(
    sidecar_builder: Any, repository: Path
) -> None:
    staging = repository / "staging"
    staging.mkdir()
    payload = staging / "payload.bin"
    payload.write_bytes(b"payload")
    attempted = False

    def try_concurrent_write(phase: str, path: Path) -> None:
        nonlocal attempted
        if phase == "after-file-open" and path == payload:
            attempted = True
            with pytest.raises(OSError), payload.open("r+b"):
                pass

    sidecar_builder._inventory(staging, phase_hook=try_concurrent_write)

    assert attempted is True


@pytest.mark.skipif(os.name != "nt", reason="Windows handle disposition behavior")
def test_windows_leaf_swap_deletes_opened_original_not_replacement(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate = generated(repository, ".engine-next")
    candidate.mkdir()
    leaf = candidate / "leaf.txt"
    leaf.write_text("original", encoding="utf-8")
    displaced = repository / "displaced-leaf.txt"

    def swap(phase: str, path: Path) -> None:
        if phase == "before-leaf-delete" and path == leaf:
            leaf.rename(displaced)
            leaf.write_text("replacement", encoding="utf-8")

    sidecar_builder._remove_entry_windows(leaf, phase_hook=swap)

    assert leaf.read_text(encoding="utf-8") == "replacement"
    assert not displaced.exists()


def test_native_prepare_invokes_the_builder_with_isolated_python() -> None:
    package_json = (Path(__file__).parents[2] / "apps" / "desktop" / "package.json").read_text(
        encoding="utf-8"
    )

    assert "--frozen python -I ../../scripts/build-engine-sidecar.py" in package_json


def test_pyinstaller_command_uses_isolated_python(sidecar_builder: Any) -> None:
    command = sidecar_builder._pyinstaller_command(
        source_root=Path("source"),
        work=Path("work"),
        spec=Path("spec"),
        dist=Path("dist"),
        entry=Path("entry.py"),
    )

    assert command[:4] == [sys.executable, "-I", "-m", "PyInstaller"]


def test_pyinstaller_excludes_type_checker_plugins_without_excluding_runtime(
    sidecar_builder: Any,
) -> None:
    from PyInstaller.__main__ import generate_parser  # type: ignore[import-untyped]

    command = sidecar_builder._pyinstaller_command(
        source_root=Path("source"),
        work=Path("work"),
        spec=Path("spec"),
        dist=Path("dist"),
        entry=Path("entry.py"),
    )
    options = generate_parser().parse_args(command[4:])

    # Pydantic's collection hook otherwise discovers these development plugins
    # and pulls the installed mypy compiler into the runtime sidecar.
    assert set(options.excludes) == {"mypy", "pydantic.mypy", "pydantic.v1.mypy"}


class InjectedCrash(BaseException):
    pass


def publication_paths(repository: Path) -> tuple[Path, Path, Path, Path]:
    resources = repository / "apps" / "desktop" / "src-tauri" / "resources"
    return (
        resources / ".engine-next",
        resources / "engine",
        resources / ".engine-previous",
        resources / ".engine-publish.json",
    )


def write_engine(path: Path, marker: str) -> None:
    path.mkdir()
    (path / "marker.txt").write_text(marker, encoding="utf-8")
    executable_name = "zombie-killer-engine.exe" if os.name == "nt" else "zombie-killer-engine"
    (path / executable_name).write_text("test executable", encoding="utf-8")
    entries = []
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        payload = child.read_bytes()
        entries.append(
            {
                "path": child.name,
                "type": "file",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest = {
        "format": "pyinstaller-onedir",
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": platform.python_version(),
        "pyinstaller": "6.18.0",
        "source_date_epoch": "1700000000",
        "entries": entries,
    }
    (path / "BUILD-MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def engine_marker(path: Path) -> str:
    return (path / "marker.txt").read_text(encoding="utf-8")


def test_publish_failure_after_previous_rename_rolls_back_before_returning(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def fail(phase: str) -> None:
        if phase == "after-previous-renamed":
            raise RuntimeError("injected publication failure")

    with pytest.raises(RuntimeError, match="injected publication failure"):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=fail,
        )

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_crash_after_previous_rename_is_recovered_to_last_good(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def crash(phase: str) -> None:
        if phase == "after-previous-renamed":
            raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=crash,
        )

    assert engine_marker(previous) == "old"
    assert engine_marker(candidate) == "new"
    assert not destination.exists()
    assert journal.is_file()

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_crash_after_candidate_rename_rolls_back_uncommitted_candidate(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def crash(phase: str) -> None:
        if phase == "after-candidate-renamed":
            raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=crash,
        )

    assert engine_marker(destination) == "new"
    assert engine_marker(previous) == "old"
    assert journal.is_file()

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_crash_after_commit_record_finishes_committed_publication(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def crash(phase: str) -> None:
        if phase == "after-candidate-committed":
            raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=crash,
        )

    assert engine_marker(destination) == "new"
    assert engine_marker(previous) == "old"
    assert journal.is_file()

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "new"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_committed_recovery_restores_valid_previous_when_destination_is_corrupt(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(destination, "new")
    write_engine(previous, "old")
    (destination / "marker.txt").write_text("corrupt-after-manifest", encoding="utf-8")
    sidecar_builder._write_publication_journal(
        journal,
        repository,
        phase="candidate-committed",
        had_destination=True,
    )

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_candidate_seal_failure_never_commits_or_moves_last_good(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def fail_seal(_candidate: Path) -> None:
        raise OSError("injected candidate seal failure")

    monkeypatch.setattr(sidecar_builder, "_seal_candidate_durable", fail_seal, raising=False)

    with pytest.raises(OSError, match="injected candidate seal failure"):
        sidecar_builder._publish(candidate, destination, previous, journal, repository)

    assert engine_marker(candidate) == "new"
    assert engine_marker(destination) == "old"
    assert not previous.exists()
    assert not journal.exists()


def test_candidate_seal_flushes_manifest_and_files_before_directories_bottom_up(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, _destination, _previous, _journal = publication_paths(repository)
    write_engine(candidate, "new")
    nested = candidate / "nested"
    nested.mkdir()
    nested_file = nested / "payload.bin"
    nested_file.write_bytes(b"payload")
    events: list[tuple[str, Path]] = []

    sidecar_builder._seal_candidate_durable(
        candidate,
        phase_hook=lambda phase, path: events.append((phase, path)),
    )

    assert ("sealed-file", candidate / "BUILD-MANIFEST.json") in events
    assert ("sealed-file", nested_file) in events
    assert events.index(("sealed-file", nested_file)) < events.index(("sealed-directory", nested))
    root_index = events.index(("sealed-directory", candidate))
    assert all(
        index < root_index
        for index, (phase, _path) in enumerate(events)
        if phase in {"sealed-file", "sealed-directory"} and index != root_index
    )


def test_crash_after_candidate_seal_recovers_without_touching_last_good(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def crash(phase: str) -> None:
        if phase == "after-candidate-sealed":
            raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=crash,
        )

    assert engine_marker(candidate) == "new"
    assert engine_marker(destination) == "old"
    assert not previous.exists()
    assert not journal.exists()

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()


def test_live_publish_fails_if_postseal_corruption_restores_last_good(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def corrupt_after_seal(phase: str) -> None:
        if phase == "after-candidate-sealed":
            (candidate / "marker.txt").write_text("corrupt", encoding="utf-8")

    with pytest.raises(RuntimeError, match="failed validation"):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=corrupt_after_seal,
        )

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_rollback_rename_failure_preserves_last_good_for_later_recovery(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")
    real_rename = sidecar_builder._rename_durable

    def fail_restore(source: Path, target: Path) -> None:
        if source == previous and target == destination:
            raise OSError("injected rollback rename failure")
        real_rename(source, target)

    monkeypatch.setattr(sidecar_builder, "_rename_durable", fail_restore)

    def fail(phase: str) -> None:
        if phase == "after-previous-renamed":
            raise RuntimeError("injected publication failure")

    with pytest.raises(OSError, match="injected rollback rename failure"):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=fail,
        )

    assert engine_marker(previous) == "old"
    assert engine_marker(candidate) == "new"
    assert not destination.exists()
    assert journal.is_file()

    monkeypatch.setattr(sidecar_builder, "_rename_durable", real_rename)
    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_rollback_failure_after_candidate_move_keeps_both_verified_copies(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")
    real_rename = sidecar_builder._rename_durable

    def fail_last_good_restore(source: Path, target: Path) -> None:
        if source == previous and target == destination:
            raise OSError("injected post-candidate rollback failure")
        real_rename(source, target)

    monkeypatch.setattr(sidecar_builder, "_rename_durable", fail_last_good_restore)

    def fail(phase: str) -> None:
        if phase == "after-candidate-renamed":
            raise RuntimeError("injected pre-commit failure")

    with pytest.raises(OSError, match="injected post-candidate rollback failure"):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=fail,
        )

    assert engine_marker(candidate) == "new"
    assert engine_marker(previous) == "old"
    assert not destination.exists()
    assert journal.is_file()

    monkeypatch.setattr(sidecar_builder, "_rename_durable", real_rename)
    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_corrupt_publication_journal_preserves_every_engine_copy(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "current")
    write_engine(previous, "old")
    journal.write_text("not-json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="publication journal"):
        sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(candidate) == "new"
    assert engine_marker(destination) == "current"
    assert engine_marker(previous) == "old"
    assert journal.read_text(encoding="utf-8") == "not-json"


def test_orphan_candidate_before_first_journal_is_discarded_for_clean_rebuild(
    sidecar_builder: Any, repository: Path
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "validated-but-uncommitted")

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert not candidate.exists()
    assert not destination.exists()
    assert not previous.exists()
    assert not journal.exists()


@pytest.mark.parametrize(
    "crash_phase",
    [
        "after-journal-prepared",
        "after-previous-renamed",
        "after-previous-journaled",
        "after-candidate-renamed",
    ],
)
def test_every_precommit_crash_phase_recovers_last_good(
    sidecar_builder: Any, repository: Path, crash_phase: str
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")

    def crash(phase: str) -> None:
        if phase == crash_phase:
            raise InjectedCrash()

    with pytest.raises(InjectedCrash):
        sidecar_builder._publish(
            candidate,
            destination,
            previous,
            journal,
            repository,
            phase_hook=crash,
        )

    sidecar_builder._recover_publication(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_candidate_rename_failure_rolls_back_and_preserves_last_good(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")
    real_rename = sidecar_builder._rename_durable

    def fail_candidate(source: Path, target: Path) -> None:
        if source == candidate and target == destination:
            raise OSError("injected candidate rename failure")
        real_rename(source, target)

    monkeypatch.setattr(sidecar_builder, "_rename_durable", fail_candidate)

    with pytest.raises(OSError, match="injected candidate rename failure"):
        sidecar_builder._publish(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_previous_rename_failure_never_removes_current_or_candidate(
    sidecar_builder: Any,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, destination, previous, journal = publication_paths(repository)
    write_engine(candidate, "new")
    write_engine(destination, "old")
    real_rename = sidecar_builder._rename_durable

    def fail_previous(source: Path, target: Path) -> None:
        if source == destination and target == previous:
            raise OSError("injected previous rename failure")
        real_rename(source, target)

    monkeypatch.setattr(sidecar_builder, "_rename_durable", fail_previous)

    with pytest.raises(OSError, match="injected previous rename failure"):
        sidecar_builder._publish(candidate, destination, previous, journal, repository)

    assert engine_marker(destination) == "old"
    assert not candidate.exists()
    assert not previous.exists()
    assert not journal.exists()


def test_unlocked_crash_stale_lock_does_not_block_recovery(
    sidecar_builder: Any, repository: Path
) -> None:
    lock = generated(repository, ".engine-build.lock")
    lock.write_text("999999999\n", encoding="ascii")

    with sidecar_builder._exclusive_build_lock(lock, repository):
        assert lock.is_file()


def test_live_build_lock_still_rejects_a_second_owner(
    sidecar_builder: Any, repository: Path
) -> None:
    lock = generated(repository, ".engine-build.lock")

    with (
        sidecar_builder._exclusive_build_lock(lock, repository),
        pytest.raises(RuntimeError, match="another sidecar build"),
        sidecar_builder._exclusive_build_lock(lock, repository),
    ):
        raise AssertionError("the second owner must never enter")


def smoke_response() -> str:
    return json.dumps(
        {
            "protocol_version": "1.0",
            "request_id": "11111111-1111-4111-8111-111111111111",
            "method": "system.info",
            "ok": True,
            "result": {"local_only": True, "network_listener": False},
        }
    )


def test_smoke_injects_fresh_internal_state_and_cleans_it(
    sidecar_builder: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    executable = staging / "zombie-killer-engine.exe"
    executable.write_bytes(b"placeholder")
    observed: dict[str, Path] = {}

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        option = command.index("--internal-state-root")
        state_root = Path(command[option + 1])
        assert state_root.is_absolute()
        assert state_root.exists()
        assert not any(state_root.iterdir())
        (state_root / "state").mkdir()
        (state_root / "state" / "zombie-killer.sqlite3").write_bytes(b"smoke-only")
        observed["state_root"] = state_root
        return subprocess.CompletedProcess(command, 0, smoke_response(), "")

    monkeypatch.setattr(sidecar_builder.subprocess, "run", run)

    sidecar_builder._smoke(executable, staging)

    assert "state_root" in observed
    assert not observed["state_root"].exists()


def test_nonisolated_builder_rejects_script_directory_shadow_modules(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "build-engine-sidecar.py"
    copied = tmp_path / source.name
    copied.write_bytes(source.read_bytes())
    marker = tmp_path / "shadow-loaded.txt"
    (tmp_path / "json.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, str(copied)],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "must be launched with isolated Python (-I)" in completed.stderr
    assert not marker.exists()
