from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from python_package_artifacts import (  # noqa: E402
    PYTHON_DISTRIBUTIONS,
    inspect_python_distributions,
)


def _metadata(
    name: str,
    *,
    license_files: tuple[str, ...] = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"),
) -> bytes:
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {name}",
        "Version: 0.1.0a1",
        "License-Expression: Apache-2.0",
        *(f"License-File: {item}" for item in license_files),
        "",
        "fixture",
    ]
    return "\n".join(lines).encode()


def _add_tar_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(data))


def _build_fixture_archives(
    output: Path,
    *,
    wheel_notice_override: bytes | None = None,
    sdist_legal_files: tuple[str, ...] = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"),
    metadata_license_files: tuple[str, ...] = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"),
) -> None:
    output.mkdir()
    for spec in PYTHON_DISTRIBUTIONS:
        source = REPOSITORY_ROOT / spec.source_root
        metadata = _metadata(spec.distribution_name, license_files=metadata_license_files)
        dist_info = f"{spec.normalized_name}-0.1.0a1.dist-info"
        wheel = output / f"{spec.normalized_name}-0.1.0a1-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(f"{dist_info}/METADATA", metadata)
            for legal_file in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
                data = (source / legal_file).read_bytes()
                if legal_file == "NOTICE" and wheel_notice_override is not None:
                    data = wheel_notice_override
                archive.writestr(f"{dist_info}/licenses/{legal_file}", data)

        prefix = f"{spec.normalized_name}-0.1.0a1"
        sdist = output / f"{prefix}.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            _add_tar_bytes(archive, f"{prefix}/PKG-INFO", metadata)
            for legal_file in sdist_legal_files:
                _add_tar_bytes(
                    archive,
                    f"{prefix}/{legal_file}",
                    (source / legal_file).read_bytes(),
                )


def test_accepts_exact_package_legal_files_and_metadata(tmp_path: Path) -> None:
    _build_fixture_archives(tmp_path / "dist")

    assert inspect_python_distributions(REPOSITORY_ROOT, tmp_path / "dist") == []


def test_rejects_archive_legal_bytes_that_differ_from_package_source(tmp_path: Path) -> None:
    _build_fixture_archives(tmp_path / "dist", wheel_notice_override=b"wrong notice\n")

    issues = inspect_python_distributions(REPOSITORY_ROOT, tmp_path / "dist")

    assert any("NOTICE bytes differ from package source" in issue for issue in issues)


@pytest.mark.parametrize(
    ("sdist_legal_files", "metadata_license_files", "expected"),
    [
        (
            ("LICENSE", "NOTICE"),
            ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"),
            "missing legal file THIRD_PARTY_NOTICES.md",
        ),
        (
            ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"),
            ("LICENSE", "NOTICE"),
            "License-File metadata must list exactly",
        ),
    ],
)
def test_rejects_missing_archive_file_or_metadata_declaration(
    tmp_path: Path,
    sdist_legal_files: tuple[str, ...],
    metadata_license_files: tuple[str, ...],
    expected: str,
) -> None:
    _build_fixture_archives(
        tmp_path / "dist",
        sdist_legal_files=sdist_legal_files,
        metadata_license_files=metadata_license_files,
    )

    issues = inspect_python_distributions(REPOSITORY_ROOT, tmp_path / "dist")

    assert any(expected in issue for issue in issues)
