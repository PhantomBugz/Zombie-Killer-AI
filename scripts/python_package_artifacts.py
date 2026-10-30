from __future__ import annotations

import argparse
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path

LEGAL_FILES = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")


@dataclass(frozen=True)
class PythonDistribution:
    distribution_name: str
    source_root: str

    @property
    def normalized_name(self) -> str:
        return self.distribution_name.replace("-", "_")


PYTHON_DISTRIBUTIONS = (
    PythonDistribution("zombie-killer-engine", "services/engine"),
    PythonDistribution("zombie-killer-sdk", "packages/sdk-python"),
)


def _check_metadata(data: bytes, spec: PythonDistribution, version: str, label: str) -> list[str]:
    metadata = BytesParser(policy=compat32).parsebytes(data)
    issues = []
    expected_fields = {
        "Name": spec.distribution_name,
        "Version": version,
        "License-Expression": "Apache-2.0",
    }
    for field, expected in expected_fields.items():
        if metadata.get(field) != expected:
            issues.append(f"{label}: {field} metadata must be {expected!r}")
    license_files = metadata.get_all("License-File") or []
    if len(license_files) != len(LEGAL_FILES) or sorted(license_files) != sorted(LEGAL_FILES):
        issues.append(f"{label}: License-File metadata must list exactly {', '.join(LEGAL_FILES)}")
    return issues


def _inspect_wheel(
    wheel: Path,
    repository_root: Path,
    spec: PythonDistribution,
    version: str,
) -> list[str]:
    issues = []
    try:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                return [f"{wheel.name}: expected exactly one .dist-info/METADATA file"]
            metadata_name = metadata_names[0]
            issues.extend(_check_metadata(archive.read(metadata_name), spec, version, wheel.name))

            license_prefix = f"{metadata_name.removesuffix('METADATA')}licenses/"
            archive_legal_files = [
                name.removeprefix(license_prefix)
                for name in names
                if name.startswith(license_prefix)
            ]
            if len(archive_legal_files) != len(LEGAL_FILES) or sorted(
                archive_legal_files
            ) != sorted(LEGAL_FILES):
                issues.append(
                    f"{wheel.name}: license directory must contain exactly {', '.join(LEGAL_FILES)}"
                )

            source_root = repository_root / spec.source_root
            for legal_file in LEGAL_FILES:
                member = f"{license_prefix}{legal_file}"
                if names.count(member) != 1:
                    issues.append(f"{wheel.name}: missing legal file {legal_file}")
                elif archive.read(member) != (source_root / legal_file).read_bytes():
                    issues.append(f"{wheel.name}: {legal_file} bytes differ from package source")
    except (OSError, zipfile.BadZipFile) as error:
        issues.append(f"{wheel.name}: cannot inspect wheel ({type(error).__name__})")
    return issues


def _inspect_sdist(
    sdist: Path,
    repository_root: Path,
    spec: PythonDistribution,
    version: str,
) -> list[str]:
    issues = []
    prefix = f"{spec.normalized_name}-{version}/"
    try:
        with tarfile.open(sdist, "r:gz") as archive:
            names = archive.getnames()
            metadata_name = f"{prefix}PKG-INFO"
            if names.count(metadata_name) != 1:
                return [f"{sdist.name}: expected exactly one root PKG-INFO file"]
            metadata_file = archive.extractfile(metadata_name)
            if metadata_file is None:
                return [f"{sdist.name}: PKG-INFO is not a regular file"]
            issues.extend(_check_metadata(metadata_file.read(), spec, version, sdist.name))

            source_root = repository_root / spec.source_root
            for legal_file in LEGAL_FILES:
                member = f"{prefix}{legal_file}"
                if names.count(member) != 1:
                    issues.append(f"{sdist.name}: missing legal file {legal_file}")
                    continue
                archived_file = archive.extractfile(member)
                if archived_file is None:
                    issues.append(f"{sdist.name}: legal file {legal_file} is not a regular file")
                elif archived_file.read() != (source_root / legal_file).read_bytes():
                    issues.append(f"{sdist.name}: {legal_file} bytes differ from package source")
    except (OSError, tarfile.TarError) as error:
        issues.append(f"{sdist.name}: cannot inspect source distribution ({type(error).__name__})")
    return issues


def inspect_python_distributions(repository_root: Path, dist_dir: Path) -> list[str]:
    repository_root = repository_root.resolve()
    dist_dir = dist_dir.resolve()
    issues = []
    for spec in PYTHON_DISTRIBUTIONS:
        pyproject = repository_root / spec.source_root / "pyproject.toml"
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
        version = project["version"]
        if project["name"] != spec.distribution_name:
            issues.append(f"{spec.source_root}/pyproject.toml: unexpected project name")
            continue

        wheels = sorted(dist_dir.glob(f"{spec.normalized_name}-{version}-*.whl"))
        sdists = sorted(dist_dir.glob(f"{spec.normalized_name}-{version}.tar.gz"))
        if len(wheels) != 1:
            issues.append(
                f"{spec.distribution_name}: expected exactly one wheel for version {version}"
            )
        else:
            issues.extend(_inspect_wheel(wheels[0], repository_root, spec, version))
        if len(sdists) != 1:
            issues.append(
                f"{spec.distribution_name}: expected exactly one source distribution "
                f"for version {version}"
            )
        else:
            issues.extend(_inspect_sdist(sdists[0], repository_root, spec, version))
    return issues


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Verify Python distribution legal files and metadata."
    )
    parser.add_argument("--dist", type=Path, default=repository_root / "dist")
    args = parser.parse_args()
    issues = inspect_python_distributions(repository_root, args.dist)
    if issues:
        for issue in issues:
            print(f"ERROR: {issue}")
        return 1
    print(f"Verified {len(PYTHON_DISTRIBUTIONS)} Python wheel/source-distribution pairs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
