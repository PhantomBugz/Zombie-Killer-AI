from __future__ import annotations

import argparse
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath

LEGAL_FILES = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md")
PACKAGE_PATHS = (Path("services/engine"), Path("packages/sdk-python"))
LICENSE_EXPRESSION = "Apache-2.0"


@dataclass(frozen=True)
class DistributionReport:
    artifact_count: int
    legal_file_count: int


@dataclass(frozen=True)
class PackageContract:
    name: str
    artifact_name: str
    version: str
    source_root: Path
    legal_content: dict[str, bytes]


def _artifact_name(project_name: str) -> str:
    return project_name.replace("-", "_").replace(".", "_")


def _load_contract(repository_root: Path, relative_root: Path) -> PackageContract:
    source_root = repository_root / relative_root
    configuration = tomllib.loads((source_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = configuration.get("project")
    if not isinstance(project, dict):
        raise RuntimeError(f"{relative_root}: pyproject.toml has no [project] table")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise RuntimeError(f"{relative_root}: project name and version must be strings")
    if project.get("license") != LICENSE_EXPRESSION:
        raise RuntimeError(f"{name}: project license must be {LICENSE_EXPRESSION}")
    declared_legal = project.get("license-files")
    if declared_legal != list(LEGAL_FILES):
        raise RuntimeError(f"{name}: license-files must list the reviewed legal files exactly")

    legal_content: dict[str, bytes] = {}
    for legal_name in LEGAL_FILES:
        legal_path = source_root / legal_name
        if not legal_path.is_file():
            raise RuntimeError(f"{name}: source {legal_name} is missing")
        legal_content[legal_name] = legal_path.read_bytes()
    return PackageContract(
        name=name,
        artifact_name=_artifact_name(name),
        version=version,
        source_root=source_root,
        legal_content=legal_content,
    )


def _metadata(raw: bytes, *, package_name: str, location: str, version: str) -> Message:
    message = BytesParser(policy=default).parsebytes(raw)
    expected = {
        "Name": package_name,
        "Version": version,
        "License-Expression": LICENSE_EXPRESSION,
    }
    for field, expected_value in expected.items():
        if message.get(field) != expected_value:
            raise RuntimeError(f"{package_name}: {location} {field} must be {expected_value}")
    if message.get_all("License-File", []) != list(LEGAL_FILES):
        raise RuntimeError(
            f"{package_name}: {location} License-File fields must list the reviewed files exactly"
        )
    return message


def _read_unique_wheel_member(
    archive: zipfile.ZipFile,
    member_name: str,
    *,
    package_name: str,
) -> bytes:
    matches = [entry for entry in archive.infolist() if entry.filename == member_name]
    if len(matches) != 1 or matches[0].is_dir():
        raise RuntimeError(f"{package_name}: wheel must contain one regular {member_name}")
    return archive.read(matches[0])


def _read_unique_sdist_member(
    archive: tarfile.TarFile,
    member_name: str,
    *,
    package_name: str,
) -> bytes:
    matches = [entry for entry in archive.getmembers() if entry.name == member_name]
    if len(matches) != 1 or not matches[0].isfile():
        raise RuntimeError(f"{package_name}: sdist must contain one regular {member_name}")
    stream = archive.extractfile(matches[0])
    if stream is None:
        raise RuntimeError(f"{package_name}: sdist member {member_name} cannot be read")
    return stream.read()


def _validate_wheel_member_names(
    entries: list[zipfile.ZipInfo],
    *,
    package_name: str,
) -> None:
    casefolded_paths: dict[str, str] = {}
    for entry in entries:
        original_name = entry.orig_filename
        if "\\" in original_name:
            raise RuntimeError(f"{package_name}: wheel member paths must not contain backslashes")
        path_name = original_name[:-1] if entry.is_dir() else original_name
        raw_parts = path_name.split("/")
        parsed_path = PurePosixPath(path_name)
        if (
            not path_name
            or parsed_path.is_absolute()
            or parsed_path.as_posix() != path_name
            or any(part in {"", ".", ".."} for part in raw_parts)
            or any(part.endswith((" ", ".")) for part in raw_parts)
            or any(any(character in '<>:"|?*' for character in part) for part in raw_parts)
            or "\x00" in path_name
        ):
            raise RuntimeError(f"{package_name}: wheel member path is noncanonical")
        folded_name = path_name.casefold()
        previous = casefolded_paths.get(folded_name)
        if previous is not None:
            raise RuntimeError(f"{package_name}: wheel contains a case-insensitive path collision")
        casefolded_paths[folded_name] = original_name


def _verify_wheel(path: Path, contract: PackageContract) -> int:
    dist_info = f"{contract.artifact_name}-{contract.version}.dist-info"
    with zipfile.ZipFile(path, "r") as archive:
        entries = archive.infolist()
        _validate_wheel_member_names(entries, package_name=contract.name)
        metadata_members = [
            entry for entry in entries if entry.filename.casefold().endswith(".dist-info/metadata")
        ]
        expected_metadata = f"{dist_info}/METADATA"
        if (
            len(metadata_members) != 1
            or metadata_members[0].filename != expected_metadata
            or metadata_members[0].is_dir()
        ):
            raise RuntimeError(
                f"{contract.name}: wheel must contain exactly one expected .dist-info/METADATA"
            )

        expected_legal_members = {
            f"{dist_info}/licenses/{legal_name}" for legal_name in LEGAL_FILES
        }
        archive_legal_members = [
            entry for entry in entries if ".dist-info/licenses/" in entry.filename.casefold()
        ]
        if (
            len(archive_legal_members) != len(expected_legal_members)
            or {entry.filename for entry in archive_legal_members} != expected_legal_members
            or any(entry.is_dir() for entry in archive_legal_members)
        ):
            raise RuntimeError(
                f"{contract.name}: wheel license directory must contain exactly "
                f"{', '.join(LEGAL_FILES)}"
            )

        raw_metadata = _read_unique_wheel_member(
            archive,
            expected_metadata,
            package_name=contract.name,
        )
        _metadata(
            raw_metadata,
            package_name=contract.name,
            location="wheel METADATA",
            version=contract.version,
        )
        for legal_name, expected_content in contract.legal_content.items():
            member = f"{dist_info}/licenses/{legal_name}"
            actual_content = _read_unique_wheel_member(
                archive,
                member,
                package_name=contract.name,
            )
            if actual_content != expected_content:
                raise RuntimeError(f"{contract.name}: wheel {legal_name} differs from source")
    return len(contract.legal_content)


def _verify_sdist(path: Path, contract: PackageContract) -> int:
    root = PurePosixPath(f"{contract.artifact_name}-{contract.version}")
    with tarfile.open(path, "r:gz") as archive:
        raw_metadata = _read_unique_sdist_member(
            archive,
            str(root / "PKG-INFO"),
            package_name=contract.name,
        )
        _metadata(
            raw_metadata,
            package_name=contract.name,
            location="sdist PKG-INFO",
            version=contract.version,
        )
        for legal_name, expected_content in contract.legal_content.items():
            member = str(root / legal_name)
            actual_content = _read_unique_sdist_member(
                archive,
                member,
                package_name=contract.name,
            )
            if actual_content != expected_content:
                raise RuntimeError(f"{contract.name}: sdist {legal_name} differs from source")
    return len(contract.legal_content)


def _one_artifact(dist_dir: Path, pattern: str, *, package_name: str, kind: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    if len(matches) != 1 or not matches[0].is_file():
        raise RuntimeError(f"{package_name}: expected exactly one {kind} matching {pattern}")
    return matches[0]


def verify_distributions(dist_dir: Path, repository_root: Path) -> DistributionReport:
    resolved_dist = dist_dir.resolve(strict=True)
    resolved_repository = repository_root.resolve(strict=True)
    if not resolved_dist.is_dir():
        raise RuntimeError(f"distribution path is not a directory: {resolved_dist}")

    contracts = [
        _load_contract(resolved_repository, relative_root) for relative_root in PACKAGE_PATHS
    ]
    reviewed_artifacts: set[str] = set()
    legal_file_count = 0
    for contract in contracts:
        wheel = _one_artifact(
            resolved_dist,
            f"{contract.artifact_name}-{contract.version}-*.whl",
            package_name=contract.name,
            kind="wheel",
        )
        sdist = _one_artifact(
            resolved_dist,
            f"{contract.artifact_name}-{contract.version}.tar.gz",
            package_name=contract.name,
            kind="source distribution",
        )
        reviewed_artifacts.update((wheel.name, sdist.name))
        legal_file_count += _verify_wheel(wheel, contract)
        legal_file_count += _verify_sdist(sdist, contract)

    present_artifacts = {
        entry.name for entry in resolved_dist.iterdir() if entry.name != ".gitignore"
    }
    unexpected = sorted(present_artifacts - reviewed_artifacts)
    if unexpected:
        raise RuntimeError(f"unexpected distribution artifact or entry: {', '.join(unexpected)}")
    if present_artifacts != reviewed_artifacts:
        missing = sorted(reviewed_artifacts - present_artifacts)
        raise RuntimeError(f"reviewed distribution artifacts are missing: {', '.join(missing)}")

    return DistributionReport(
        artifact_count=len(reviewed_artifacts),
        legal_file_count=legal_file_count,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify legal files and metadata in Zombie Killer Python distributions."
    )
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    report = verify_distributions(arguments.dist_dir, arguments.repository_root)
    print(
        "Verified "
        f"{report.artifact_count} Python distributions with "
        f"{report.legal_file_count} exact packaged legal files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
