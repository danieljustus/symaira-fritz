#!/usr/bin/env python3
"""Generate and validate the Rust cutover release manifest.

The manifest is intentionally independent of GoReleaser so a single publisher
can ship the Rust primary and Go fallback in one archive per target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable

TARGETS = (
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
)


def archive_name(version: str, os_name: str, arch: str) -> str:
    suffix = "zip" if os_name == "windows" else "tar.gz"
    return f"symaira-fritz_{version}_{os_name}_{arch}.{suffix}"


def binary_names(os_name: str) -> tuple[str, str]:
    suffix = ".exe" if os_name == "windows" else ""
    return (f"symfritz{suffix}", f"symfritz-go{suffix}")


def parse_targets(values: Iterable[str]) -> list[tuple[str, str]]:
    targets = []
    for value in values:
        try:
            os_name, arch = value.split("/", 1)
        except ValueError as exc:
            raise ValueError(f"target must be OS/ARCH, got {value!r}") from exc
        if (os_name, arch) not in TARGETS:
            raise ValueError(f"unsupported target {value!r}")
        targets.append((os_name, arch))
    if len(set(targets)) != len(targets):
        raise ValueError("duplicate target")
    return targets


def archive_members(path: Path) -> list[str]:
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return sorted(member.name for member in archive.getmembers() if member.isfile())
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            return sorted(name for name in archive.namelist() if not name.endswith("/"))
    raise ValueError(f"unsupported archive type: {path}")


def expected_members(os_name: str) -> list[str]:
    rust, fallback = binary_names(os_name)
    return sorted(["LICENSE", "README.md", rust, fallback])


def validate_archive(path: Path, version: str, os_name: str, arch: str) -> dict[str, object]:
    expected_name = archive_name(version, os_name, arch)
    if path.name != expected_name:
        raise ValueError(f"expected {expected_name}, got {path.name}")
    actual = archive_members(path)
    expected = expected_members(os_name)
    if actual != expected:
        raise ValueError(f"{path.name}: contents {actual!r} != {expected!r}")
    return {
        "name": path.name,
        "os": os_name,
        "arch": arch,
        "format": "zip" if os_name == "windows" else "tar.gz",
        "contents": expected,
        "sha256": sha256(path),
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(version: str, dist: Path, targets: Iterable[tuple[str, str]]) -> dict[str, object]:
    target_list = list(targets)
    archives = []
    for os_name, arch in target_list:
        path = dist / archive_name(version, os_name, arch)
        if not path.is_file():
            raise ValueError(f"missing release archive: {path}")
        archives.append(validate_archive(path, version, os_name, arch))
    return {
        "schema_version": 1,
        "version": version,
        "binary_names": {"rust_primary": "symfritz", "go_fallback": "symfritz-go"},
        "targets": [
            {
                "os": os_name,
                "arch": arch,
                "archive": archive_name(version, os_name, arch),
                "format": "zip" if os_name == "windows" else "tar.gz",
                "binaries": list(binary_names(os_name)),
            }
            for os_name, arch in target_list
        ],
        "archives": archives,
    }


def write_checksums(dist: Path, output: Path) -> None:
    files = sorted(
        path for path in dist.iterdir() if path.is_file() and path.name != output.name
    )
    output.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksums", action="store_true")
    args = parser.parse_args()
    try:
        if args.checksums:
            write_checksums(args.dist, args.output)
        else:
            values = args.targets or [f"{os_name}/{arch}" for os_name, arch in TARGETS]
            targets = parse_targets(values)
            manifest = build_manifest(args.version, args.dist, targets)
            args.output.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
