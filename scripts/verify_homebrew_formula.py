#!/usr/bin/env python3
"""Verify that a Homebrew formula references the exact public release assets."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from release_manifest import TARGETS, archive_name


def checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split(None, 1)
        result[name.strip()] = digest
    return result


def validate(formula_path: Path, version: str, release_url: str, checksum_path: Path) -> None:
    text = formula_path.read_text(encoding="utf-8")
    digest = checksums(checksum_path)
    release_url = release_url.rstrip("/")

    if f'version "{version}"' not in text:
        raise ValueError("formula is missing the exact version stanza")
    if 'system "#{bin}/symfritz", "version"' not in text:
        raise ValueError("formula does not test symfritz")
    if 'system "#{bin}/symfritz-go", "version"' not in text:
        raise ValueError("formula does not test symfritz-go")

    for os_name, arch in TARGETS:
        if os_name == "windows":
            continue
        asset = archive_name(version, os_name, arch)
        expected_url = f'{release_url}/{asset}'
        expected_sha = digest.get(asset)
        if expected_sha is None:
            raise ValueError(f"checksums do not contain {asset}")
        if f'url "{expected_url}"' not in text:
            raise ValueError(f"formula does not reference {expected_url}")
        if f'sha256 "{expected_sha}"' not in text:
            raise ValueError(f"formula does not use the checksum for {asset}")

    urls = re.findall(r'^\s+url "([^"]+)"$', text, flags=re.MULTILINE)
    expected_urls = [
        f"{release_url}/{archive_name(version, os_name, arch)}"
        for os_name, arch in TARGETS
        if os_name != "windows"
    ]
    if sorted(urls) != sorted(expected_urls):
        raise ValueError(f"formula URLs {urls!r} do not equal expected public assets")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--formula", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-url", required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args()
    validate(args.formula, args.version, args.release_url, args.checksums)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
