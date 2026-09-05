#!/usr/bin/env python3
"""Render the maintained Homebrew formula for the dual-binary archive."""
from __future__ import annotations

import argparse
from pathlib import Path

from release_manifest import archive_name


def checksums(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split(None, 1)
        result[name.strip()] = digest
    return result


def formula(version: str, release_url: str, digest: dict[str, str]) -> str:
    def block(os_name: str, condition: str) -> str:
        rows = []
        for arch, homebrew_condition in (("amd64", "Hardware::CPU.intel?"), ("arm64", "Hardware::CPU.arm?")):
            asset = archive_name(version, os_name, arch)
            rows.append(
                f'''    if {homebrew_condition}{" && Hardware::CPU.is_64_bit?" if os_name == "linux" else ""}\n'''
                f'''      url "{release_url}/{asset}"\n'''
                f'''      sha256 "{digest[asset]}"\n\n'''
                f'''      define_method(:install) do\n'''
                f'''        bin.install "symfritz"\n'''
                f'''        bin.install "symfritz-go"\n'''
                f'''      end\n'''
                f'''    end'''
            )
        return f"  {block_header(os_name)}\n" + "\n".join(rows) + "\n  end"

    def block_header(os_name: str) -> str:
        return "on_macos do" if os_name == "darwin" else "on_linux do"

    return f'''# typed: false
# frozen_string_literal: true

# Generated from the dual-binary release archive. Do not edit manually.
class Symfritz < Formula
  desc "CLI to administer, analyse, and control an AVM FRITZ!Box"
  homepage "https://github.com/danieljustus/symaira-fritz"
  version "{version}"
  license "Apache-2.0"

{block("darwin", "")}

{block("linux", "")}

  test do
    system "#{{bin}}/symfritz", "version"
    system "#{{bin}}/symfritz-go", "version"
  end
end
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-url", required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(
        formula(args.version, args.release_url.rstrip("/"), checksums(args.checksums)),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
