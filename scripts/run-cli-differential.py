#!/usr/bin/env python3
"""Build the immutable Go oracle and run the CLI differential harness."""
from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ORACLE_COMMIT = "b1491793aea173eac926e1a0c9db5ba6dd4604a9"


def extract_oracle(root: Path, destination: Path) -> None:
    archive = subprocess.run(
        ["git", "-C", str(root), "archive", ORACLE_COMMIT],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise RuntimeError(f"refusing unsafe oracle archive member: {member.name}")
            # The "data" extraction filter is only available on Python 3.12+.
            # Enforce the parts of its contract we rely on explicitly, so an
            # older interpreter refuses the same members instead of silently
            # extracting under weaker rules.
            if not (member.isfile() or member.isdir()):
                raise RuntimeError(
                    f"refusing non-regular oracle archive member: {member.name}"
                )
            if member.mode & (0o4000 | 0o2000):
                raise RuntimeError(
                    f"refusing setuid/setgid oracle archive member: {member.name}"
                )
        if sys.version_info >= (3, 12):
            bundle.extractall(destination, filter="data")
        else:
            bundle.extractall(destination)


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--go", help="prebuilt immutable Go oracle binary")
    parser.add_argument("--rust", help="current Rust candidate binary")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    suffix = ".exe" if os.name == "nt" else ""
    rust = Path(args.rust).resolve() if args.rust else root / "target" / "debug" / f"symfritz{suffix}"
    if not rust.is_file():
        raise SystemExit(f"Rust candidate does not exist: {rust}; run cargo build first")

    if args.go:
        go_binary = Path(args.go).resolve()
        if not go_binary.is_file():
            raise SystemExit(f"Go oracle does not exist: {go_binary}")
        run([sys.executable, "scripts/test_cli_differential.py"], cwd=root)
        run(
            [sys.executable, "scripts/cli-differential.py", "--go", str(go_binary), "--rust", str(rust), "--root", str(root)],
            cwd=root,
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="symfritz-go-oracle-") as raw:
        oracle_root = Path(raw)
        try:
            extract_oracle(root, oracle_root)
            go_binary = oracle_root / f"symfritz-go{suffix}"
            go_env = dict(os.environ, CGO_ENABLED="0")
            run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-ldflags",
                    "-s -w -X main.version=dev",
                    "-o",
                    str(go_binary),
                    "./cmd/symfritz",
                ],
                cwd=oracle_root,
                env=go_env,
            )
            run([sys.executable, "scripts/test_cli_differential.py"], cwd=root)
            run(
                [
                    sys.executable,
                    "scripts/cli-differential.py",
                    "--go",
                    str(go_binary),
                    "--rust",
                    str(rust),
                    "--root",
                    str(root),
                ],
                cwd=root,
            )
        except (OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
            print(f"FAIL historical Go oracle differential: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
