#!/usr/bin/env python3
"""Build the immutable Go oracle and run the CLI differential harness.

The Git and Go executables must come from the trusted setup environment as
absolute paths.  The runner intentionally has no prebuilt-oracle ``--go``
override: gated evidence is always rebuilt from the pinned source archive.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

ORACLE_COMMIT = "b1491793aea173eac926e1a0c9db5ba6dd4604a9"
ORACLE_ARCHIVE_SHA256 = "7ce7e15cae0bc81e60f3e3876fa15739604efb539d1442fea6262f8b16c4bf62"
ORACLE_GO_VERSION = "1.26.6"
ORACLE_TOOLCHAIN = f"go{ORACLE_GO_VERSION}"
TRUSTED_GIT_ENV = "SYMAIRA_TRUSTED_GIT"
TRUSTED_GO_ENV = "SYMAIRA_TRUSTED_GO"


@dataclass(frozen=True)
class OracleProvenance:
    source_commit: str
    source_archive_sha256: str
    go_toolchain: str
    go_executable: str
    binary: str
    binary_sha256: str
    build_id: str


def _stdout_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _go_environment() -> dict[str, str]:
    """Ignore caller Go overrides and force the local pinned toolchain."""
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("GO"):
            env.pop(key)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off"})
    return env


def oracle_environment(root: Path) -> dict[str, str]:
    """Keep source, module, build, home, and temporary state under one temp root."""
    home = root / "home"
    cache = root / "go-cache"
    module_cache = root / "go-modcache"
    gopath = root / "go-path"
    temp = root / "tmp"
    for directory in (home, cache, module_cache, gopath, temp):
        directory.mkdir(parents=True, exist_ok=True)
    env = _go_environment()
    env.update(
        {
            "CGO_ENABLED": "0",
            "GOCACHE": str(cache),
            "GOMODCACHE": str(module_cache),
            "GOPATH": str(gopath),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TMPDIR": str(temp),
            "TMP": str(temp),
            "TEMP": str(temp),
        }
    )
    return env


def _capture(command: list[str], *, env: dict[str, str] | None = None) -> bytes:
    result = subprocess.run(command, check=True, capture_output=True, env=env)
    stdout = result.stdout
    if isinstance(stdout, str):
        return stdout.encode("ascii")
    return stdout


def _trusted_executable(
    env_name: str,
    explicit: str | Path | None,
    label: str,
) -> Path:
    raw = explicit if explicit is not None else os.environ.get(env_name)
    if not raw:
        raise RuntimeError(
            f"{label} requires an explicit absolute executable via {env_name}"
        )
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{label} path must be absolute: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(f"{label} does not exist: {path}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{label} is not executable: {resolved}")
    return resolved


def resolve_oracle_commit(root: Path, *, git: str | Path | None = None) -> str:
    """Resolve the pinned object as a commit, never a mutable ref."""
    git_path = _trusted_executable(TRUSTED_GIT_ENV, git, "trusted Git")
    output = _capture(
        [
            str(git_path),
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            f"{ORACLE_COMMIT}^{{commit}}",
        ]
    )
    resolved = output.decode("ascii").strip()
    if resolved != ORACLE_COMMIT:
        raise RuntimeError(
            f"historical oracle resolved to {resolved!r}, expected {ORACLE_COMMIT}"
        )
    return resolved


def extract_oracle(
    root: Path,
    destination: Path,
    *,
    git: str | Path | None = None,
) -> str:
    git_path = _trusted_executable(TRUSTED_GIT_ENV, git, "trusted Git")
    archive = subprocess.run(
        [
            str(git_path),
            "-C",
            str(root),
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.eol=lf",
            "archive",
            "--format=tar",
            ORACLE_COMMIT,
        ],
        check=True,
        capture_output=True,
    ).stdout
    if isinstance(archive, str):
        archive = archive.encode()
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    if archive_sha256 != ORACLE_ARCHIVE_SHA256:
        raise RuntimeError(
            f"oracle archive digest mismatch: expected {ORACLE_ARCHIVE_SHA256}, "
            f"got {archive_sha256}"
        )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        destination_root = destination.resolve()
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination_root):
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
    return archive_sha256


def require_go_toolchain() -> Path:
    """Return only the Go executable exported by the trusted setup step."""
    go = _trusted_executable(TRUSTED_GO_ENV, None, "pinned Go toolchain")
    env = _go_environment()
    version = _stdout_text(_capture([str(go), "version"], env=env)).strip()
    if not re.fullmatch(rf"go version {re.escape(ORACLE_TOOLCHAIN)} [^\s/]+/[^\s]+", version):
        raise RuntimeError(
            f"Go toolchain mismatch: expected {ORACLE_TOOLCHAIN}, got {version!r}"
        )
    reported = _stdout_text(_capture([str(go), "env", "GOVERSION"], env=env)).strip()
    if reported != ORACLE_TOOLCHAIN:
        raise RuntimeError(
            f"Go toolchain metadata mismatch: expected {ORACLE_TOOLCHAIN}, got {reported!r}"
        )
    goroot_value = _stdout_text(
        _capture([str(go), "env", "GOROOT"], env=env)
    ).strip()
    goroot_path = Path(goroot_value)
    if not goroot_path.is_absolute():
        raise RuntimeError(f"Go toolchain GOROOT must be absolute: {goroot_value!r}")
    goroot = goroot_path.resolve(strict=True)
    direct = goroot / "bin" / ("go.exe" if os.name == "nt" else "go")
    if not direct.is_file() or not os.access(direct, os.X_OK):
        raise RuntimeError(f"Go toolchain GOROOT has no executable go: {direct}")
    if direct != go:
        raise RuntimeError(
            f"Go toolchain path does not match its GOROOT executable: {go} != {direct}"
        )
    direct_version = _stdout_text(_capture([str(direct), "version"], env=env)).strip()
    if not re.fullmatch(
        rf"go version {re.escape(ORACLE_TOOLCHAIN)} [^\s/]+/[^\s]+", direct_version
    ):
        raise RuntimeError(
            f"Go GOROOT toolchain mismatch: expected {ORACLE_TOOLCHAIN}, "
            f"got {direct_version!r}"
        )
    return direct


def oracle_build_id(source_archive_sha256: str) -> str:
    """Bind the source commit, archive bytes, and toolchain into the binary."""
    return (
        f"symfritz-oracle-{ORACLE_COMMIT}-{source_archive_sha256}-{ORACLE_TOOLCHAIN}"
    )


def verify_oracle_binary(
    go: Path,
    binary: Path,
    env: dict[str, str],
    expected_build_id: str,
    *,
    source_archive_sha256: str,
) -> OracleProvenance:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Go oracle build did not produce an executable: {binary}")
    metadata = _stdout_text(_capture([str(go), "version", "-m", str(binary)], env=env))
    first_line = metadata.splitlines()[0] if metadata.splitlines() else ""
    if not re.search(rf"\b{re.escape(ORACLE_TOOLCHAIN)}\s*$", first_line):
        raise RuntimeError(
            f"Go oracle binary toolchain mismatch: expected {ORACLE_TOOLCHAIN}, "
            f"got {first_line!r}"
        )
    actual_build_id = _stdout_text(
        _capture([str(go), "tool", "buildid", str(binary)], env=env)
    ).strip()
    if actual_build_id != expected_build_id:
        raise RuntimeError(
            f"Go oracle binary provenance mismatch: expected build id "
            f"{expected_build_id!r}, got {actual_build_id!r}"
        )
    return OracleProvenance(
        source_commit=ORACLE_COMMIT,
        source_archive_sha256=source_archive_sha256,
        go_toolchain=ORACLE_TOOLCHAIN,
        go_executable=str(go),
        binary=str(binary),
        binary_sha256=_sha256_file(binary),
        build_id=actual_build_id,
    )


def build_oracle(
    oracle_root: Path,
    go: Path,
    source_archive_sha256: str,
) -> OracleProvenance:
    env = oracle_environment(oracle_root)
    binary = oracle_root / ("symfritz-go.exe" if os.name == "nt" else "symfritz-go")
    build_id = oracle_build_id(source_archive_sha256)
    run(
        [
            str(go),
            "build",
            "-mod=readonly",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags",
            f"-s -w -buildid={build_id} -X main.version=dev",
            "-o",
            str(binary),
            "./cmd/symfritz",
        ],
        cwd=oracle_root,
        env=env,
    )
    return verify_oracle_binary(
        go,
        binary,
        env,
        build_id,
        source_archive_sha256=source_archive_sha256,
    )


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--git",
        help=f"trusted absolute Git executable (defaults to ${TRUSTED_GIT_ENV})",
    )
    parser.add_argument("--rust", help="current Rust candidate binary")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    suffix = ".exe" if os.name == "nt" else ""
    rust = Path(args.rust).expanduser().resolve() if args.rust else root / "target" / "debug" / f"symfritz{suffix}"
    if not rust.is_file():
        raise SystemExit(f"Rust candidate does not exist: {rust}; run cargo build first")

    try:
        git = _trusted_executable(TRUSTED_GIT_ENV, args.git, "trusted Git")
        go = require_go_toolchain()
        source_commit = resolve_oracle_commit(root, git=git)
        with tempfile.TemporaryDirectory(prefix="symfritz-go-oracle-") as raw:
            oracle_root = Path(raw)
            source_archive_sha256 = extract_oracle(root, oracle_root, git=git)
            provenance = build_oracle(oracle_root, go, source_archive_sha256)
            if provenance.source_commit != source_commit:
                raise RuntimeError(
                    f"oracle provenance commit changed: {provenance.source_commit}"
                )
            print(
                "ORACLE_PROVENANCE "
                f"source_commit={provenance.source_commit} "
                f"source_archive_sha256={provenance.source_archive_sha256} "
                f"go_toolchain={provenance.go_toolchain} "
                f"go_executable={provenance.go_executable} "
                f"binary_sha256={provenance.binary_sha256} "
                f"build_id={provenance.build_id}"
            )
            run([sys.executable, "scripts/test_cli_differential.py"], cwd=root)
            run(
                [
                    sys.executable,
                    "scripts/cli-differential.py",
                    "--go",
                    provenance.binary,
                    "--rust",
                    str(rust),
                    "--root",
                    str(root),
                ],
                cwd=root,
            )
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"FAIL historical Go oracle differential: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
