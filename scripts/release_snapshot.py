#!/usr/bin/env python3
"""Build and package a deterministic local cutover snapshot.

The snapshot always contains the Rust ``symfritz`` primary and the Go
``symfritz-go`` rollback binary in the same archive. It is deliberately limited
to the host target; the release workflow runs the same packager per native CI
matrix target.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_manifest import (  # noqa: E402
    archive_name,
    build_manifest,
    binary_names,
    parse_targets,
)


def host_target() -> tuple[str, str]:
    os_name = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(
        platform.system()
    )
    arch = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine()
    )
    if not os_name or not arch:
        raise RuntimeError(f"unsupported local host: {platform.system()} {platform.machine()}")
    return os_name, arch


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def run_json(binary: Path, args: list[str], *, env: dict[str, str], cwd: Path) -> dict[str, object]:
    result = subprocess.run(
        [str(binary), *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    )
    if result.stderr:
        raise RuntimeError(f"{binary.name} emitted diagnostics on stdout check")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{binary.name} returned a non-object version payload")
    return payload


def config_fixture(binary: Path, home: Path, *, cwd: Path) -> bytes:
    env = os.environ.copy()
    env.update({"HOME": str(home), "USERPROFILE": str(home)})
    run([str(binary), "config", "init", "--force"], cwd=cwd, env=env)
    path = home / ".config" / "symfritz" / "config.toml"
    if not path.is_file():
        raise RuntimeError(f"{binary.name} did not write {path}")
    if os.name != "nt" and path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError(f"{binary.name} wrote config with unsafe mode")
    return path.read_bytes()


def add_tar_member(tar: tarfile.TarFile, name: str, data: bytes, executable: bool) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755 if executable else 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, __import__("io").BytesIO(data))


def package_archive(
    root: Path, out: Path, version: str, os_name: str, arch: str, rust: Path, go: Path
) -> Path:
    name = archive_name(version, os_name, arch)
    path = out / name
    rust_name, go_name = binary_names(os_name)
    files = [
        (rust_name, rust.read_bytes(), True),
        (go_name, go.read_bytes(), True),
        ("LICENSE", (root / "LICENSE").read_bytes(), False),
        ("README.md", (root / "README.md").read_bytes(), False),
    ]
    if os_name == "windows":
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for member_name, data, executable in sorted(files):
                info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ((0o755 if executable else 0o644) << 16)
                archive.writestr(info, data)
    else:
        raw = __import__("io").BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for member_name, data, executable in sorted(files):
                add_tar_member(archive, member_name, data, executable)
        with path.open("wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0, filename="") as compressed:
                compressed.write(raw.getvalue())
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="0.0.0-dev")
    parser.add_argument("--out", type=Path, default=Path("dist/snapshot"))
    parser.add_argument("--target", help="OS/ARCH; defaults to the current host")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--skip-runtime-validation",
        action="store_true",
        help="package a cross-compiled target without executing foreign binaries",
    )
    parser.add_argument("--rust-bin", type=Path)
    parser.add_argument("--go-bin", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os_name, arch = parse_targets([args.target] if args.target else ["/".join(host_target())])[0]
    out = (root / args.out).resolve() if not args.out.is_absolute() else args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build_dir = out / ".build"
    build_dir.mkdir(exist_ok=True)
    suffix = ".exe" if os_name == "windows" else ""
    rust = args.rust_bin.resolve() if args.rust_bin else build_dir / f"symfritz{suffix}"
    go = args.go_bin.resolve() if args.go_bin else build_dir / f"symfritz-go{suffix}"
    if not args.skip_build:
        env = os.environ.copy()
        env["SYMFRITZ_VERSION"] = args.version
        run(["cargo", "build", "--release", "--locked", "-p", "symfritz-cli"], cwd=root, env=env)
        rust_source = root / "target" / "release" / f"symfritz{suffix}"
        if not rust_source.is_file():
            raise RuntimeError(f"missing Rust release binary: {rust_source}")
        shutil.copy2(rust_source, rust)
        run(
            [
                "go",
                "build",
                "-ldflags",
                f"-s -w -X main.version={args.version}",
                "-o",
                str(go),
                "./cmd/symfritz",
            ],
            cwd=root,
            env={**os.environ, "CGO_ENABLED": "0"},
        )
    for binary in (rust, go):
        if not binary.is_file():
            raise RuntimeError(f"missing input binary: {binary}")
    if not args.skip_runtime_validation:
        env = os.environ.copy()
        with tempfile.TemporaryDirectory(prefix="symfritz-cutover-") as temp:
            temp_path = Path(temp)
            rust_version = run_json(rust, ["version", "--json"], env=env, cwd=root)
            go_version = run_json(go, ["version", "--json"], env=env, cwd=root)
            expected = {"tool": "symfritz", "version": args.version, "schema_version": 1}
            if rust_version != expected or go_version != expected:
                raise RuntimeError(
                    f"version contract mismatch: rust={rust_version!r} go={go_version!r} expected={expected!r}"
                )
            rust_config = config_fixture(rust, temp_path / "rust-home", cwd=root)
            go_config = config_fixture(go, temp_path / "go-home", cwd=root)
            if rust_config != go_config:
                raise RuntimeError("Rust and Go config init bytes differ")
    package_archive(root, out, args.version, os_name, arch, rust, go)
    manifest = build_manifest(args.version, out, [(os_name, arch)])
    manifest_path = out / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
