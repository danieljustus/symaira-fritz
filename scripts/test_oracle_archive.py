#!/usr/bin/env python3
"""Exercise the actual pinned-oracle extractor, including its older-Python path."""
import base64
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oracle_runner", ROOT / "scripts/run-cli-differential.py")
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


def _archive_bytes(payload: bytes) -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as bundle:
        member = tarfile.TarInfo("source.go")
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
    return archive.getvalue()


def _python_tool(directory: Path, name: str, source: str) -> Path:
    if os.name == "nt":
        script = directory / f"{name}.py"
        script.write_text(source, encoding="utf-8")
        launcher = directory / f"{name}.cmd"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8",
        )
        return launcher
    script = directory / name
    script.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


class OracleArchiveTests(unittest.TestCase):
    def extract(self, member, version):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as bundle:
            payload = b"oracle"
            member.size = len(payload) if member.isfile() else 0
            bundle.addfile(member, io.BytesIO(payload) if member.isfile() else None)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            destination = root / "out"
            destination.mkdir()
            git = root / "git"
            git.write_bytes(b"trusted git placeholder")
            git.chmod(git.stat().st_mode | stat.S_IXUSR)
            result = subprocess.CompletedProcess([], 0, stdout=archive.getvalue())
            archive_sha256 = hashlib.sha256(archive.getvalue()).hexdigest()
            with (
                patch.object(runner.subprocess, "run", return_value=result),
                patch.object(runner.sys, "version_info", version),
                patch.object(runner, "ORACLE_ARCHIVE_SHA256", archive_sha256),
            ):
                runner.extract_oracle(ROOT, destination, git=git)
            return (destination / "source.go").read_bytes()

    def test_regular_file_on_both_extraction_paths(self):
        for version in ((3, 11), (3, 12)):
            with self.subTest(version=version):
                self.assertEqual(self.extract(tarfile.TarInfo("source.go"), version), b"oracle")

    def test_rejects_unsafe_members_on_both_paths(self):
        for version in ((3, 11), (3, 12)):
            for kind in ("traversal", "symlink", "hardlink", "fifo", "setuid", "setgid"):
                with self.subTest(version=version, kind=kind):
                    member = tarfile.TarInfo("../escape" if kind == "traversal" else "source.go")
                    if kind in ("symlink", "hardlink", "fifo"):
                        member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                        member.linkname = "../escape"
                    if kind == "setuid":
                        member.mode = 0o4755
                    if kind == "setgid":
                        member.mode = 0o2755
                    with self.assertRaises(RuntimeError):
                        self.extract(member, version)

    def test_resolves_the_exact_pinned_oracle_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            git = Path(raw) / "trusted-git"
            git.write_bytes(b"trusted git placeholder")
            git.chmod(git.stat().st_mode | stat.S_IXUSR)
            result = subprocess.CompletedProcess(
                [], 0, stdout=(runner.ORACLE_COMMIT + "\n").encode()
            )
            with patch.object(runner.subprocess, "run", return_value=result) as invoke:
                self.assertEqual(
                    runner.resolve_oracle_commit(ROOT, git=git), runner.ORACLE_COMMIT
                )
        invoke.assert_called_once_with(
            [
                str(git.resolve()),
                "-C",
                str(ROOT),
                "rev-parse",
                "--verify",
                f"{runner.ORACLE_COMMIT}^{{commit}}",
            ],
            check=True,
            capture_output=True,
            env=None,
        )

    def test_oracle_build_id_binds_commit_archive_and_toolchain(self) -> None:
        archive_sha256 = "a" * 64
        build_id = runner.oracle_build_id(archive_sha256)
        self.assertIn(runner.ORACLE_COMMIT, build_id)
        self.assertIn(archive_sha256, build_id)
        self.assertIn(runner.ORACLE_TOOLCHAIN, build_id)

    def test_rejects_a_non_pinned_go_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake_go = Path(raw) / "go"
            fake_go.write_bytes(b"not-a-go-toolchain")
            fake_go.chmod(0o755)
            with (
                patch.dict(
                    os.environ,
                    {runner.TRUSTED_GO_ENV: str(fake_go)},
                    clear=False,
                ),
                patch.object(
                    runner,
                    "_capture",
                    return_value=b"go version go1.27.1 darwin/arm64\n",
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "expected go1.26.6"):
                    runner.require_go_toolchain()

    def test_live_archive_matches_the_pinned_digest(self) -> None:
        git_value = shutil.which("git")
        if git_value is None:
            self.skipTest("Git is unavailable")
        git = Path(git_value).resolve()
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "oracle"
            destination.mkdir()
            digest = runner.extract_oracle(ROOT, destination, git=git)
            self.assertEqual(digest, runner.ORACLE_ARCHIVE_SHA256)
            self.assertTrue((destination / "cmd" / "symfritz" / "main.go").is_file())

    def test_live_archive_immune_to_hostile_autocrlf(self) -> None:
        git_value = shutil.which("git")
        if git_value is None:
            self.skipTest("Git is unavailable")
        git = Path(git_value).resolve()
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "oracle"
            destination.mkdir()
            env_override = {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.autocrlf",
                "GIT_CONFIG_VALUE_0": "true",
            }
            with patch.dict(os.environ, env_override):
                digest = runner.extract_oracle(ROOT, destination, git=git)
            self.assertEqual(digest, runner.ORACLE_ARCHIVE_SHA256)
            self.assertTrue((destination / "cmd" / "symfritz" / "main.go").is_file())

    def test_live_fake_git_cannot_supply_an_arbitrary_archive(self) -> None:
        archive = base64.b64encode(_archive_bytes(b"attacker source")).decode("ascii")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake_dir = root / "fake git;touch injected"
            fake_dir.mkdir()
            injected = root / "injected"
            fake_git = _python_tool(
                fake_dir,
                "git",
                f"""
import base64
import sys
if "rev-parse" in sys.argv:
    sys.stdout.write({runner.ORACLE_COMMIT!r} + "\\n")
elif "archive" in sys.argv:
    sys.stdout.buffer.write(base64.b64decode({archive!r}))
else:
    raise SystemExit(2)
""",
            )
            destination = root / "oracle"
            destination.mkdir()
            self.assertEqual(
                runner.resolve_oracle_commit(ROOT, git=fake_git), runner.ORACLE_COMMIT
            )
            with self.assertRaisesRegex(RuntimeError, "archive digest mismatch"):
                runner.extract_oracle(ROOT, destination, git=fake_git)
            self.assertFalse((destination / "source.go").exists())
            self.assertFalse(injected.exists())

    def test_path_shadowing_cannot_replace_trusted_git(self) -> None:
        git_value = shutil.which("git")
        if git_value is None:
            self.skipTest("Git is unavailable")
        trusted_git = Path(git_value).resolve()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake_dir = root / "fake git;touch injected"
            fake_dir.mkdir()
            marker = root / "fake-git-called"
            _python_tool(
                fake_dir,
                "git",
                f"""
from pathlib import Path
Path({str(marker)!r}).write_text("called", encoding="utf-8")
raise SystemExit(97)
""",
            )
            destination = root / "oracle"
            destination.mkdir()
            path = os.pathsep.join((str(fake_dir), os.environ.get("PATH", "")))
            with patch.dict(
                os.environ,
                {runner.TRUSTED_GIT_ENV: str(trusted_git), "PATH": path},
                clear=False,
            ):
                self.assertEqual(
                    runner.resolve_oracle_commit(ROOT), runner.ORACLE_COMMIT
                )
                self.assertEqual(
                    runner.extract_oracle(ROOT, destination),
                    runner.ORACLE_ARCHIVE_SHA256,
                )
            self.assertFalse(marker.exists())

    def test_path_shadowing_cannot_replace_trusted_go(self) -> None:
        go_value = os.environ.get(runner.TRUSTED_GO_ENV) or shutil.which("go")
        if go_value is None:
            self.skipTest("Go is unavailable")
        trusted_go = Path(go_value).resolve()
        version = subprocess.run(
            [str(trusted_go), "version"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        fields = version.split()
        if len(fields) < 3 or fields[2] != runner.ORACLE_TOOLCHAIN:
            self.skipTest(
                f"pinned Go setup is required for this live test: {version!r}"
            )
        fake_goroot = trusted_go.parent.parent
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake_dir = root / "fake go;touch injected"
            fake_dir.mkdir()
            marker = root / "fake-go-called"
            _python_tool(
                fake_dir,
                "go",
                f"""
from pathlib import Path
import sys
Path({str(marker)!r}).write_text("called", encoding="utf-8")
if sys.argv[1:] == ["version"]:
    print({version!r})
elif sys.argv[1:] == ["env", "GOVERSION"]:
    print({runner.ORACLE_TOOLCHAIN!r})
elif sys.argv[1:] == ["env", "GOROOT"]:
    print({str(fake_goroot)!r})
else:
    raise SystemExit(97)
""",
            )
            path = os.pathsep.join((str(fake_dir), os.environ.get("PATH", "")))
            with patch.dict(
                os.environ,
                {runner.TRUSTED_GO_ENV: str(trusted_go), "PATH": path},
                clear=False,
            ):
                self.assertEqual(runner.require_go_toolchain(), trusted_go)
            self.assertFalse(marker.exists())

    def test_build_oracle_uses_isolated_pinned_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            oracle_root = Path(raw)
            go = oracle_root / "go"
            go.write_bytes(b"test go path")
            with (
                patch.object(runner, "run") as build,
                patch.object(runner, "verify_oracle_binary") as verify,
            ):
                runner.build_oracle(oracle_root, go, "b" * 64)
            command = build.call_args.args[0]
            self.assertEqual(command[0], str(go))
            self.assertEqual(command[1:4], ["build", "-mod=readonly", "-trimpath"])
            self.assertIn("-buildvcs=false", command)
            ldflags = command[command.index("-ldflags") + 1]
            self.assertIn("-X main.version=dev", ldflags)
            self.assertIn(runner.ORACLE_COMMIT, ldflags)
            self.assertIn("b" * 64, ldflags)
            self.assertIn("./cmd/symfritz", command)
            output_path = Path(command[command.index("-o") + 1])
            self.assertTrue(output_path.is_relative_to(oracle_root))
            env = build.call_args.kwargs["env"]
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["CGO_ENABLED"], "0")
            self.assertTrue(env["GOCACHE"].startswith(str(oracle_root)))
            verify.assert_called_once()

    def test_runner_rejects_an_arbitrary_caller_go_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fake_go = Path(raw) / "fake-go"
            fake_go.write_text("#!/bin/sh\nexit 0\n")
            fake_go.chmod(0o755)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run-cli-differential.py"),
                    "--root",
                    str(ROOT),
                    "--rust",
                    str(fake_go),
                    "--go",
                    str(fake_go),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --go", result.stderr)
        self.assertNotIn("ORACLE_PROVENANCE", result.stdout)


if __name__ == "__main__":
    unittest.main()
