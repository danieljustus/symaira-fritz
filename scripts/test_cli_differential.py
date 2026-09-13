#!/usr/bin/env python3
"""Focused portability regressions for the CLI contract harness."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "cli-differential.py"
SPEC = importlib.util.spec_from_file_location("cli_differential", HARNESS)
assert SPEC and SPEC.loader
cli_differential = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli_differential
SPEC.loader.exec_module(cli_differential)


class CliDifferentialPortabilityTests(unittest.TestCase):
    def test_windows_path_keeps_only_mock_blocker_and_system_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            mock_dir = home / "mock-symvault"
            mock_dir.mkdir()
            path = cli_differential.isolated_path(
                home,
                mock_dir,
                {
                    "PATH": r"C:\host-tools;C:\untrusted-helper",
                    "SystemRoot": r"C:\Windows",
                },
                is_windows=True,
            )
            self.assertEqual(
                path.split(";"),
                [str(mock_dir), str(home / "empty-path"), r"C:\Windows\System32"],
            )
            self.assertTrue((home / "empty-path").is_dir())
            self.assertNotIn("host-tools", path)
            self.assertNotIn("untrusted-helper", path)

    def test_non_windows_path_blocks_host_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            path = cli_differential.isolated_path(
                home,
                None,
                {"PATH": "/host-tools:/untrusted-helper"},
                is_windows=False,
            )
            self.assertEqual(path, str(home / "empty-path"))

    def test_non_windows_helper_path_retains_runtime_tools_only_with_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            path = cli_differential.isolated_path(
                home,
                home / "helper",
                {"PATH": "/system-tools:/untrusted-helper"},
                is_windows=False,
            )
            self.assertEqual(
                path.split(":"),
                [str(home / "helper"), str(home / "empty-path"), "/system-tools", "/untrusted-helper"],
            )

    def test_temporary_directory_uses_the_platform_temp_root(self) -> None:
        with (
            mock.patch.object(cli_differential.tempfile, "gettempdir", return_value=r"C:\runner-temp"),
            mock.patch.object(cli_differential.tempfile, "TemporaryDirectory") as directory,
        ):
            cli_differential.temporary_directory("symfritz-cli-")
        directory.assert_called_once_with(prefix="symfritz-cli-", dir=r"C:\runner-temp")

    def test_same_native_executable_pair_is_rejected_before_suite_setup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "symfritz.exe"
            binary.write_bytes(b"test executable")
            stderr = io.StringIO()
            with (
                mock.patch.object(cli_differential, "private_address") as private_address,
                mock.patch.object(sys, "argv", [str(HARNESS), "--go", str(binary), "--rust", str(binary)]),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(cli_differential.main(), 1)
            private_address.assert_not_called()
            self.assertIn("reference and candidate binaries must be distinct", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
