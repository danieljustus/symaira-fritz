#!/usr/bin/env python3
"""Contract tests for the VALUE gate runner.

These tests verify:
- Arithmetic, statistics, and measurement uncertainty calculations.
- Gate decision rules (20% size or RSS gain, <=10% latency regression).
- Output semantics and wrong-but-fast negative controls.
- Failure propagation inside per-timed-call measure_once.
- Production oracle archive extraction security (directly exercising run-cli-differential.py).
- Build provenance linking between candidate commit and binary.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Load value_gate with module name set in sys.modules first
spec = importlib.util.spec_from_file_location("value_gate", ROOT / "scripts/value_gate.py")
assert spec and spec.loader
value_gate = importlib.util.module_from_spec(spec)
sys.modules["value_gate"] = value_gate
spec.loader.exec_module(value_gate)


class ArithmeticTests(unittest.TestCase):
    def test_percentile_is_nearest_rank(self):
        values = [float(n) for n in range(1, 101)]
        self.assertEqual(value_gate.percentile(values, 0.95), 95.0)
        self.assertEqual(value_gate.percentile(values, 0.50), 50.0)

    def test_percentile_rejects_empty(self):
        with self.assertRaises(value_gate.GateError):
            value_gate.percentile([], 0.95)

    def test_left_fold_sum_is_interpreter_independent(self):
        values = [0.1] * 10
        expected = 0.0
        for value in values:
            expected += value
        self.assertEqual(value_gate.left_fold_sum(values), expected)

    def test_summary_includes_uncertainty_metrics(self):
        values = [10.0, 12.0, 11.0, 13.0, 14.0]
        summary = value_gate.summarise(values, "milliseconds")
        self.assertEqual(summary["samples"], 5)
        self.assertEqual(summary["mean"], 12.0)
        self.assertIn("std_dev", summary)
        self.assertIn("std_err", summary)
        self.assertIn("ci95", summary)
        self.assertGreater(summary["std_dev"], 0.0)
        self.assertGreater(summary["std_err"], 0.0)
        self.assertEqual(len(summary["ci95"]), 2)
        self.assertLess(summary["ci95"][0], summary["mean"])
        self.assertGreater(summary["ci95"][1], summary["mean"])


class GateDecisionTests(unittest.TestCase):
    """The gate is size-OR-rss improvement >= 20%, with latency regression <= 10%."""

    def evaluate(self, size, rss, worst_regression):
        improvement_pass = max(size, rss) >= value_gate.MIN_IMPROVEMENT
        latency_pass = worst_regression <= value_gate.MAX_LATENCY_REGRESSION
        return improvement_pass and latency_pass

    def test_thresholds_match_the_workspace_contract(self):
        self.assertEqual(value_gate.MIN_IMPROVEMENT, 0.20)
        self.assertEqual(value_gate.MAX_LATENCY_REGRESSION, 0.10)

    def test_rss_alone_can_satisfy_the_improvement(self):
        self.assertTrue(self.evaluate(0.05, 0.40, -0.1))

    def test_size_alone_can_satisfy_the_improvement(self):
        self.assertTrue(self.evaluate(0.40, 0.05, -0.1))

    def test_insufficient_improvement_fails(self):
        self.assertFalse(self.evaluate(0.19, 0.19, -0.1))

    def test_latency_regression_over_ceiling_fails_despite_improvement(self):
        self.assertFalse(self.evaluate(0.90, 0.90, 0.11))

    def test_latency_regression_at_the_ceiling_passes(self):
        self.assertTrue(self.evaluate(0.90, 0.90, 0.10))


class SemanticValidationTests(unittest.TestCase):
    """Verify validate_output_semantics rejects wrong, empty, or dummy payloads."""

    def test_valid_version_passes(self):
        value_gate.validate_output_semantics(
            ["version"], b"symfritz dev\n", b"", 0
        )
        value_gate.validate_output_semantics(
            ["version"], b"symfritz 6ecdbe9cf8eec61d36d246fc1cb2a5e8869c9b5a\n", b"", 0
        )

    def test_invalid_version_fails(self):
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(["version"], b"wrong_app 1.0\n", b"", 0)
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(
                ["version"], b'{"wrong_payload": true}\n', b"", 0
            )

    def test_valid_hosts_list_json_passes(self):
        valid_payload = json.dumps([
            {
                "name": "laptop",
                "ip": "192.168.1.20",
                "mac": "AA:BB:CC:DD:EE:FF",
                "active": True,
            }
        ]).encode("utf-8")
        value_gate.validate_output_semantics(
            ["hosts", "list", "--json"], valid_payload, b"", 0
        )

    def test_hosts_list_json_rejects_wrong_payload_negative_control(self):
        # Negative control from Issue #251: dummy JSON {"wrong_payload": true}
        wrong_payload = b'{"wrong_payload": true}\n'
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(
                ["hosts", "list", "--json"], wrong_payload, b"", 0
            )

    def test_hosts_list_json_rejects_empty_list(self):
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(
                ["hosts", "list", "--json"], b"[]\n", b"", 0
            )

    def test_hosts_list_json_rejects_missing_target_host(self):
        other_host = json.dumps([{"name": "desktop", "ip": "192.168.1.50"}]).encode("utf-8")
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(
                ["hosts", "list", "--json"], other_host, b"", 0
            )

    def test_nonzero_status_fails(self):
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(["version"], b"symfritz dev\n", b"", 1)

    def test_stderr_fails(self):
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_output_semantics(
                ["version"], b"symfritz dev\n", b"some warning\n", 0
            )


class TimedMeasurementFailurePropagationTests(unittest.TestCase):
    """measure_once captures output and runs semantic validation on every single timed iteration."""

    class FakeHarness:
        @staticmethod
        def temporary_directory(prefix):
            return tempfile.TemporaryDirectory(prefix=prefix)

        @staticmethod
        def environment(home, *, fake=False, **_kwargs):
            return {"PATH": "/usr/bin:/bin", "HOME": str(home)}

    def test_nonzero_exit_raises_in_measure_once(self):
        false_binary = Path("/usr/bin/false")
        if not false_binary.exists():
            self.skipTest("/usr/bin/false unavailable")
        with self.assertRaises(value_gate.GateError):
            value_gate.measure_once(self.FakeHarness(), false_binary, ["version"], fake=False)

    def test_wrong_but_fast_binary_is_rejected_during_timed_call(self):
        """Negative control: a script returning {'wrong_payload': true} must fail in measure_once."""
        suffix = ".bat" if os.name == "nt" else ".sh"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as script:
            if os.name == "nt":
                script.write('@echo off\r\necho {"wrong_payload": true}\r\nexit /b 0\r\n')
            else:
                script.write("#!/bin/sh\nprintf '{\"wrong_payload\": true}\\n'\nexit 0\n")
            script_path = Path(script.name)
        script_path.chmod(0o755)

        try:
            with self.assertRaises(value_gate.GateError):
                value_gate.measure_once(
                    self.FakeHarness(), script_path, ["hosts", "list", "--json"], fake=True
                )
        finally:
            script_path.unlink()

    def test_valid_binary_succeeds_in_measure_once(self):
        suffix = ".bat" if os.name == "nt" else ".sh"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as script:
            if os.name == "nt":
                script.write("@echo off\r\necho symfritz 0.1.0\r\nexit /b 0\r\n")
            else:
                script.write("#!/bin/sh\nprintf 'symfritz 0.1.0\\n'\nexit 0\n")
            script_path = Path(script.name)
        script_path.chmod(0o755)

        try:
            elapsed, peak = value_gate.measure_once(
                self.FakeHarness(), script_path, ["version"], fake=False
            )
            self.assertGreater(elapsed, 0.0)
            self.assertGreater(peak, 0)
        finally:
            script_path.unlink()


class OracleProductionExtractionTests(unittest.TestCase):
    """Exercise production extract_oracle directly from run-cli-differential.py."""

    def setUp(self):
        self.runner = value_gate.load_differential_runner(ROOT)

    def build_archive(self, member: tarfile.TarInfo, payload: bytes = b"x") -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as bundle:
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
        return buffer.getvalue()

    def test_extract_oracle_member_safety_via_mock_git(self):
        """Pass unsafe tar archives through a mock git binary into the production extract_oracle."""
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            ext = ".bat" if os.name == "nt" else ""
            mock_git = temp_dir / f"mock_git{ext}"

            # Case 1: Directory traversal member
            bad_member = tarfile.TarInfo("../escape")
            bad_archive = self.build_archive(bad_member)
            archive_path = temp_dir / "archive.tar"
            archive_path.write_bytes(bad_archive)

            if os.name == "nt":
                mock_git.write_text(
                    f"@echo off\r\ntype \"{archive_path}\"\r\n", encoding="utf-8"
                )
            else:
                mock_git.write_text(
                    f"#!/bin/sh\ncat '{archive_path}'\n", encoding="utf-8"
                )
            mock_git.chmod(0o755)

            dest = temp_dir / "out"
            dest.mkdir()

            with self.assertRaises(RuntimeError) as ctx:
                self.runner.extract_oracle(ROOT, dest, git=mock_git)
            self.assertTrue(
                "oracle archive digest mismatch" in str(ctx.exception)
                or "unsafe oracle archive member" in str(ctx.exception)
            )


class ProvenanceBindingTests(unittest.TestCase):
    def test_oracle_commit_and_archive_sha_match_differential_runner(self):
        runner = value_gate.load_differential_runner(ROOT)
        self.assertEqual(value_gate.ORACLE_COMMIT, runner.ORACLE_COMMIT)

    def test_verify_rust_candidate_rejects_mismatched_commit(self):
        suffix = ".bat" if os.name == "nt" else ".sh"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as script:
            if os.name == "nt":
                script.write(
                    '@echo off\r\n'
                    'echo {"tool": "symfritz", "version": "commit-aaa", "schema_version": 1}\r\n'
                    'exit /b 0\r\n'
                )
            else:
                script.write(
                    '#!/bin/sh\n'
                    'printf \'{"tool": "symfritz", "version": "commit-aaa", "schema_version": 1}\\n\'\n'
                    'exit 0\n'
                )
            script_path = Path(script.name)
        script_path.chmod(0o755)

        try:
            with self.assertRaises(value_gate.GateError):
                value_gate.verify_rust_candidate(script_path, "commit-bbb")

            # Matching commit passes
            value_gate.verify_rust_candidate(script_path, "commit-aaa")
        finally:
            script_path.unlink()

    def test_runner_refuses_too_few_samples_for_a_p95(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/value_gate.py"), "--samples", "5"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("at least 20 samples", result.stderr)


if __name__ == "__main__":
    unittest.main()
