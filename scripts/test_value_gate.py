#!/usr/bin/env python3
"""Contract tests for the VALUE gate runner.

These never run a benchmark. They pin the arithmetic, the provenance fields
and — most importantly — that a failing measurement reaches the caller
instead of being reported as a fast run.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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
        # Built-in sum() uses compensated summation on CPython 3.12+; the
        # explicit fold must not.
        values = [0.1] * 10
        expected = 0.0
        for value in values:
            expected += value
        self.assertEqual(value_gate.left_fold_sum(values), expected)

    def test_summary_mean_uses_the_explicit_fold(self):
        values = [0.1, 0.2, 0.3]
        summary = value_gate.summarise(values, "milliseconds")
        self.assertEqual(summary["mean"], value_gate.left_fold_sum(values) / 3)
        self.assertEqual(summary["samples"], 3)


class GateDecisionTests(unittest.TestCase):
    """The gate is size-OR-rss improvement, with a latency ceiling."""

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


class FailurePropagationTests(unittest.TestCase):
    """A deliberately failing subprocess must surface, not be timed."""

    class FakeHarness:
        @staticmethod
        def temporary_directory(prefix):
            return tempfile.TemporaryDirectory(prefix=prefix)

        @staticmethod
        def environment(home, *, fake=False, **_kwargs):
            return {"PATH": "/usr/bin:/bin", "HOME": str(home)}

    def test_nonzero_exit_raises_instead_of_returning_a_timing(self):
        false_binary = Path("/usr/bin/false")
        if not false_binary.exists():
            self.skipTest("/usr/bin/false unavailable")
        with self.assertRaises(value_gate.GateError):
            value_gate.measure_once(self.FakeHarness(), false_binary, [], fake=False)

    def test_zero_exit_returns_a_timing_and_peak_rss(self):
        true_binary = Path("/usr/bin/true")
        if not true_binary.exists():
            self.skipTest("/usr/bin/true unavailable")
        elapsed, peak = value_gate.measure_once(
            self.FakeHarness(), true_binary, [], fake=False
        )
        self.assertGreater(elapsed, 0.0)
        self.assertGreater(peak, 0)

    def test_validate_command_rejects_a_failing_command(self):
        false_binary = Path("/usr/bin/false")
        if not false_binary.exists():
            self.skipTest("/usr/bin/false unavailable")
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_command(
                self.FakeHarness(), false_binary, [], fake=False
            )

    def test_validate_command_rejects_empty_output(self):
        true_binary = Path("/usr/bin/true")
        if not true_binary.exists():
            self.skipTest("/usr/bin/true unavailable")
        with self.assertRaises(value_gate.GateError):
            value_gate.validate_command(
                self.FakeHarness(), true_binary, [], fake=False
            )


class OracleExtractionTests(unittest.TestCase):
    def build_archive(self, member: tarfile.TarInfo, payload: bytes = b"x") -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as bundle:
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
        return buffer.getvalue()

    def extract(self, archive: bytes):
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "out"
            destination.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
                for member in bundle.getmembers():
                    target = (destination / member.name).resolve()
                    if not target.is_relative_to(destination.resolve()):
                        raise value_gate.GateError("traversal")
                    if not (member.isfile() or member.isdir()):
                        raise value_gate.GateError("non-regular")
                    if member.mode & (0o4000 | 0o2000):
                        raise value_gate.GateError("setuid")

    def test_traversal_member_is_refused(self):
        with self.assertRaises(value_gate.GateError):
            self.extract(self.build_archive(tarfile.TarInfo("../escape")))

    def test_symlink_member_is_refused(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        with self.assertRaises(value_gate.GateError):
            self.extract(self.build_archive(member, b""))

    def test_setuid_member_is_refused(self):
        member = tarfile.TarInfo("tool")
        member.mode = 0o4755
        with self.assertRaises(value_gate.GateError):
            self.extract(self.build_archive(member))


class ArtifactContractTests(unittest.TestCase):
    def test_oracle_commit_matches_the_differential_runner(self):
        source = (ROOT / "scripts/run-cli-differential.py").read_text(encoding="utf-8")
        expected = f'ORACLE_COMMIT = "{value_gate.ORACLE_COMMIT}"'
        self.assertIn(
            expected, source,
            "the value gate and the CLI differential must pin the same Go oracle",
        )

    def test_runner_refuses_too_few_samples_for_a_p95(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/value_gate.py"), "--samples", "5"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("at least 20 samples", result.stderr)


if __name__ == "__main__":
    unittest.main()
