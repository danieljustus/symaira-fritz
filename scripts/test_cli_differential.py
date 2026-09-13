#!/usr/bin/env python3
"""Unit tests for the historical Go-vs-Rust CLI differential guardrails."""
from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cli-differential.py"
SPEC = importlib.util.spec_from_file_location("cli_differential", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CliDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = MODULE.load_policy(ROOT)
        setattr(MODULE, "PRIVATE_IP", "192.168.1.20")

    def test_same_binary_is_rejected_before_fake_box_startup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "symfritz"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(AssertionError, "self-comparison is forbidden"):
                MODULE.resolve_distinct_binaries(str(binary), str(binary))

    def test_identical_binary_copy_is_rejected_before_fake_box_startup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "go-oracle"
            copy = Path(raw) / "rust-copy"
            source.write_bytes(b"not-a-real-binary")
            shutil.copyfile(source, copy)
            with self.assertRaisesRegex(AssertionError, "identical binary content"):
                MODULE.resolve_distinct_binaries(str(source), str(copy))

    def test_wlan_policy_requires_exact_asymmetric_traces(self) -> None:
        go_trace, rust_trace = MODULE._trace_override(self.policy, "wlan-guest-status")
        self.assertEqual(go_trace, [("POST", "/upnp/control/wlanconfig3", "GetInfo")])
        self.assertEqual(
            rust_trace,
            [
                ("GET", "/tr64desc.xml", ""),
                ("POST", "/upnp/control/wlanconfig3", "GetInfo"),
            ],
        )

    def test_asymmetric_traces_still_compare_shared_request_bodies(self) -> None:
        expected_go = [("POST", "/upnp/control/wlanconfig3", "SetEnable")]
        expected_rust = [
            ("GET", "/tr64desc.xml", ""),
            ("POST", "/upnp/control/wlanconfig3", "SetEnable"),
        ]
        with self.assertRaisesRegex(AssertionError, "shared request body mismatch"):
            MODULE.assert_shared_request_bodies(
                "guest-on",
                [("POST", "/upnp/control/wlanconfig3", "SetEnable", b"<NewEnable>1</NewEnable>")],
                [
                    ("GET", "/tr64desc.xml", "", b""),
                    ("POST", "/upnp/control/wlanconfig3", "SetEnable", b"<NewEnable>0</NewEnable>"),
                ],
                expected_go,
                expected_rust,
            )

    def test_home_list_empty_collection_is_case_scoped(self) -> None:
        self.assertEqual(
            MODULE._structured_transform("home-list-aha", {"groups": None}, self.policy, "oracle"),
            MODULE._structured_transform("home-list-aha", {"groups": []}, self.policy, "candidate"),
        )
        with self.assertRaises(AssertionError):
            MODULE._structured_transform("home-list-aha", {"groups": None}, self.policy, "candidate")
        self.assertEqual(
            MODULE._structured_transform("unrelated", {"groups": None}, self.policy, "oracle"),
            {"groups": None},
        )

    def test_structured_error_policy_strips_only_declared_go_preamble(self) -> None:
        prefix = self.policy["harness"]["byte_stream_overrides"][0]["cases"]["auth-unauthorized"][
            "oracle_stdout_prefix"
        ].format(private_ip="192.168.1.20", port=49000).encode()
        payload = b'{"error":{"kind":"auth"}}\n'
        MODULE.assert_bytes(
            "auth-unauthorized",
            MODULE.Result(3, prefix + payload, b""),
            MODULE.Result(3, payload, b""),
            policy=self.policy,
        )
        with self.assertRaises(AssertionError):
            MODULE.assert_bytes(
                "auth-unauthorized",
                MODULE.Result(3, b"unexpected\n" + payload, b""),
                MODULE.Result(3, payload, b""),
                policy=self.policy,
            )

    def test_config_template_policy_requires_exact_opt_in_block(self) -> None:
        before = b"use_tls = true\n\ninsecure_tls = false\n"
        insert = (
            b"# Allow retrying an unavailable TLS endpoint over unencrypted HTTP.\n"
            b"# Keep disabled unless this legacy compatibility fallback is required.\n"
            b"allow_http_fallback = false\n\n"
        )
        self.assertEqual(
            MODULE._config_template_transform(
                "config-init-fresh", before + insert, self.policy, "candidate"
            ),
            before,
        )
        with self.assertRaises(AssertionError):
            MODULE._config_template_transform(
                "config-init-fresh", before, self.policy, "candidate"
            )


if __name__ == "__main__":
    unittest.main()
