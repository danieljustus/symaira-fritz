#!/usr/bin/env python3
"""Unit tests for the historical Go-vs-Rust CLI differential guardrails."""
from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest import mock

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

    def test_resolved_path_alias_is_rejected_before_fake_box_startup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "go-oracle"
            alias = Path(raw) / "rust-alias"
            source.write_bytes(b"different executable contents")
            source.chmod(source.stat().st_mode | stat.S_IXUSR)
            alias.symlink_to(source)
            with self.assertRaisesRegex(AssertionError, "same executable"):
                MODULE.resolve_distinct_binaries(str(source), str(alias))

    def test_hardlinked_inode_is_rejected_before_fake_box_startup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "go-oracle"
            alias = Path(raw) / "rust-hardlink"
            source.write_bytes(b"different executable contents")
            source.chmod(source.stat().st_mode | stat.S_IXUSR)
            os.link(source, alias)
            with self.assertRaisesRegex(AssertionError, "same executable"):
                MODULE.resolve_distinct_binaries(str(source), str(alias))

    def test_policy_mutation_cannot_remove_an_approved_target(self) -> None:
        mutated = copy.deepcopy(self.policy)
        mutated["approved_target_changes"] = [
            target
            for target in mutated["approved_target_changes"]
            if target["id"] != "CLI-STRUCTURED-ERROR-CLEAN"
        ]
        with self.assertRaisesRegex(AssertionError, r"invalid byte stream"):
            MODULE.validate_policy(ROOT, mutated)

    def test_uncovered_difference_fails_without_a_policy_transform(self) -> None:
        left = MODULE.Result(0, b'{"unexpected":null}\n', b"")
        right = MODULE.Result(0, b'{"unexpected":[]}\n', b"")
        with self.assertRaisesRegex(AssertionError, "JSON mismatch"):
            MODULE.assert_json("uncovered-difference", left, right, policy=self.policy)

    def test_policy_mutation_leaving_a_difference_uncovered_still_fails(self) -> None:
        mutated = copy.deepcopy(self.policy)
        structured_rule = next(
            rule
            for rule in mutated["harness"]["structured_transforms"]
            if rule["id"] == "CAP-AHA-HOME-LIST-SINGLE-FETCH"
        )
        structured_rule["paths"]["home-list-aha"] = ["$.nested.groups"]
        MODULE.validate_policy(ROOT, mutated)
        left = MODULE.Result(0, b'{"groups":null,"nested":{"groups":[]}}\n', b"")
        right = MODULE.Result(0, b'{"groups":[],"nested":{"groups":[]}}\n', b"")
        with self.assertRaisesRegex(AssertionError, "changed 0"):
            MODULE.assert_json("home-list-aha", left, right, policy=mutated)

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

    def test_windows_path_keeps_only_explicit_helper_empty_dir_and_system_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            helper = home / "mock-symvault"
            helper.mkdir()
            path = MODULE.isolated_path(
                home,
                helper,
                {
                    "PATH": r"C:\host-tools;C:\untrusted-helper",
                    "SystemRoot": r"C:\Windows",
                },
                is_windows=True,
            )
            self.assertEqual(
                path.split(";"),
                [str(helper), str(home / "empty-path"), r"C:\Windows\System32"],
            )
            self.assertNotIn("host-tools", path)
            self.assertNotIn("untrusted-helper", path)

    def test_non_windows_path_is_empty_without_explicit_helper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            self.assertEqual(
                MODULE.isolated_path(
                    home,
                    None,
                    {"PATH": "/host-tools:/untrusted-helper"},
                    is_windows=False,
                ),
                str(home / "empty-path"),
            )

    def test_strict_fake_box_rejects_extra_aha_and_soap_parameters(self) -> None:
        server = MODULE.StrictFakeBox(("127.0.0.1", 0), "192.168.1.20")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            login_url = f"http://127.0.0.1:{port}/login_sid.lua?version=2&unexpected=1"
            with self.assertRaises(HTTPError) as login_error:
                urlopen(login_url, timeout=2)
            self.assertEqual(login_error.exception.code, 400)
            login_error.exception.close()
            self.assertEqual(server.accepted, [])
            self.assertTrue(server.failures)

            server.reset()
            aha_url = (
                f"http://127.0.0.1:{port}/webservices/homeautoswitch.lua"
                f"?ain={MODULE.AIN}&sid={MODULE.SID}&switchcmd=setswitchon&extra=1"
            )
            with self.assertRaises(HTTPError) as aha_error:
                urlopen(aha_url, timeout=2)
            self.assertEqual(aha_error.exception.code, 400)
            aha_error.exception.close()
            self.assertEqual(server.accepted, [])
            self.assertTrue(server.failures)

            server.reset()
            soap_url = f"http://127.0.0.1:{port}/upnp/control/deviceinfo"
            soap_body = (
                b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                b'<s:Body><u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1">'
                b"<Unexpected>1</Unexpected>"
                b"</u:GetInfo></s:Body></s:Envelope>"
            )
            request = Request(
                soap_url,
                data=soap_body,
                headers={"SOAPAction": '"urn:dslforum-org:service:DeviceInfo:1#GetInfo"'},
            )
            with self.assertRaises(HTTPError) as soap_error:
                urlopen(request, timeout=2)
            self.assertEqual(soap_error.exception.code, 400)
            soap_error.exception.close()
            self.assertEqual(server.accepted, [])
            self.assertTrue(server.failures)

            server.reset()
            with self.assertRaises(HTTPError) as method_error:
                urlopen(Request(f"http://127.0.0.1:{port}/tr64desc.xml", method="PUT"), timeout=2)
            self.assertEqual(method_error.exception.code, 405)
            method_error.exception.close()
            self.assertEqual(server.accepted, [])
            self.assertTrue(server.failures)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_strict_query_and_shared_body_controls_include_cardinality(self) -> None:
        self.assertFalse(
            MODULE._query_is_exact(
                f"sid={MODULE.SID}&extra=1", [("sid", MODULE.SID)]
            )
        )
        response = MODULE.legacy_response(MODULE.CHALLENGE, MODULE.PASSWORD)
        options = MODULE._login_query_options(response)
        self.assertEqual(len(options), 3)
        for option in options:
            self.assertTrue(MODULE._query_is_exact(MODULE._canonical_form(option), option))
        self.assertFalse(
            MODULE._query_is_exact(
                MODULE._canonical_form(options[0] + [("extra", "1")]), options[0]
            )
        )
        self.assertFalse(
            MODULE._query_is_exact(
                MODULE._canonical_form(
                    [("version", "2"), ("response", "wrong"), ("username", MODULE.USER)]
                ),
                options[0],
            )
        )
        request = ("POST", "/upnp/control/wlanconfig3", "SetEnable")
        expected = [request, request]
        with self.assertRaisesRegex(AssertionError, "cardinality"):
            MODULE.assert_shared_request_bodies(
                "repeated-cardinality",
                [(request[0], request[1], request[2], b"a")],
                [
                    (request[0], request[1], request[2], b"a"),
                    (request[0], request[1], request[2], b"b"),
                ],
                expected,
                expected,
            )
        with self.assertRaisesRegex(AssertionError, "occurrence 1"):
            MODULE.assert_shared_request_bodies(
                "repeated-index",
                [
                    (request[0], request[1], request[2], b"a"),
                    (request[0], request[1], request[2], b"b"),
                ],
                [
                    (request[0], request[1], request[2], b"a"),
                    (request[0], request[1], request[2], b"c"),
                ],
                expected,
                expected,
            )

    def test_structured_success_requires_exact_case_schema(self) -> None:
        with self.assertRaisesRegex(AssertionError, "keys mismatch"):
            MODULE.assert_success_object(
                "auth-trust-json",
                MODULE.Result(0, b'{"ok":true}\n', b""),
                "json",
                self.policy,
                case="auth-trust",
            )
        value = MODULE.assert_success_object(
            "auth-trust-json",
            MODULE.Result(
                0,
                b'{"ok":true,"action":"auth_trust","host":"no-pin-recorded","reset":false}\n',
                b"",
            ),
            "json",
            self.policy,
            case="auth-trust",
        )
        self.assertEqual(value["action"], "auth_trust")

    def test_exact_transform_paths_leave_unrelated_nested_keys_strict(self) -> None:
        oracle = b'[{"Date":"outerZ","nested":{"Date":"nestedZ","Time":"nestedZ","groups":null}}]\n'
        candidate = b'[{"Date":"outer","nested":{"Date":"different","Time":"nestedZ","groups":null}}]\n'
        with self.assertRaisesRegex(AssertionError, "JSON mismatch"):
            MODULE.assert_json(
                "calls",
                MODULE.Result(0, oracle, b""),
                MODULE.Result(0, candidate, b""),
                self.policy,
            )
        transformed = MODULE._structured_transform(
            "calls",
            [{"Date": "outerZ", "nested": {"Date": "nestedZ", "Time": "nestedZ", "groups": None}}],
            self.policy,
            "oracle",
        )
        self.assertEqual(transformed[0]["Date"], "outer")
        self.assertEqual(transformed[0]["nested"], {"Date": "nestedZ", "Time": "nestedZ", "groups": None})

    def test_policy_assertion_scope_cannot_be_added_without_harness_binding(self) -> None:
        mutated = copy.deepcopy(self.policy)
        target = next(
            item
            for item in mutated["approved_target_changes"]
            if item["id"] == "CAP-MESH-UID-ALIASES"
        )
        target["scope"]["cases"].append("never-executed")
        with self.assertRaisesRegex(AssertionError, "scope cases must be bound"):
            MODULE.validate_policy(ROOT, mutated)

    def test_policy_assertion_command_is_validated_as_argv(self) -> None:
        target = self.policy["approved_target_changes"][0]
        valid = target["rust_assertion"]["command"]
        MODULE._validated_rust_command(valid, "valid", expected_test=target["rust_assertion"]["test"])
        for malformed in (
            ["cargo", "test", "-p", "symfritz-core", "--lib", "test", "--locked", "extra"],
            ["cargo", "test", "-p", "symfritz-core", "--lib", "test", "--locked", "&&", "bad"],
            ["not-cargo", "test"],
        ):
            with self.assertRaises(AssertionError):
                MODULE._validated_rust_command(malformed, "malformed", expected_test="test")

        missing = copy.deepcopy(self.policy)
        missing_target = missing["approved_target_changes"][0]
        missing_command = missing_target["rust_assertion"]["command"]
        missing_command[missing_command.index("-p") + 1] = "definitely-not-a-symfritz-package"
        with self.assertRaisesRegex(AssertionError, "Rust assertion failed"):
            MODULE.run_rust_assertions(ROOT, missing)

    def test_policy_case_coverage_fails_for_unexecuted_scope(self) -> None:
        coverage = MODULE.PolicyCaseCoverage(self.policy)
        target_id = "CAP-MESH-UID-ALIASES"
        coverage.mark(target_id, "mesh-path-and-sid", "mesh-path-and-sid")
        with self.assertRaisesRegex(AssertionError, "never executed"):
            coverage.assert_complete()

    def test_temporary_directory_uses_platform_temp_root(self) -> None:
        with (
            mock.patch.object(MODULE.tempfile, "gettempdir", return_value=r"C:\runner-temp"),
            mock.patch.object(MODULE.tempfile, "TemporaryDirectory") as directory,
        ):
            MODULE.temporary_directory("symfritz-cli-")
        directory.assert_called_once_with(prefix="symfritz-cli-", dir=r"C:\runner-temp")


if __name__ == "__main__":
    unittest.main()
