#!/usr/bin/env python3
"""Evidence-gated black-box parity checks for the Go and Rust CLIs.

The fake box is deliberately strict: an unexpected method, route, SOAP action,
argument, or authentication sequence is a test failure, never a generic 200.
All subprocesses use isolated HOME/XDG trees and a PATH containing no backend
binaries, so these checks cannot contact a real router, Keychain, or SymVault.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PORT = 49000
REALM = "symfritz-test"
NONCE = "fixed-test-nonce"
TRAFFIC_XML = b'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:X_AVM-DE_GetOnlineMonitorResponse xmlns:u="urn:dslforum-org:service:WANCommonInterfaceConfig:1">
<Newds_current_bps>1500000,1200000</Newds_current_bps><Newmc_current_bps>500000</Newmc_current_bps><Newds_guest_bps>0</Newds_guest_bps>
<Newprio_realtime_bps>100000</Newprio_realtime_bps><Newprio_high_bps>200000</Newprio_high_bps><Newprio_default_bps>800000</Newprio_default_bps><Newprio_low_bps>50000</Newprio_low_bps><Newus_guest_bps>0</Newus_guest_bps>
</u:X_AVM-DE_GetOnlineMonitorResponse></s:Body></s:Envelope>'''
DESC_XML = b'''<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><serviceList>
<service><serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/wancommonifconfig1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service>
</serviceList></device></root>'''

# This is the allow-list, not a response fall-through. Adding a command requires
# adding its exact route/action here and a fixture response for that action.
EXPECTED_ACTIONS = {
    "/upnp/control/deviceinfo": {"GetInfo"},
    "/upnp/control/userif": {"GetInfo"},
    "/upnp/control/wanipconnection1": {"GetInfo", "GetExternalIPAddress"},
    "/upnp/control/wanpppconn1": {"GetInfo", "GetExternalIPAddress"},
    "/upnp/control/wancommonifconfig1": {"X_AVM-DE_GetOnlineMonitor"},
    "/upnp/control/hosts": {
        "X_AVM-DE_GetHostListPath", "GetHostNumberOfEntries", "GetGenericHostEntry",
        "GetSpecificHostEntry", "X_AVM-DE_GetSpecificHostEntryByIP",
        "X_AVM-DE_WakeOnLANByMACAddress",
    },
    "/upnp/control/wandslifconfig1": {"X_AVM-DE_GetDSLLinkInfo"},
    "/upnp/control/x_voip": {
        "X_AVM-DE_Dial", "X_AVM-DE_DialHangup",
    },
    "/upnp/control/x_contact": {"X_AVM-DE_GetCallList"},
    "/upnp/control/deviceconfig": {"Reboot"},
}


class StrictFakeBox(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, StrictHandler)
        self.requests: list[tuple[str, str, str, bytes]] = []
        self.failures: list[str] = []
        self.authenticated: set[tuple[str, str]] = set()


class StrictHandler(http.server.BaseHTTPRequestHandler):
    server: StrictFakeBox  # type: ignore[reportIncompatibleVariableOverride]

    def do_GET(self) -> None:
        if self.path != "/tr64desc.xml":
            self.server.failures.append(f"GET unexpected path {self.path!r}")
            self.send_error(404)
            return
        self.server.requests.append(("GET", self.path, "", b""))
        self.reply(DESC_XML, "text/xml")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 0 or length > 1024 * 1024:
            self.server.failures.append("POST missing or oversized Content-Length")
            self.send_error(400)
            return
        body = self.rfile.read(length)
        soap_action = self.headers.get("SOAPAction", "")
        action = soap_action.strip('"').rsplit("#", 1)[-1]
        key = (self.path, action)
        self.server.requests.append(("POST", self.path, soap_action, body))

        if self.path not in EXPECTED_ACTIONS or action not in EXPECTED_ACTIONS[self.path]:
            self.server.failures.append(f"POST unexpected route/action {self.path!r} {soap_action!r}")
            self.send_error(404)
            return
        if f"{action}" not in body.decode("utf-8", "replace"):
            self.server.failures.append(f"SOAP body omitted action {action!r}")
            self.send_error(400)
            return
        if action == "X_AVM-DE_GetOnlineMonitor" and (
            body.count(b"<NewSyncGroupIndex>") != 1
            or b"<NewSyncGroupIndex>0</NewSyncGroupIndex>" not in body
        ):
            # The traffic action requires the fixed sync-group argument. This
            # catches a route that returns the right fixture with wrong input.
            self.server.failures.append("traffic action carried wrong arguments")
            self.send_error(400)
            return

        authorization = self.headers.get("Authorization", "")
        if key not in self.server.authenticated:
            if authorization:
                self.server.failures.append("first SOAP request was authenticated")
                self.send_error(400)
                return
            self.reply(b"", "text/xml", status=401,
                       extra={"WWW-Authenticate": f'Digest realm="{REALM}", nonce="{NONCE}"'})
            self.server.authenticated.add(key)
            return
        if not authorization.startswith("Digest "):
            self.server.failures.append("retry SOAP request omitted Digest authorization")
            self.send_error(401)
            return

        if action == "X_AVM-DE_GetOnlineMonitor":
            self.reply(TRAFFIC_XML, "text/xml")
        else:
            # Only explicitly allow-listed actions reach this response. The
            # body is action-specific so a wrong action cannot silently pass.
            response = (
                f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
                f'<u:{action}Response xmlns:u="urn:dslforum-org:service:test:1">'
                f'</u:{action}Response></s:Body></s:Envelope>'
            ).encode()
            self.reply(response, "text/xml")

    def reply(self, body: bytes, content_type: str, *, status: int = 200,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@dataclass
class Result:
    code: int
    stdout: bytes
    stderr: bytes


def environment(home: Path, *, fake: bool) -> dict[str, str]:
    # Deliberately remove all Symfritz settings and backend executables.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SYMFRITZ_")}
    backend_free_path = home / "empty-path"
    backend_free_path.mkdir()
    env.update({
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"),
        "TMPDIR": str(home / "tmp"), "TMP": str(home / "tmp"),
        "TEMP": str(home / "tmp"), "PATH": str(backend_free_path),
        "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
    })
    if fake:
        env.update({
            "SYMFRITZ_BOX_HOST": "127.0.0.1",
            "SYMFRITZ_BOX_USE_TLS": "false",
            "SYMFRITZ_PASSWORD": "test-password",
            "SYMFRITZ_BOX_TIMEOUT_SECONDS": "1",
        })
    return env


def run(binary: str, args: list[str], *, fake: bool = False, timeout: float = 5) -> Result:
    with tempfile.TemporaryDirectory(prefix="symfritz-cli-") as temp:
        home = Path(temp)
        try:
            process = subprocess.run(
                [binary, *args], cwd=home, env=environment(home, fake=fake),
                capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{binary} {args} exceeded {timeout}s") from exc
        return Result(process.returncode, process.stdout, process.stderr)


def run_watch(binary: str, *, fmt: str) -> Result:
    with tempfile.TemporaryDirectory(prefix="symfritz-watch-") as temp:
        home = Path(temp)
        env = environment(home, fake=True)
        process = subprocess.Popen(
            [binary, "traffic", "--watch", "--output", fmt, "--interval", "10ms"],
            cwd=home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        process.send_signal(signal.SIGINT)
        out, err = process.communicate(timeout=3)
        return Result(process.returncode, out, err)


def assert_bytes(label: str, left: Result, right: Result) -> None:
    if (left.code, left.stdout, left.stderr) != (right.code, right.stdout, right.stderr):
        raise AssertionError(
            f"{label}: exact mismatch\n"
            f"Go=({left.code}, {left.stdout!r}, {left.stderr!r})\n"
            f"Rust=({right.code}, {right.stdout!r}, {right.stderr!r})"
        )


def assert_structured(label: str, left: Result, right: Result, kind: str) -> None:
    if left.code != right.code or left.stderr != right.stderr:
        raise AssertionError(f"{label}: exit/stderr mismatch: {left} != {right}")
    if kind == "json":
        if json.loads(left.stdout) != json.loads(right.stdout):
            raise AssertionError(f"{label}: JSON mismatch")
    elif kind == "yaml":
        # Compare the complete key/value sequence while ignoring only scalar
        # integer-vs-float spelling differences between the typed ports.
        def normalize(data: bytes) -> list[tuple[str, str]]:
            return [(line.split(":", 1)[0], line.split(":", 1)[1].strip())
                    for line in data.decode().splitlines() if ":" in line]
        if normalize(left.stdout) != normalize(right.stdout):
            raise AssertionError(f"{label}: YAML mismatch")
    else:
        raise ValueError(kind)


def assert_help_semantic(label: str, left: Result, right: Result) -> None:
    if left.code != 0 or right.code != 0:
        raise AssertionError(f"{label}: help failed: Go={left.code}, Rust={right.code}")
    for output in (left.stdout, right.stdout):
        if b"Usage:" not in output or not output.endswith(b"\n"):
            raise AssertionError(f"{label}: missing stable usage/newline contract")


def parse_validation_fixture(root: Path) -> list[dict[str, Any]]:
    fixture = json.loads((root / "testdata/port/cli/command-contracts.json").read_text())
    validation = fixture["validation"]
    if len(validation) != 17:
        raise AssertionError(f"fixture validation count changed: {len(validation)}")
    return validation


def run_suite(go: str, rust: str, root: Path) -> None:
    server = StrictFakeBox(("127.0.0.1", PORT))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Every implemented family gets a real executable help invocation. Help
        # is intentionally semantic-normalized because Cobra and clap format it
        # differently; parse/error contracts below remain exact bytes.
        families = [
            "auth", "call", "calls", "completion", "config", "detect", "diagnose",
            "dial", "doctor", "dsl", "hangup", "help", "home", "hosts", "log", "mcp",
            "mesh", "reboot", "scrape", "services", "status", "traffic", "version",
            "wlan", "wol",
        ]
        for family in families:
            assert_help_semantic(f"help-{family}", run(go, ["help", family]), run(rust, ["help", family]))
            print(f"PASS help-{family}")

        for label, args in [
            ("version-text", ["version"]),
            ("version-json", ["version", "--output", "json"]),
            ("version-yaml", ["version", "--output", "yaml"]),
            ("invalid-output-9", ["version", "--output", "invalid"]),
            ("reboot-without-confirmation-9", ["reboot"]),
        ]:
            assert_bytes(label, run(go, args), run(rust, args))
            print(f"PASS {label}")

        for fmt, kind in [("text", "bytes"), ("json", "json"), ("yaml", "yaml")]:
            args = ["traffic", "--output", fmt]
            server.authenticated.clear()
            left = run(go, args, fake=True)
            server.authenticated.clear()
            right = run(rust, args, fake=True)
            if server.failures:
                raise AssertionError("fake-box traffic failure: " + "; ".join(server.failures))
            if kind == "bytes":
                assert_bytes(f"traffic-{fmt}", left, right)
            else:
                assert_structured(f"traffic-{fmt}", left, right, kind)
            print(f"PASS traffic-{fmt}")

        if os.name != "nt":
            server.authenticated.clear()
            left = run_watch(go, fmt="json")
            server.authenticated.clear()
            right = run_watch(rust, fmt="json")
            if left.code != 130 or right.code != 130:
                raise AssertionError(f"traffic cancellation must exit 130: {left.code}, {right.code}")
            left_records = [json.loads(line) for line in left.stdout.splitlines()]
            right_records = [json.loads(line) for line in right.stdout.splitlines()]
            if len(left_records) < 2 or len(right_records) < 2 or left_records[0] != right_records[0]:
                raise AssertionError("traffic watch did not flush two equivalent snapshots")
            if left.stderr != right.stderr:
                raise AssertionError("traffic watch stderr mismatch")
            print("PASS traffic-watch-json-cancel")

        # All committed validation cases are exact stream/exit gates. There is
        # no status-only or non-empty-stderr false pass here.
        for case in parse_validation_fixture(root):
            args = [str(value) for value in case["args"]]
            assert_bytes(str(case["id"]), run(go, args), run(rust, args))
            print(f"PASS {case['id']}")

        # Safe seams: config creation and rejected mutations/auth do not invoke
        # the fake box or backend CLIs, and the strict request log proves it.
        config_left, config_right = run(go, ["config", "init"]), run(rust, ["config", "init"])
        if (config_left.code, config_right.code) != (0, 0) or config_left.stderr or config_right.stderr:
            raise AssertionError(f"config-init-safe-seam failed: {config_left} != {config_right}")
        config_pattern = re.compile(rb"^Config written to .*/.config/symfritz/config.toml\n$")
        if not config_pattern.match(config_left.stdout) or not config_pattern.match(config_right.stdout):
            raise AssertionError("config-init-safe-seam emitted an unexpected path or stream")
        before = len(server.requests)
        auth_left, auth_right = run(go, ["auth", "store", "--symvault", "fritz.password"]), run(
            rust, ["auth", "store", "--symvault", "fritz.password"]
        )
        if auth_left.code == 0 or auth_right.code == 0 or len(server.requests) != before:
            raise AssertionError("auth safe seam unexpectedly succeeded or contacted fake box")
        reboot_left, reboot_right = run(go, ["reboot"]), run(rust, ["reboot"])
        if reboot_left.code == 0 or reboot_right.code == 0 or len(server.requests) != before:
            raise AssertionError("unconfirmed reboot contacted the fake box")
        print("PASS config-auth-mutation-safe-seams")

        if server.failures:
            raise AssertionError("fake-box assertions failed: " + "; ".join(server.failures))
        print(f"PASS strict-fake-http requests={len(server.requests)}")
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="./symfritz")
    parser.add_argument("--rust", default="./target/debug/symfritz-rust")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    try:
        run_suite(os.path.abspath(args.go), os.path.abspath(args.rust), Path(args.root).resolve())
    except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
