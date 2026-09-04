#!/usr/bin/env python3
"""Black-box Go/Rust CLI parity checks with a local fake TR-064 endpoint.

The runner deliberately imports neither implementation. Each invocation gets a
fresh HOME/XDG tree, a fixed locale/timezone, and only the documented test
configuration. Stable text/help/error contracts use byte comparison; structured
traffic output uses decoded JSON comparison because Go and Rust represent
integral rates differently on the wire.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

PORT = 49000
TRAFFIC_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:X_AVM-DE_GetOnlineMonitorResponse xmlns:u="urn:dslforum-org:service:WANCommonInterfaceConfig:1">
<Newds_current_bps>1500000,1200000</Newds_current_bps><Newmc_current_bps>500000</Newmc_current_bps><Newds_guest_bps>0</Newds_guest_bps>
<Newprio_realtime_bps>100000</Newprio_realtime_bps><Newprio_high_bps>200000</Newprio_high_bps><Newprio_default_bps>800000</Newprio_default_bps><Newprio_low_bps>50000</Newprio_low_bps><Newus_guest_bps>0</Newus_guest_bps>
</u:X_AVM-DE_GetOnlineMonitorResponse></s:Body></s:Envelope>""".encode()
GENERIC_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:Response xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
<NewModelName>FRITZ!Box Test</NewModelName><NewSoftwareVersion>7.50</NewSoftwareVersion><NewExternalIPAddress>192.0.2.1</NewExternalIPAddress><NewConnectionStatus>Connected</NewConnectionStatus><NewUpTime>42</NewUpTime>
<NewLayer1DownstreamMaxBitRate>100000000</NewLayer1DownstreamMaxBitRate><NewLayer1UpstreamMaxBitRate>20000000</NewLayer1UpstreamMaxBitRate>
<NewHostNumberOfEntries>0</NewHostNumberOfEntries><NewCallListURL>/calllist.json</NewCallListURL><NewX_AVM-DE_HostListPath>/hosts.xml</NewX_AVM-DE_HostListPath>
</u:Response></s:Body></s:Envelope>""".encode()
DESC_XML = b'''<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><serviceList><service><serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/wancommonifconfig1</controlURL></service><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service></serviceList></device></root>'''


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_count = 0


class FakeBox(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/tr64desc.xml":
            self.reply(DESC_XML, "text/xml")
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        action = self.headers.get("SOAPAction", "") + body.decode("utf-8", "replace")
        self.server.request_count += 1  # type: ignore[attr-defined]
        self.reply(TRAFFIC_XML if "GetOnlineMonitor" in action else GENERIC_XML, "text/xml")

    def reply(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@dataclass
class Result:
    code: int | None
    stdout: bytes
    stderr: bytes


def environment(home: Path, *, fake: bool) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SYMFRITZ_")}
    env.update({
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"), "XDG_DATA_HOME": str(home / "data"),
        "TMPDIR": str(home / "tmp"), "TMP": str(home / "tmp"), "TEMP": str(home / "tmp"),
        "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
    })
    if fake:
        env.update({"SYMFRITZ_BOX_HOST": "127.0.0.1", "SYMFRITZ_BOX_USE_TLS": "false", "SYMFRITZ_PASSWORD": "test-password", "SYMFRITZ_BOX_TIMEOUT_SECONDS": "1"})
    return env


def run(binary: str, args: list[str], *, fake: bool = False, timeout: float = 5) -> Result:
    with tempfile.TemporaryDirectory(prefix="symfritz-cli-") as temp:
        home = Path(temp)
        p = subprocess.run([binary, *args], cwd=home, env=environment(home, fake=fake), capture_output=True, timeout=timeout)
        return Result(p.returncode, p.stdout, p.stderr)


def run_watch(binary: str, *, fmt: str) -> Result:
    with tempfile.TemporaryDirectory(prefix="symfritz-watch-") as temp:
        home = Path(temp)
        env = environment(home, fake=True)
        p = subprocess.Popen([binary, "traffic", "--watch", "--output", fmt, "--interval", "10ms"], cwd=home, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=3)
        return Result(p.returncode, out, err)


def assert_equal(label: str, left: Result, right: Result, *, mode: str = "bytes") -> None:
    if left.code != right.code:
        raise AssertionError(f"{label}: exit {left.code} != {right.code}")
    if mode == "bytes":
        if left.stdout != right.stdout or left.stderr != right.stderr:
            raise AssertionError(f"{label}: byte mismatch\nGo stdout={left.stdout!r}\nRust stdout={right.stdout!r}\nGo stderr={left.stderr!r}\nRust stderr={right.stderr!r}")
    elif mode == "json":
        try:
            if json.loads(left.stdout) != json.loads(right.stdout):
                raise AssertionError(f"{label}: structured stdout mismatch")
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{label}: invalid JSON: {exc}") from exc
        if left.stderr != right.stderr:
            raise AssertionError(f"{label}: stderr mismatch: {left.stderr!r} != {right.stderr!r}")
    elif mode == "ndjson":
        try:
            left_records = [json.loads(line) for line in left.stdout.splitlines()]
            right_records = [json.loads(line) for line in right.stdout.splitlines()]
            if len(left_records) < 2 or len(right_records) < 2 or left_records[0] != right_records[0]:
                raise AssertionError(f"{label}: structured stdout mismatch")
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{label}: invalid NDJSON: {exc}") from exc
        if left.stderr != right.stderr:
            raise AssertionError(f"{label}: stderr mismatch: {left.stderr!r} != {right.stderr!r}")
    elif mode == "yaml":
        def parse_yaml_lists(data: bytes) -> dict[str, list[float]]:
            parsed: dict[str, list[float]] = {}
            key = ""
            for raw_line in data.decode().splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.endswith(":"):
                    key = line[:-1]
                    parsed[key] = []
                elif line.startswith("-") and key:
                    parsed[key].append(float(line[1:].strip()))
            return parsed
        if parse_yaml_lists(left.stdout) != parse_yaml_lists(right.stdout):
            raise AssertionError(f"{label}: structured YAML mismatch")
        if left.stderr != right.stderr:
            raise AssertionError(f"{label}: stderr mismatch: {left.stderr!r} != {right.stderr!r}")
    elif mode == "exit":
        return
    else:
        raise ValueError(mode)


def run_suite(go: str, rust: str) -> None:
    server = ReusableServer(("127.0.0.1", PORT), FakeBox)
    server.request_count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        stable = [
            ("version-text", ["version"], False),
            ("version-json", ["version", "--output", "json"], False),
            ("version-yaml", ["version", "--output", "yaml"], False),
            ("invalid-output-9", ["version", "--output", "invalid"], False),
            ("reboot-without-confirmation-9", ["reboot"], False),
        ]
        for label, args, fake in stable:
            assert_equal(label, run(go, args, fake=fake), run(rust, args, fake=fake))
            print(f"PASS {label}")

        for fmt, mode in [("text", "bytes"), ("json", "json"), ("yaml", "yaml")]:
            args = ["traffic", "--output", fmt]
            assert_equal(f"traffic-{fmt}", run(go, args, fake=True), run(rust, args, fake=True), mode=mode)
            print(f"PASS traffic-{fmt}")

        if os.name == "nt":
            print("SKIP traffic-watch-json-cancel (SIGINT process semantics are Unix-only)")
        else:
            go_watch = run_watch(go, fmt="json")
            rust_watch = run_watch(rust, fmt="json")
            if go_watch.code != 130 or rust_watch.code != 130:
                raise AssertionError(f"watch cancellation must exit 130: Go={go_watch.code}, Rust={rust_watch.code}")
            if not go_watch.stdout or not rust_watch.stdout:
                raise AssertionError("watch cancellation flushed no snapshot")
            assert_equal("traffic-watch-json", go_watch, rust_watch, mode="ndjson")
            print("PASS traffic-watch-json-cancel")

        # Parse failures intentionally retain clap's conventional status 2 on
        # Rust; the fixture records Go's Cobra status 1 separately. The gate
        # checks both documented statuses and non-empty stderr without erasing
        # the distinction.
        for label, args, expected_go, expected_rust in [
            ("missing-call", ["call"], 1, 2),
            ("invalid-duration", ["traffic", "--interval", "wat"], 1, 2),
        ]:
            go_result, rust_result = run(go, args), run(rust, args)
            if (go_result.code, rust_result.code) != (expected_go, expected_rust) or not go_result.stderr or not rust_result.stderr:
                raise AssertionError(f"{label}: unexpected parse results Go={go_result.code}/{go_result.stderr!r}, Rust={rust_result.code}/{rust_result.stderr!r}")
            print(f"PASS {label} (Go={expected_go}, Rust={expected_rust})")

        print(f"PASS fake-http requests={server.request_count}")
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="./symfritz")
    parser.add_argument("--rust", default="./target/debug/symfritz-rust")
    args = parser.parse_args()
    try:
        run_suite(os.path.abspath(args.go), os.path.abspath(args.rust))
    except (AssertionError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
