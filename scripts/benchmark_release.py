#!/usr/bin/env python3
"""Measure the Rust cutover value gate against the Go fallback.

All measurements are made locally from release-built binaries. No router is
contacted: the representative command talks to a loopback fake box serving the
committed discovery fixture.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import platform
import re
import socketserver
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


class FakeBox(http.server.BaseHTTPRequestHandler):
    fixture = b""

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/tr64desc.xml":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(self.fixture)))
        self.end_headers()
        self.wfile.write(self.fixture)

    def log_message(self, format: str, *args: object) -> None:
        return


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def percentile(values: list[float], number: float = 0.95) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(number * len(ordered) + 0.999999) - 1))
    return ordered[index]


def measure(binary: Path, args: list[str], env: dict[str, str], cwd: Path, runs: int, warmups: int) -> list[float]:
    for _ in range(warmups):
        subprocess.run([str(binary), *args], cwd=cwd, env=env, check=True, capture_output=True)
    samples = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        subprocess.run([str(binary), *args], cwd=cwd, env=env, check=True, capture_output=True)
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return samples


def max_rss(binary: Path, env: dict[str, str], cwd: Path) -> int:
    command = ["/usr/bin/time", "-l", str(binary), "version", "--json"]
    result = subprocess.run(command, cwd=cwd, env=env, check=True, capture_output=True, text=True)
    match = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
    if not match:
        raise RuntimeError("/usr/bin/time did not report maximum resident set size")
    return int(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=50)
    parser.add_argument("--warmups", type=int, default=10)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("the local value gate currently requires macOS /usr/bin/time -l")
    root = Path(__file__).resolve().parents[1]
    fixture = (root / "internal/fritz/testdata/tr64desc.xml").read_bytes()
    FakeBox.fixture = fixture
    server = ThreadingServer(("127.0.0.1", 0), FakeBox)
    server_thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = server.server_address[1]
    try:
        with tempfile.TemporaryDirectory(prefix="symfritz-value-gate-") as temp:
            home = Path(temp)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.upper().startswith("SYMFRITZ_")
            }
            env.update(
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "XDG_CONFIG_HOME": str(home / "config"),
                    "XDG_CACHE_HOME": str(home / "cache"),
                    "XDG_DATA_HOME": str(home / "data"),
                    "SYMFRITZ_BOX_HOST": f"127.0.0.1:{port}",
                    "SYMFRITZ_BOX_USE_TLS": "false",
                    "SYMFRITZ_BOX_TIMEOUT_SECONDS": "2",
                    "LC_ALL": "C",
                    "LANG": "C",
                    "TZ": "UTC",
                }
            )
            args.command = ["services", "--output", "json"]
            go_start = measure(args.go.resolve(), ["version", "--json"], env, root, args.runs, args.warmups)
            rust_start = measure(args.rust.resolve(), ["version", "--json"], {**env, "SYMFRITZ_VERSION": "0.0.0-dev"}, root, args.runs, args.warmups)
            go_fake = measure(args.go.resolve(), args.command, env, root, args.runs, args.warmups)
            rust_fake = measure(args.rust.resolve(), args.command, {**env, "SYMFRITZ_VERSION": "0.0.0-dev"}, root, args.runs, args.warmups)
            go_size = args.go.stat().st_size
            rust_size = args.rust.stat().st_size
            go_rss = max_rss(args.go.resolve(), env, root)
            rust_rss = max_rss(args.rust.resolve(), {**env, "SYMFRITZ_VERSION": "0.0.0-dev"}, root)
            startup_p95 = percentile(rust_start) / percentile(go_start)
            command_p95 = percentile(rust_fake) / percentile(go_fake)
            size_improvement = 1 - rust_size / go_size
            rss_improvement = 1 - rust_rss / go_rss
            report = {
                "schema_version": 1,
                "gate": {
                    "size_or_rss_improvement": size_improvement >= 0.20 or rss_improvement >= 0.20,
                    "latency_regression": command_p95 <= 1.10,
                    "pass": (size_improvement >= 0.20 or rss_improvement >= 0.20) and command_p95 <= 1.10,
                    "thresholds": {"improvement": 0.20, "latency_regression": 0.10},
                },
                "platform": {"os": "darwin", "arch": platform.machine()},
                "binaries": {
                    "go_fallback": {"path": str(args.go), "bytes": go_size, "max_rss_bytes": go_rss, "startup_p95_ms": percentile(go_start), "fake_box_command_p95_ms": percentile(go_fake)},
                    "rust_primary": {"path": str(args.rust), "bytes": rust_size, "max_rss_bytes": rust_rss, "startup_p95_ms": percentile(rust_start), "fake_box_command_p95_ms": percentile(rust_fake)},
                },
                "comparison": {"size_improvement": size_improvement, "rss_improvement": rss_improvement, "startup_p95_ratio": startup_p95, "fake_box_command_p95_ratio": command_p95},
            }
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(args.output)
            if not report["gate"]["pass"]:
                raise SystemExit("Rust value gate failed; retain Go as primary")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
