#!/usr/bin/env python3
"""Run a sanitized FRITZ!Box smoke command or a replay fixture.

Live mode uses the caller's existing credential/config resolution and never
prints or persists command output. Replay fixtures are deliberately local and
must contain only sanitized responses.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class ReplayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    responses: dict[str, dict[str, object]] = {}


class ReplayHandler(http.server.BaseHTTPRequestHandler):
    server: Any

    def do_GET(self) -> None:  # noqa: N802
        response = self.server.responses.get(self.path)
        if response is None:
            self.send_error(404)
            return
        body = response.get("body", "").encode("utf-8")
        self.send_response(int(response.get("status", 200)))
        self.send_header("Content-Type", str(response.get("content_type", "text/xml")))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, format: str, *args: object) -> None:
        return


def load_recording(path: Path) -> dict[str, dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("responses"), dict):
        raise ValueError("recording must use schema_version 1 with a responses object")
    forbidden = ("password", "session_id", "sid", "phone", "mac_address", "public_ip")
    encoded = json.dumps(payload).lower()
    if any(token in encoded for token in forbidden):
        raise ValueError("recording contains a forbidden unsanitized field name")
    return payload["responses"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("live", "replay"), required=True)
    parser.add_argument("--recording", type=Path)
    parser.add_argument("--command", nargs=argparse.REMAINDER, default=["services", "--output", "json"])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "replay" and not args.recording:
        parser.error("--recording is required in replay mode")
    server = None
    thread = None
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("SYMFRITZ_")}
    with tempfile.TemporaryDirectory(prefix="symfritz-smoke-") as temp:
        home = Path(temp)
        env.update({"HOME": str(home), "USERPROFILE": str(home), "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
        if args.mode == "replay":
            server = ReplayServer(("127.0.0.1", 0), ReplayHandler)
            server.responses = load_recording(args.recording)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            env.update({"SYMFRITZ_BOX_HOST": f"127.0.0.1:{server.server_address[1]}", "SYMFRITZ_BOX_USE_TLS": "false"})
        started = time.perf_counter()
        result = subprocess.run([str(args.binary), *args.command], env=env, cwd=home, capture_output=True, timeout=30)
        elapsed_ms = (time.perf_counter() - started) * 1000
    if server:
        server.shutdown()
        server.server_close()
    args.report.write_text(
        json.dumps(
            {"schema_version": 1, "mode": args.mode, "exit_code": result.returncode, "elapsed_ms": round(elapsed_ms, 3), "output_captured": False},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(args.report)
    return 0 if result.returncode == 0 else result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
