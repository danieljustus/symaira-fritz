#!/usr/bin/env python3
"""Compare raw MCP frames from the Go oracle and Rust implementation."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def read_frame(raw: bytes) -> object:
    if not raw:
        return None
    if not raw.startswith(b"Content-Length:"):
        raise AssertionError(f"stdout is not a Content-Length frame: {raw[:80]!r}")
    header, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError("missing frame separator")
    length = int(header.split(b":", 1)[1].strip())
    if len(body) != length:
        raise AssertionError(f"frame length {length} does not match body {len(body)}")
    return json.loads(body)


def comparable(value: object, *, ignore_error_message: bool) -> object:
    if isinstance(value, dict):
        result = {key: comparable(item, ignore_error_message=ignore_error_message) for key, item in value.items()}
        if ignore_error_message and isinstance(result.get("error"), dict):
            error = result["error"]
            assert isinstance(error, dict)
            error.pop("message", None)
        return result
    if isinstance(value, list):
        return [comparable(item, ignore_error_message=ignore_error_message) for item in value]
    return value


def run(binary: str, request: str) -> object:
    completed = subprocess.run(
        [binary, "-serve"],
        input=request.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"{binary} exited {completed.returncode}: {completed.stderr.decode(errors='replace')}")
    if completed.stderr:
        raise AssertionError(f"{binary} wrote diagnostics to stderr: {completed.stderr[:200]!r}")
    return read_frame(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", required=True)
    parser.add_argument("--rust", required=True)
    parser.add_argument("--fixtures", default="testdata/mcp/protocol-fixtures.json")
    args = parser.parse_args()
    fixture = json.loads(Path(args.fixtures).read_text())
    for case in fixture["cases"]:
        expected = case["response"]
        go = run(args.go, case["request"])
        rust = run(args.rust, case["request"])
        ignore = case["name"] in {"invalid-params", "parse-error"}
        if comparable(go, ignore_error_message=ignore) != comparable(rust, ignore_error_message=ignore):
            raise AssertionError(
                f"{case['name']} differs\nGo:   {json.dumps(go, sort_keys=True)}\nRust: {json.dumps(rust, sort_keys=True)}"
            )
        if comparable(rust, ignore_error_message=ignore) != comparable(expected, ignore_error_message=ignore):
            raise AssertionError(f"{case['name']} differs from generated fixture")
    print(f"MCP raw parity: {len(fixture['cases'])} cases passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError) as error:
        print(f"MCP raw parity failed: {error}", file=sys.stderr)
        raise SystemExit(1)
