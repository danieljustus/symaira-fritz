#!/usr/bin/env python3
"""Compare Go and Rust binaries against language-neutral golden fixtures."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def clean_environment(home: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SYMFRITZ_")
    }
    env.update(
        {
            "HOME": home,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
        }
    )
    return env


def run_case(binary: str, args: list[str], home: str) -> dict[str, Any]:
    result = subprocess.run(
        [binary, *args],
        check=False,
        capture_output=True,
        env=clean_environment(home),
    )
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout.decode("utf-8"),
        "stderr": result.stderr.decode("utf-8"),
    }


def compare(case: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    failures = []
    for field in ("exit_code", "stdout", "stderr"):
        if actual[field] != case[field]:
            failures.append(
                f"{field}: expected {case[field]!r}, got {actual[field]!r}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", default="./symfritz")
    parser.add_argument("--candidate", default="./target/debug/symfritz-rust")
    parser.add_argument(
        "--fixture", default="testdata/port/cli/version-cases.json"
    )
    args = parser.parse_args()

    reference = str(Path(args.reference).resolve())
    candidate = str(Path(args.candidate).resolve())
    fixture = json.loads(Path(args.fixture).read_text())

    failed = 0
    with tempfile.TemporaryDirectory(prefix="symfritz-port-parity-") as root:
        for case in fixture["cases"]:
            case_failures = []
            for label, binary in (
                ("reference", reference),
                ("candidate", candidate),
            ):
                home = str(Path(root) / f"{case['id']}-{label}")
                Path(home).mkdir()
                actual = run_case(binary, case["args"], home)
                case_failures.extend(
                    f"{label} {failure}"
                    for failure in compare(case, actual)
                )

            if case_failures:
                failed += 1
                print(f"FAIL {case['id']}")
                for failure in case_failures:
                    print(f"  {failure}")
            else:
                print(f"PASS {case['id']}")

    total = len(fixture["cases"])
    print(f"\n{total - failed}/{total} parity cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
