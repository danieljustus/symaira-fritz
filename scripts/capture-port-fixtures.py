#!/usr/bin/env python3
"""Capture deterministic CLI fixtures from the Go oracle."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

CASES = [
    ("version-text", ["version"]),
    ("version-flag", ["--version"]),
    ("version-json-output", ["version", "--output", "json"]),
    ("version-json-flag", ["version", "--json"]),
    ("version-json-case-insensitive", ["version", "--output", "JSON"]),
    ("version-yaml", ["version", "--output", "yaml"]),
    ("version-extra-argument", ["version", "extra"]),
    ("version-invalid-output", ["--output", "wat", "version"]),
    ("version-conflicting-output", ["version", "--json", "--output", "yaml"]),
]


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default="./symfritz")
    parser.add_argument(
        "--output", default="testdata/port/cli/version-cases.json"
    )
    args = parser.parse_args()

    oracle = str(Path(args.oracle).resolve())
    captured = []
    with tempfile.TemporaryDirectory(prefix="symfritz-port-oracle-") as home:
        env = clean_environment(home)
        for case_id, case_args in CASES:
            result = subprocess.run(
                [oracle, *case_args],
                check=False,
                capture_output=True,
                env=env,
            )
            captured.append(
                {
                    "id": case_id,
                    "args": case_args,
                    "exit_code": result.returncode,
                    "stdout": result.stdout.decode("utf-8"),
                    "stderr": result.stderr.decode("utf-8"),
                    "comparison": "bytes",
                }
            )

    payload = {
        "schema_version": 1,
        "oracle": "Go symfritz built with version=dev",
        "environment": {
            "HOME": "isolated temporary directory",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "SYMFRITZ_*": "unset",
        },
        "cases": captured,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"captured {len(captured)} cases in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
