#!/usr/bin/env python3
"""Measure and record the VALUE gate for the Rust symfritz candidate.

Produces a provenance-bound artifact: every number is tied to the candidate
commit, the pinned Go oracle commit, the exact binaries measured (by digest)
and the toolchains that built them. A report that cannot state its own
provenance is not evidence, so this runner refuses to emit one.

The gate is the workspace contract: at least 20% improvement in binary size
OR resident memory, with no more than 10% p95 latency regression. Thresholds
are constants here and are not command-line arguments.

Per Issue #251:
- Builds or verifies the candidate with explicit source-commit provenance.
- Uses production extract_oracle and build_oracle from run-cli-differential.py.
- Validates semantic output per timed operation (rejecting wrong-but-fast payloads).
- Reports measurement uncertainty (standard deviation, standard error, 95% CI).
- Preserves historical artifacts unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Pinned Go oracle, identical to scripts/run-cli-differential.py.
ORACLE_COMMIT = "b1491793aea173eac926e1a0c9db5ba6dd4604a9"

MIN_IMPROVEMENT = 0.20
MAX_LATENCY_REGRESSION = 0.10
SCHEMA_VERSION = 2

DEFAULT_SAMPLES = 60
DEFAULT_WARMUPS = 10

# Representative commands: startup text and fake-box SOAP query with JSON output.
BOX_COMMAND = ["hosts", "list", "--json"]
STARTUP_COMMAND = ["version"]


class GateError(RuntimeError):
    """Any condition that makes the measurement untrustworthy."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def left_fold_sum(values: list[float]) -> float:
    """Explicit ordered summation.

    CPython 3.12+ uses compensated summation in the built-in sum(), so a plain
    sum() makes the recorded mean depend on the interpreter that happened to
    run the harness. Fold explicitly so every interpreter agrees.
    """
    total = 0.0
    for value in values:
        total += value
    return total


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise GateError("cannot take a percentile of zero samples")
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def summarise(values: list[float], unit: str) -> dict[str, Any]:
    """Calculate summary statistics including measurement uncertainty."""
    n = len(values)
    if n < 1:
        raise GateError("cannot summarise empty values")
    mean = left_fold_sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    std_dev = math.sqrt(variance)
    std_err = std_dev / math.sqrt(n)
    ci95_half = 1.96 * std_err
    return {
        "unit": unit,
        "samples": n,
        "min": min(values),
        "mean": mean,
        "std_dev": std_dev,
        "std_err": std_err,
        "ci95": [mean - ci95_half, mean + ci95_half],
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": max(values),
        "raw": values,
    }


def validate_output_semantics(
    args: list[str],
    stdout: bytes,
    stderr: bytes,
    status: int,
    *,
    binary_label: str = "binary",
) -> None:
    """Verify semantic validity of the command output.

    Wrong-but-fast outputs (e.g. dummy JSON `{"wrong_payload": true}`) must fail.
    """
    if status != 0:
        raise GateError(
            f"{binary_label} {' '.join(args)} exited with wait status {status}"
        )
    if stderr:
        raise GateError(
            f"{binary_label} {' '.join(args)} emitted stderr: {stderr[:200]!r}"
        )
    if not stdout.strip():
        raise GateError(f"{binary_label} {' '.join(args)} produced no stdout")

    if args == STARTUP_COMMAND or args == ["version"]:
        text = stdout.decode("ascii", errors="replace").strip()
        if not re.match(r"^symfritz\s+[a-zA-Z0-9._-]+\s*$", text):
            raise GateError(
                f"{binary_label} version output is semantically invalid: {text!r}"
            )
    elif "--json" in args:
        try:
            payload = json.loads(stdout)
        except Exception as exc:
            raise GateError(
                f"{binary_label} {' '.join(args)} did not produce valid JSON: {exc}"
            ) from exc

        if args == BOX_COMMAND or args == ["hosts", "list", "--json"]:
            if not isinstance(payload, list) or len(payload) == 0:
                raise GateError(
                    f"{binary_label} hosts list --json must return a non-empty list"
                )
            found_laptop = False
            for item in payload:
                if not isinstance(item, dict):
                    raise GateError(
                        f"{binary_label} host item is not a dict: {item!r}"
                    )
                name = item.get("name") or item.get("HostName") or item.get("hostname")
                ip = item.get("ip") or item.get("IPAddress") or item.get("ip_address")
                if name == "laptop" and ip == "192.168.1.20":
                    found_laptop = True
                    break
            if not found_laptop:
                raise GateError(
                    f"{binary_label} hosts list --json payload missing expected host "
                    f"'laptop' (192.168.1.20): {payload!r}"
                )
        elif args == ["version", "--json"]:
            if not isinstance(payload, dict):
                raise GateError(f"{binary_label} version --json must return a dict")
            if payload.get("tool") != "symfritz" or not payload.get("version"):
                raise GateError(
                    f"{binary_label} version --json missing tool or version: {payload!r}"
                )


def measure_once(
    harness: Any, binary: Path, args: list[str], *, fake: bool
) -> tuple[float, int]:
    """Run one invocation; return (wall milliseconds, peak RSS bytes).

    Captures stdout/stderr into temporary files and enforces semantic validation
    on each timed call so wrong-but-fast runs fail immediately. Peak RSS comes
    from wait4() for this child alone.
    """
    temp = harness.temporary_directory("symfritz-value-")
    home = Path(temp.name)
    for name in ("tmp", "config", "cache", "data"):
        (home / name).mkdir()
    env = harness.environment(home, fake=fake)

    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            [str(binary), *args],
            cwd=home,
            env=env,
            stdout=out_f,
            stderr=err_f,
        )
        _, status, usage = os.wait4(process.pid, 0)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        process.returncode = 0

        out_f.seek(0)
        err_f.seek(0)
        stdout_bytes = out_f.read()
        stderr_bytes = err_f.read()

    temp.cleanup()

    validate_output_semantics(
        args, stdout_bytes, stderr_bytes, status, binary_label=binary.name
    )

    peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return elapsed_ms, peak


def measure_pair(
    harness: Any,
    go: Path,
    rust: Path,
    args: list[str],
    *,
    fake: bool,
    samples: int,
    warmups: int,
    server: Any = None,
) -> dict[str, Any]:
    """Alternating paired sampling, so drift and ordering affect both sides."""
    times: dict[str, list[float]] = {"go": [], "rust": []}
    peaks: dict[str, list[float]] = {"go": [], "rust": []}
    orders: list[str] = []
    for index in range(warmups + samples):
        go_first = index % 2 == 0
        if index >= warmups:
            orders.append("go-rust" if go_first else "rust-go")
        pairs = [("go", go), ("rust", rust)] if go_first else [("rust", rust), ("go", go)]
        for name, binary in pairs:
            if server is not None:
                server.reset()
            elapsed, peak = measure_once(harness, binary, args, fake=fake)
            if index >= warmups:
                times[name].append(elapsed)
                peaks[name].append(float(peak))
    return {
        "command": args,
        "warmups": warmups,
        "pair_order": orders,
        "go": {
            "latency": summarise(times["go"], "milliseconds"),
            "rss": summarise(peaks["go"], "bytes"),
        },
        "rust": {
            "latency": summarise(times["rust"], "milliseconds"),
            "rss": summarise(peaks["rust"], "bytes"),
        },
    }


def load_harness(root: Path) -> Any:
    """Reuse the existing differential harness: fake box, env isolation, ports."""
    path = root / "scripts/cli-differential.py"
    spec = importlib.util.spec_from_file_location("cli_differential", path)
    if spec is None or spec.loader is None:
        raise GateError(f"cannot load harness from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["cli_differential"] = module
    spec.loader.exec_module(module)
    return module


def load_differential_runner(root: Path) -> Any:
    """Load the differential runner to access production extraction and oracle building."""
    path = root / "scripts/run-cli-differential.py"
    spec = importlib.util.spec_from_file_location("run_cli_differential", path)
    if spec is None or spec.loader is None:
        raise GateError(f"cannot load runner from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_cli_differential"] = module
    spec.loader.exec_module(module)
    return module


def resolve_trusted_tools(runner: Any) -> tuple[Path, Path]:
    """Resolve trusted git and go executables with fallback to system paths."""
    git_env = os.environ.get(runner.TRUSTED_GIT_ENV)
    if git_env:
        git_path = Path(git_env)
    else:
        which_git = shutil.which("git")
        if not which_git:
            raise GateError("git executable not found")
        git_path = Path(which_git).resolve()
    os.environ[runner.TRUSTED_GIT_ENV] = str(git_path)

    go_env = os.environ.get(runner.TRUSTED_GO_ENV)
    if go_env:
        go_path = Path(go_env)
    else:
        for candidate in ["/Users/daniel/sdk/go1.26.6/bin/go", shutil.which("go")]:
            if candidate and Path(candidate).is_file():
                go_path = Path(candidate).resolve()
                break
        else:
            raise GateError("go 1.26.6 executable not found")
    os.environ[runner.TRUSTED_GO_ENV] = str(go_path)

    return git_path, go_path


def verify_rust_candidate(
    binary: Path, expected_commit: str, *, allow_unverified: bool = False
) -> None:
    """Verify that the Rust binary runs and matches expected commit provenance."""
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise GateError(f"candidate binary is not an executable file: {binary}")
    result = subprocess.run(
        [str(binary), "version", "--json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0 or result.stderr:
        raise GateError(
            f"candidate binary failed version check: exit={result.returncode} "
            f"stderr={result.stderr[:200]!r}"
        )
    try:
        data = json.loads(result.stdout)
    except Exception as exc:
        raise GateError(f"candidate binary emitted non-JSON version output: {exc}") from exc

    if data.get("tool") != "symfritz":
        raise GateError(f"candidate binary reported unexpected tool: {data!r}")

    version = data.get("version", "")
    if not allow_unverified:
        # Pinned commit or short prefix match
        if version != expected_commit and not expected_commit.startswith(version):
            raise GateError(
                f"candidate binary build provenance mismatch: binary version {version!r} "
                f"does not match expected commit {expected_commit!r}"
            )


def build_rust_candidate(root: Path, commit: str) -> tuple[Path, str]:
    """Compile the Rust release binary directly with candidate commit bound."""
    env = dict(os.environ, SYMFRITZ_VERSION=commit)
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "symfritz"],
        cwd=root,
        env=env,
        check=True,
    )
    suffix = ".exe" if os.name == "nt" else ""
    binary = root / "target" / "release" / f"symfritz{suffix}"
    verify_rust_candidate(binary, commit)
    return binary, sha256_file(binary)


def build_report(
    root: Path,
    go: Path,
    rust: Path,
    go_toolchain: str,
    go_build_id: str,
    startup: dict[str, Any],
    box: dict[str, Any],
    *,
    allow_dirty: bool = False,
    allow_unverified_binary: bool = False,
) -> dict[str, Any]:
    head = git(root, "rev-parse", "HEAD")
    status = git(root, "status", "--porcelain")
    go_bytes = go.stat().st_size
    rust_bytes = rust.stat().st_size
    go_rss = box["go"]["rss"]["p50"]
    rust_rss = box["rust"]["rss"]["p50"]

    size_improvement = (go_bytes - rust_bytes) / go_bytes
    rss_improvement = (go_rss - rust_rss) / go_rss
    startup_ratio = startup["rust"]["latency"]["p95"] / startup["go"]["latency"]["p95"]
    box_ratio = box["rust"]["latency"]["p95"] / box["go"]["latency"]["p95"]
    worst_regression = max(startup_ratio, box_ratio) - 1.0

    improvement_pass = max(size_improvement, rss_improvement) >= MIN_IMPROVEMENT
    latency_pass = worst_regression <= MAX_LATENCY_REGRESSION

    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "FRITZ-VALUE",
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "provenance": {
            "candidate_commit": head,
            "candidate_clean": status == "",
            "candidate_status": status,
            "oracle_commit": ORACLE_COMMIT,
            "runner": "scripts/value_gate.py",
            "runner_sha256": sha256_file(Path(__file__).resolve()),
            "allow_dirty": allow_dirty,
            "allow_unverified_binary": allow_unverified_binary,
        },
        "toolchains": {
            "go": go_toolchain,
            "cargo": subprocess.run(
                ["cargo", "--version"], capture_output=True, text=True
            ).stdout.strip(),
            "rustc": subprocess.run(
                ["rustc", "--version"], capture_output=True, text=True
            ).stdout.strip(),
            "python": sys.version.split()[0],
        },
        "platform": {
            "os": sys.platform,
            "arch": platform.machine(),
            "release": platform.release(),
        },
        "binaries": {
            "go_oracle": {
                "bytes": go_bytes,
                "sha256": sha256_file(go),
                "built_from": ORACLE_COMMIT,
                "build_id": go_build_id,
            },
            "rust_candidate": {
                "bytes": rust_bytes,
                "sha256": sha256_file(rust),
                "built_from": head,
            },
        },
        "metrics": {"startup": startup, "fake_box_command": box},
        "comparison": {
            "size_improvement": size_improvement,
            "rss_improvement": rss_improvement,
            "startup_p95_ratio": startup_ratio,
            "fake_box_command_p95_ratio": box_ratio,
            "worst_latency_regression": worst_regression,
        },
        "gate": {
            "thresholds": {
                "improvement": MIN_IMPROVEMENT,
                "latency_regression": MAX_LATENCY_REGRESSION,
            },
            "size_or_rss_improvement": improvement_pass,
            "latency_regression_within_limit": latency_pass,
            "pass": improvement_pass and latency_pass,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument(
        "--rust",
        help="prebuilt release symfritz binary (must have matching build provenance)",
    )
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument(
        "--output", help="artifact path (default docs/rust-port/value-gate-<sha>.json)"
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="record a dirty candidate; the artifact is marked accordingly",
    )
    parser.add_argument(
        "--allow-unverified-binary",
        action="store_true",
        help="bypass build provenance check on the Rust binary",
    )
    args = parser.parse_args()

    if args.samples < 20:
        raise GateError("at least 20 samples are required for a p95")
    if args.warmups < 1:
        raise GateError("at least one warmup is required")

    root = Path(args.root).resolve()
    head = git(root, "rev-parse", "HEAD")
    status = git(root, "status", "--porcelain")
    if status and not args.allow_dirty:
        raise GateError(
            "candidate working tree is dirty; commit it or pass --allow-dirty "
            "(the artifact then records the candidate as dirty)"
        )

    runner = load_differential_runner(root)
    git_path, go_path = resolve_trusted_tools(runner)
    go_toolchain = runner.require_go_toolchain()

    if args.rust:
        rust = Path(args.rust).resolve()
        verify_rust_candidate(
            rust, head, allow_unverified=args.allow_unverified_binary
        )
    else:
        rust, _ = build_rust_candidate(root, head)

    harness = load_harness(root)
    harness.PRIVATE_IP = harness.private_address()
    server = harness.StrictFakeBox(("0.0.0.0", harness.PORT), harness.PRIVATE_IP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="symfritz-value-oracle-") as raw:
            oracle_dir = Path(raw)
            archive_sha = runner.extract_oracle(root, oracle_dir, git=git_path)
            provenance = runner.build_oracle(oracle_dir, go_toolchain, archive_sha)
            go = Path(provenance.binary)

            startup = measure_pair(
                harness,
                go,
                rust,
                STARTUP_COMMAND,
                fake=False,
                samples=args.samples,
                warmups=args.warmups,
            )
            box = measure_pair(
                harness,
                go,
                rust,
                BOX_COMMAND,
                fake=True,
                samples=args.samples,
                warmups=args.warmups,
                server=server,
            )
            report = build_report(
                root,
                go,
                rust,
                provenance.go_toolchain,
                provenance.build_id,
                startup,
                box,
                allow_dirty=args.allow_dirty,
                allow_unverified_binary=args.allow_unverified_binary,
            )
    finally:
        server.shutdown()
        server.server_close()

    short_head = head[:8]
    output = (
        Path(args.output)
        if args.output
        else root / f"docs/rust-port/value-gate-{short_head}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    comparison = report["comparison"]
    print(
        f"candidate {report['provenance']['candidate_commit']} "
        f"(clean={report['provenance']['candidate_clean']})"
    )
    print(f"oracle    {ORACLE_COMMIT}")
    print(f"size      {comparison['size_improvement']:+.2%}")
    print(f"rss       {comparison['rss_improvement']:+.2%}")
    print(f"startup   p95 ratio {comparison['startup_p95_ratio']:.4f}")
    print(f"box cmd   p95 ratio {comparison['fake_box_command_p95_ratio']:.4f}")
    print(f"artifact  {output}")
    print("PASS" if report["gate"]["pass"] else "FAIL")
    return 0 if report["gate"]["pass"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
