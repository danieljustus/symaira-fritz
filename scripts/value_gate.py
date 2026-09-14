#!/usr/bin/env python3
"""Measure and record the VALUE gate for the Rust symfritz candidate.

Produces a provenance-bound artifact: every number is tied to the candidate
commit, the pinned Go oracle commit, the exact binaries measured (by digest)
and the toolchains that built them. A report that cannot state its own
provenance is not evidence, so this runner refuses to emit one.

The gate is the workspace contract: at least 20% improvement in binary size
OR resident memory, with no more than 10% p95 latency regression. Thresholds
are constants here and are not command-line arguments.

This runner measures; it does not decide policy. A failing gate is written
out and reported with a non-zero exit, never silently retried or discarded.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import tarfile
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

# Representative fake-box command: digest challenge, SOAP call and JSON output.
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
    import math

    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def summarise(values: list[float], unit: str) -> dict[str, Any]:
    return {
        "unit": unit,
        "samples": len(values),
        "min": min(values),
        "mean": left_fold_sum(values) / len(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": max(values),
        "raw": values,
    }


def extract_oracle(root: Path, destination: Path) -> None:
    archive = subprocess.run(
        ["git", "-C", str(root), "archive", ORACLE_COMMIT], check=True, capture_output=True
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise GateError(f"refusing unsafe oracle archive member: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise GateError(f"refusing non-regular oracle member: {member.name}")
            if member.mode & (0o4000 | 0o2000):
                raise GateError(f"refusing setuid/setgid oracle member: {member.name}")
        if sys.version_info >= (3, 12):
            bundle.extractall(destination, filter="data")
        else:
            bundle.extractall(destination)


def build_go_oracle(root: Path, workdir: Path) -> tuple[Path, str]:
    """Build the pinned Go oracle with the same flags the differential uses."""
    extract_oracle(root, workdir)
    binary = workdir / "symfritz-go"
    subprocess.run(
        ["go", "build", "-trimpath", "-ldflags", "-s -w -X main.version=dev",
         "-o", str(binary), "./cmd/symfritz"],
        cwd=workdir, env=dict(os.environ, CGO_ENABLED="0"), check=True,
    )
    version = subprocess.run(["go", "version"], capture_output=True, text=True, check=True)
    return binary, version.stdout.strip()


def measure_once(harness: Any, binary: Path, args: list[str], *, fake: bool) -> tuple[float, int]:
    """Run one invocation; return (wall milliseconds, peak RSS bytes).

    Peak RSS comes from wait4() for this child alone, not from a cumulative
    RUSAGE_CHILDREN reading, which would otherwise report the high-water mark
    of every child the harness has ever spawned.
    """
    temp = harness.temporary_directory("symfritz-value-")
    home = Path(temp.name)
    for name in ("tmp", "config", "cache", "data"):
        (home / name).mkdir()
    env = harness.environment(home, fake=fake)
    # Output goes to DEVNULL rather than a pipe: nothing reads these streams
    # while the child runs, so a pipe would risk filling and deadlocking the
    # measurement. Correctness of the output is established once, separately,
    # by validate_command() before any timing begins.
    started = time.perf_counter_ns()
    process = subprocess.Popen(
        [str(binary), *args], cwd=home, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _, status, usage = os.wait4(process.pid, 0)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    # os.wait4 already reaped the child, so tell Popen not to reap it again.
    process.returncode = 0
    temp.cleanup()
    if status != 0:
        raise GateError(f"{binary.name} {' '.join(args)} exited with wait status {status}")
    # macOS reports ru_maxrss in bytes; Linux reports kilobytes.
    peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return elapsed_ms, peak


def validate_command(harness: Any, binary: Path, args: list[str], *,
                    fake: bool, server: Any = None) -> None:
    """Prove the measured command actually succeeds and produces output.

    Timed runs discard their streams, so an invocation that silently started
    failing would otherwise still be reported as a fast one.
    """
    temp = harness.temporary_directory("symfritz-value-check-")
    home = Path(temp.name)
    for name in ("tmp", "config", "cache", "data"):
        (home / name).mkdir()
    if server is not None:
        server.reset()
    process = subprocess.run(
        [str(binary), *args], cwd=home, env=harness.environment(home, fake=fake),
        capture_output=True, timeout=30,
    )
    temp.cleanup()
    if process.returncode != 0 or process.stderr:
        raise GateError(
            f"{binary.name} {' '.join(args)} is not a valid measurement command: "
            f"exit={process.returncode} stderr={process.stderr[:200]!r}"
        )
    if not process.stdout.strip():
        raise GateError(f"{binary.name} {' '.join(args)} produced no output")
    if "--json" in args:
        try:
            json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise GateError(
                f"{binary.name} {' '.join(args)} did not produce JSON: {error}"
            ) from error


def measure_pair(harness: Any, go: Path, rust: Path, args: list[str], *,
                 fake: bool, samples: int, warmups: int, server: Any = None) -> dict[str, Any]:
    """Alternating paired sampling, so drift and ordering affect both sides."""
    for binary in (go, rust):
        validate_command(harness, binary, args, fake=fake, server=server)
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
        "go": {"latency": summarise(times["go"], "milliseconds"),
               "rss": summarise(peaks["go"], "bytes")},
        "rust": {"latency": summarise(times["rust"], "milliseconds"),
                 "rss": summarise(peaks["rust"], "bytes")},
    }


def build_report(root: Path, go: Path, rust: Path, go_toolchain: str,
                 startup: dict[str, Any], box: dict[str, Any]) -> dict[str, Any]:
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
        },
        "toolchains": {
            "go": go_toolchain,
            "cargo": subprocess.run(["cargo", "--version"], capture_output=True, text=True).stdout.strip(),
            "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip(),
            "python": sys.version.split()[0],
        },
        "platform": {
            "os": sys.platform,
            "arch": platform.machine(),
            "release": platform.release(),
        },
        "binaries": {
            "go_oracle": {"bytes": go_bytes, "sha256": sha256_file(go),
                          "built_from": ORACLE_COMMIT},
            "rust_candidate": {"bytes": rust_bytes, "sha256": sha256_file(rust),
                               "built_from": head},
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
            "thresholds": {"improvement": MIN_IMPROVEMENT,
                           "latency_regression": MAX_LATENCY_REGRESSION},
            "size_or_rss_improvement": improvement_pass,
            "latency_regression_within_limit": latency_pass,
            "pass": improvement_pass and latency_pass,
        },
    }


def load_harness(root: Path) -> Any:
    """Reuse the existing differential harness: fake box, env isolation, ports."""
    import importlib.util

    path = root / "scripts/cli-differential.py"
    spec = importlib.util.spec_from_file_location("cli_differential", path)
    if spec is None or spec.loader is None:
        raise GateError(f"cannot load harness from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["cli_differential"] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--rust", help="release symfritz binary (default target/release/symfritz)")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument("--output", help="artifact path (default docs/rust-port/value-gate-<sha>.json)")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="record a dirty candidate; the artifact is marked accordingly")
    args = parser.parse_args()

    if args.samples < 20:
        raise GateError("at least 20 samples are required for a p95")
    if args.warmups < 1:
        raise GateError("at least one warmup is required")

    root = Path(args.root).resolve()
    rust = Path(args.rust).resolve() if args.rust else root / "target/release/symfritz"
    if not rust.is_file():
        raise GateError(f"Rust release binary missing: {rust}; run cargo build --release")

    if git(root, "status", "--porcelain") and not args.allow_dirty:
        raise GateError(
            "candidate working tree is dirty; commit it or pass --allow-dirty "
            "(the artifact then records the candidate as dirty)"
        )

    harness = load_harness(root)
    harness.PRIVATE_IP = harness.private_address()
    server = harness.StrictFakeBox(("0.0.0.0", harness.PORT), harness.PRIVATE_IP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="symfritz-value-oracle-") as raw:
            go, go_toolchain = build_go_oracle(root, Path(raw))
            startup = measure_pair(harness, go, rust, STARTUP_COMMAND,
                                   fake=False, samples=args.samples, warmups=args.warmups)
            box = measure_pair(harness, go, rust, BOX_COMMAND, fake=True,
                               samples=args.samples, warmups=args.warmups, server=server)
            report = build_report(root, go, rust, go_toolchain, startup, box)
    finally:
        server.shutdown()
        server.server_close()

    head = report["provenance"]["candidate_commit"][:8]
    output = Path(args.output) if args.output else root / f"docs/rust-port/value-gate-{head}.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    comparison = report["comparison"]
    print(f"candidate {report['provenance']['candidate_commit']} "
          f"(clean={report['provenance']['candidate_clean']})")
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
