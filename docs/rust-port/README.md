# Go-to-Rust migration gate

This directory prepares a reversible, contract-first Rust port. The Go binary
remains the executable oracle and production implementation until every row in
[`contract-matrix.md`](contract-matrix.md) passes on all supported platforms.

## Decision

Proceed with a staged port, not a flag-day rewrite. Rust is not a benefit by
itself, and the migration has not yet demonstrated a production gain. Cutover
is gated on observable parity plus measured value.

The initial Rust vertical slice implements the deterministic `version`
contract. It deliberately ships as `symfritz-rust`; `symfritz` remains the Go
binary and rollback path.

## Measured Go baseline

Measured on macOS arm64 with Go 1.26.6 and the repository at commit `9465896`.
The test timing used an empty isolated Go build cache; lint and build followed
with that cache warm.

| Metric | Go baseline |
|---|---:|
| Source | 102 `.go` files / 17,922 lines |
| Tests | 50 files / 10,828 lines |
| `make test` | 11.76 s |
| `make lint` | 2.90 s |
| `make build` | 0.72 s |
| Stripped development binary | 7,669,586 bytes |
| `symfritz version` startup | median 6.106 ms; p95 7.158 ms (100 measured runs after 20 warmups) |
| Maximum resident set size | 11,993,088 bytes (single `/usr/bin/time -l` sample) |

Do not compare a Rust debug build against these numbers. Repeat the benchmark
with release artifacts on the same machine and commit when the implementation
is representative.

### Initial slice signal (not a production comparison)

The release-built Rust `version` slice is 944,624 bytes and measured at
2.959 ms median / 3.468 ms p95 on the same machine (120 runs after 20
warmups). That is 87.7% smaller and 58.6% faster at the median than the Go
oracle in this paired run. This only proves the tiny first slice has low
overhead; it says nothing yet about the complete network/MCP implementation.

## Value gate

A stable cutover requires all of the following:

1. Every contract-matrix row has an executable Go↔Rust parity test.
2. Rust release artifacts improve at least one primary metric materially
   (target: at least 20% smaller binary or 20% lower steady-state memory) while
   startup p95 and command latency regress by no more than 10%.
3. `cargo fmt`, Clippy with warnings denied, tests, doctests, dependency policy,
   security advisories, and native macOS/Linux/Windows jobs are green.
4. Authentication parsers and protocol framing have property or fuzz coverage.
5. Release names, archives, checksums, signing, notarization, Homebrew behavior,
   MCP framing, config files, and rollback are verified.

If Rust cannot meet this gate, keep Go. Rewriting 17,922 lines for vibes would
be expensive theatre.

## Local workflow

```bash
make build
make rust-check
make port-fixtures          # deliberate Go-oracle fixture regeneration
make port-parity-version    # Go + Rust + committed golden fixtures
```

`make port-parity-version` currently covers only the first vertical slice. It
runs both binaries with isolated `HOME`, fixed locale/timezone, and all
`SYMFRITZ_*` variables removed.

## Reuse assessment

Current GitHub/crates.io reconnaissance found no maintained Rust dependency
that covers symfritz's full contract:

- `fritzapi`/`fritzctrl` 0.4.1 (MIT) covers AHA home automation only; its latest
  repository commit is from 2024-12-29.
- `fritz_box_tr064_igd_api_files_generator` is archived and was last pushed in
  2020.
- `tr064_upnp` is a small MPL-2.0 helper last pushed in 2023.
- Other candidates are WIP, GPL-only, or unrelated log/config tools.

Decision: do not adopt one as the transport foundation. Reuse protocol ideas or
MIT-licensed snippets only after focused review; preserve behavior through our
own language-neutral fixtures.

## Sequence

1. Freeze CLI/config/error and fixture contracts.
2. Port pure parsers and authentication vectors.
3. Port TR-064 transport and discovery against deterministic fake boxes.
4. Port typed capabilities, AHA/session behavior, and TLS pin persistence.
5. Port MCP and run raw-frame differential tests with zero stdout pollution.
6. Validate against a real FRITZ!Box using sanitized recordings.
7. Ship a prerelease with the last known-good Go binary as the explicit fallback.
8. Remove Go only after one stable Rust release operates without unexplained
   parity defects.

See [`architecture.md`](architecture.md) for boundaries and
[`contract-matrix.md`](contract-matrix.md) for the executable acceptance map.
