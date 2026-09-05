# Go-to-Rust migration gate

This directory prepares a reversible, contract-first Rust port. The Go binary
remains the executable oracle and production implementation until every row in
[`contract-matrix.md`](contract-matrix.md) passes on all supported platforms.

## Decision

Proceed with a staged port, not a flag-day rewrite. Rust is not a benefit by
itself, and the migration has not yet demonstrated a production gain. Cutover
is gated on observable parity plus measured value.

The Rust CLI layer now freezes the complete documented Cobra command tree
(command names, `serve` alias, positional arity, flags, defaults, global flags,
version semantics, and help metadata) and wires the `mcp`/`serve` aliases to the
Rust stdio server. The release artifact is named `symfritz`; `symfritz-go` is
kept as the explicit rollback binary.

Implemented slices:

- complete documented clap command tree and parser contracts, with
  language-neutral Go-generated help/inventory and negative-argument fixtures;
- byte-exact CLI `version` behavior;
- legacy MD5 and modern PBKDF2 session challenge responses;
- HTTP Digest challenge parsing and deterministic Authorization headers;
- configuration defaults, TOML/environment precedence, secure initialization,
  and fail-closed credential resolution;
- SOAP request/response/fault handling and nested service discovery through a
  bounded transport;
- concrete blocking HTTP/rustls transport with private-origin DNS pinning,
  SPKI TOFU persistence, strict internal-only fallback, and URL redaction;
- typed AHA-HTTP device/group/switch/thermostat behavior and session-authenticated
  web-origin CPU temperatures, plus TR-064 Homeauto enumeration/switch control,
  with Go-generated fixtures and injectable tests;
- typed TR-064 status reports, including `StatusFailure` values that retain the
  complete all-failure report and its prioritized source error, plus host/Wake-on-LAN, WLAN/guest WLAN, mesh, router
  classification, and bounded TCP diagnosis capabilities, with a Go oracle
  fixture and fake-transport tests;
- typed TR-064 DSL statistics, phone call filtering/dial/hangup, reduced
  online-monitor traffic, filtered device logs, and reboot, with deterministic
  Go-generated fixtures and injected fake-transport tests;
- session-authenticated `query.lua` CPU temperatures in `symfritz-aha`, using the
  web origin and its own SID lifecycle, with one bounded 403 relogin retry;
- `data.lua` raw JSON behavior without the incorrect automatic 403 retry;
- Rust MCP stdio parity for the pinned corekit framing contract, including
  Content-Length and line mode, initialization/instructions/capabilities,
  notifications, JSON-RPC and tool errors, bounded input, nine tool definitions,
  indented text results, and a Go-generated raw-frame differential harness.

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
make port-parity-version    # Go + Rust version golden cases
make mcp-fixtures            # regenerate Go MCP wire fixtures
make mcp-parity              # raw Go oracle ↔ Rust stdio differential
```

`make port-cli-parity` runs both binaries with fresh `HOME`/XDG trees, fixed
locale/timezone, a local fake TR-064 endpoint, deterministic text/JSON/YAML
traffic cases, watch NDJSON flushing, confirmation/no-side-effect behavior,
and SIGINT cancellation. Structured traffic values are compared semantically;
stable version/configuration/confirmation outputs are compared byte-for-byte.

The remaining typed capabilities are split by protocol boundary: TR-064 owns
SOAP/digest operations, while `symfritz-aha::Client` owns session-authenticated
web-origin operations including CPU temperatures and `data.lua`. CPU refreshes
its own SID exactly once after HTTP 403; TR-064 digest and session
authentication are not silently conflated.

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

1. Freeze CLI/config/error and fixture contracts. *(in progress)*
2. Port pure parsers and authentication vectors. *(complete)*
3. Port the TR-064 protocol engine and discovery against deterministic fake
   boxes. *(complete)*
4. Port the concrete HTTP/TLS adapter and TLS pin persistence. *(complete)*
5. Port typed capabilities and AHA/session behavior. *(complete)*
6. Port MCP and run raw-frame differential tests with zero stdout pollution. *(complete: issue #191)*
7. Validate against a real FRITZ!Box using sanitized recordings.
8. Ship a prerelease with the last known-good Go binary as the explicit fallback.
9. Remove Go only after one stable Rust release operates without unexplained
   parity defects.

See [`architecture.md`](architecture.md) for boundaries and
[`contract-matrix.md`](contract-matrix.md) for the executable acceptance map.
