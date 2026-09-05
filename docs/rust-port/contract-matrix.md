# Go↔Rust contract matrix

Status meanings: **PASS** is exercised against committed language-neutral
fixtures; **FROZEN** is covered by the Go oracle but has no Rust implementation;
**PENDING** still needs an explicit fixture or acceptance test.

| ID | Seam | Fixture / input | Go oracle | Expected contract | Rust test | Platforms | Compare | Status |
|---|---|---|---|---|---|---|---|---|
| CLI-001 | Version text | `version` | `./symfritz version` | exit 0; exact stdout; empty stderr | `tests/version.rs` + parity harness | all | bytes | PASS |
| CLI-002 | Version flag | `--version` | `./symfritz --version` | Cobra-compatible text | same | all | bytes | PASS |
| CLI-003 | Version JSON | `version --json`, `--output json`, uppercase format | Go binary | compact schema v1 object | same | all | bytes | PASS |
| CLI-004 | Version YAML | `version --output yaml` | Go binary | ordered three-line YAML | same | all | bytes | PASS |
| CLI-005 | Output errors | invalid and conflicting formats | Go binary | exit 9; exact stderr | same | all | bytes | PASS |
| CLI-006 | Command tree | every command in `docs/cli.md` | `make docs` / `--help` | names, aliases, flags, defaults, inherited flags | `tests/cli_contract.rs` + `scripts/cli-differential.py` | all | semantic inventory/help | PASS |
| CLI-007 | Argument validation | missing/excess args per command | Go binary | deterministic parse exit/stream behavior | `tests/cli_contract.rs` + `scripts/cli-differential.py` | all | exit/stream semantics | PASS |
| CLI-008 | Structured output | strict fake-box success across typed/raw/web handlers in text/JSON/YAML plus watch NDJSON | Go binary + local fake HTTP | field names, omission, stable values, append/flush | `scripts/cli-differential.py` | all; signal leg macOS/Linux | text bytes; structured semantic | PASS |
| CLI-009 | Error taxonomy | output/config/auth/transport/confirmation failures | Go binary | exit codes 1/3/9, stream and structured error shape | `scripts/cli-differential.py` | all | bytes/structured semantic | PASS |
| CLI-010 | Signals | SIGINT during traffic watch | Go binary | flushed output and exit 130 | `scripts/cli-differential.py` | macOS/Linux | semantic | PASS |

| CFG-001 | Defaults | no file/env and timeout matrix | Go loader via generated fixture | host, TLS and 15 s timeout defaults | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-002 | Precedence | global/project TOML plus nested/shorthand env matrix | Go configkit via generated fixture | env overrides project file overrides global file overrides defaults; file zero-values stay ignored | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-003 | Init file | isolated fresh/existing/force writes | Go `initConfigFile` via generated fixture | exact bytes, path-dependent streams, mode and overwrite behavior | `symfritz-core/tests/config_fixtures.rs` | all | bytes + metadata | PASS |
| SEC-001 | Credential order | env/ref/keychain/plaintext success and failure combinations | Go resolver via generated fixture | env → symvault → Keychain → config; configured backend failure stops | `symfritz-core/tests/secret_fixtures.rs` | all/macOS | semantic | PASS |
| SEC-002 | Secret redaction | backend/network failures | Go binary | no password/SID in logs or errors | `symfritz-tr064/tests/tls_transport.rs`, `symfritz-tr064/tests/capabilities.rs`, safe-URL unit tests | all | semantic | PASS |
| TLS-001 | SPKI TOFU | fixed certificate plus live local TLS rotation | Go production pin helper via generated fixture | exact SHA-256 SPKI base64; the first completed handshake pins before HTTP bytes; changed certificate fails | pin fixture + local rustls server | all | bytes/semantic | PASS |
| TLS-002 | Pin persistence | missing/corrupt/reset stores | Go `PinStore` via generated fixture | exact JSON, modes, refusal to overwrite corrupt data, reset recovery | `symfritz-core/tests/pin_fixtures.rs` | all | bytes + metadata | PASS |
| TLS-003 | HTTP fallback | refused/timeout/unreachable vs certificate/TLS/auth failures | Go fallback classifier via generated fixture | fallback only when endpoint does not answer; one warning; internal port rewrite only | transport fixture + unit suites | all | semantic | PASS |
| AUTH-001 | Legacy login | AVM `1234567z` / `äbc` plus surrogate-pair vector | Go production helper via generated fixture | UTF-16LE MD5 responses | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| AUTH-002 | Modern login | PBKDF2 success/error matrix | Go production helper via generated fixture | two-round SHA-256 response; malformed inputs rejected | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| AUTH-003 | SID lifecycle | ready SID, challenge, invalid SID, block time, expiry | Go fake box | request sequence, caching, retry, errors | `symfritz-aha/tests/client.rs` | all | semantic + bytes | PASS |
| DIG-001 | Digest parser | standard, quoted commas, embedded prefix, missing nonce | Go production parser via generated fixture | fields and validity match exactly | `symfritz-core/tests/auth_fixtures.rs` | all | semantic | PASS |
| DIG-002 | Digest header | fixed nonce/cnonce/count vectors | Go production helper with deterministic cnonce seam | RFC-compatible MD5 bytes, qop fallback and 8-digit nc | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| SOAP-001 | Request | empty and multi-argument fixtures | Go production builder with sorted keys | exact XML envelope, lexical argument order and escaping | `symfritz-tr064/tests/fixtures.rs` | all | bytes | PASS |
| SOAP-002 | Response/fault | namespaced, empty, entity, nested, malformed and fault XML | Go production parsers via generated fixture | flat out-args, fault code/description and bounded engine responses | fixture + fake-transport suites | all | semantic/bytes | PASS |
| DISC-001 | Discovery inventory | committed `tr64desc.xml`, nested XML and lookup matrix | Go production parser/resolver via generated fixture | recursive services, sorting, cache/refresh and name resolution | fixture + fake-transport suites | all | semantic | PASS |
| DISC-002 | Discovery URL safety | public host, malformed URL, userinfo and cross-origin/downgrade URLs | Go URL/fallback helpers plus adversarial Rust tests | DNS pinned to private/local addresses, same-origin requests, internal-only downgrade and redacted diagnostics | transport fixture + URL policy suites | all | semantic | PASS |
| CAP-001 | Typed capabilities | status/hosts/diagnose/mesh/WLAN/WOL | Go fake-box handlers | exact requests, models and outputs; status failures retain the complete report and prioritized source taxonomy | `symfritz-tr064/tests/capabilities.rs` + Go fixture | all | semantic/bytes | PASS |
| CAP-002 | AHA capabilities | device/switch/temp/CPU fixtures | Go AHA tests + `port_aha_fixture_test.go` + `status.go` CPU oracle | SID query behavior, XML types, web-origin CPU query, 403 retry, 1 MiB bound, TR-064 Homeauto calls and capability bits | `symfritz-aha/tests/aha.rs`, `symfritz-aha/tests/fixtures.rs`, `symfritz-tr064/tests/homeauto.rs` | all | semantic/bytes | PASS |
| CAP-003 | Phone/traffic/DSL/log/reboot | `testdata/port/capabilities-remaining/contracts.json` | Go `internal/fritz/{dsl,phone,traffic,log}` plus reboot command seam | typed models, parsing/filtering, reduced datasets, request actions/arguments and negative behavior | `symfritz-tr064/tests/remaining_capabilities.rs` + Go fixture drift test | all | semantic/bytes | PASS |
| SCRAPE-001 | `data.lua` | success/error/oversized JSON fixtures | Go scraper tests | best-effort, bounded, version-fragile behavior | `symfritz-aha/tests/client.rs` + `tests/contracts.rs` | all | semantic | PASS |
| MCP-001 | Initialize | raw framed requests | Go fixture oracle | server name/version/instructions/capabilities | `testdata/mcp/protocol-fixtures.json` + `scripts/mcp-differential.py` | all | parsed semantic | PASS |
| MCP-002 | Tool surface | `tools/list` | Go fixture oracle | 9 names, schemas, descriptions, annotations | same | all | parsed semantic | PASS |
| MCP-003 | Tool calls | success/validation/backend failures | Go fixture oracle + production Go models | JSON-RPC IDs, exact Go `toJSON` content text strings, `isError` behavior | production serializer tests + raw-frame tests | all | content.text bytes; semantic envelope | PASS |
| MCP-004 | Stdio hygiene | initialize/list/call/notifications/malformed frames | Go corekit oracle | only protocol frames on stdout; logs on stderr; cancellation returns boundedly with exit 130 | raw-frame process harness + cancellation/worker tests | all | raw framing + semantic | PASS |
| DIST-001 | Artifacts | release snapshot | `scripts/release_snapshot.py` + Go build | six legacy archive names; each contains `symfritz`, `symfritz-go`, LICENSE, README; version/config bytes match | `scripts/test_release_manifest.py` + local host snapshot | host PASS; native matrix in CI | metadata + archive members | PASS |
| DIST-002 | Trust chain | checksums/sign/notarize/SBOM/Homebrew | release workflow | verifiable artifacts and formula smoke test | tag workflow + public asset read-back | all | cryptographic/semantic | PENDING |
| DIST-003 | Release ownership | tag or workflow_dispatch channel | custom release workflow | one publisher; stable tag path; prerelease fallback lifecycle; no GoReleaser race | workflow/actionlint + release-cutover docs | all | workflow semantics | PASS |
| DIST-004 | Value gate | release-built binaries + loopback discovery fixture | Go fallback benchmark oracle | >=20% size or RSS gain and <=10% fake-box p95 regression | `scripts/benchmark_release.py` JSON report | macOS arm64 | measured values | PASS |
| DIST-005 | Rollback compatibility | config.toml + pins.json | Go loader/store | Rust and Go retain config bytes, 0600 mode, and Go-compatible SPKI pin shape | `scripts/release_snapshot.py` | host PASS; native matrix in CI | bytes/metadata | PASS |
| LIVE-002 | Sanitized smoke/replay | operator-provided live box | release-built Go/Rust binaries | no credentials, SID, MAC, IP, phone values, or command output persisted; outcome-only report | `scripts/live_smoke.py` + `live-smoke-20260905.json` | macOS | semantic | PASS |
| DOC-001 | Docs/completions | generated CLI docs + four shells | Go/Cobra generation | no command/help drift | `tests/cli_contract.rs` + completion handler tests | all | semantic inventory + executable scripts | PASS |
| LIVE-001 | Real box | `docs/rust-port/live-smoke-20260905.json` (no command output or identifiers persisted) | release-built Go binary | read-only command exit/schema parity without storing router data | release-built Rust candidate + `scripts/live_smoke.py` | macOS | semantic | PASS |

## Read-only handler slice

Issue #190 subtask 2b wires the production Rust handlers for detection (`detect`
and `config detect`), diagnostic reports (`diagnose` and `diagnose router`),
`doctor`, mesh topology, both AHA and TR-064 `home list` paths, best-effort
`scrape`, version update checking, and bash/fish/PowerShell/zsh completion
scripts. Detection uses an injected runtime seam and preserves configured-host,
gateway, and common-address probe order; mesh uses separate TR-064 and web
origins with the existing SID flow. The focused CLI tests cover handler dispatch,
completion generation, and the command inventory drift gate. The black-box
harness now covers deterministic traffic text/JSON/YAML, watch NDJSON flushing,
confirmation/no-side-effect behavior, and cancellation exit 130.

## Mutation/config/auth handler slice

Issue #190 subtask 3a wires the mutation handlers (`dial`, `hangup`, WOL, guest
on/off, home switch/temp, and confirmed reboot), config initialization, and
credential trust/test/store paths. The handlers use the shared Rust
TR-064/AHA/core implementations; configured secret backends fail closed. The
black-box harness exercises every non-MCP family with a strict local fake box,
including mutation request sequences and an isolated SymVault executable.
Interactive `auth login` is deliberately excluded from this non-interactive
harness because terminal echo/prompt behavior is platform-specific; the
injected credential and secret-resolution tests in
`symfritz-core/tests/auth_fixtures.rs` and `internal/secret` cover the
login/authentication logic without touching a real Keychain or backend. MCP
remains reserved for issue #191.

## Final CLI parity scope and gaps

`make port-cli-parity` builds both binaries and runs
`scripts/cli-differential.py` against an isolated local fake TR-064 endpoint.
The harness compares every implemented non-MCP command family through
executable help, validation, success, error, config, auth-test/store, and
mutation checks. It binds the fake box on `0.0.0.0:49000`, discovers the local
RFC1918 address dynamically, and compares request method, route, SOAP action,
arguments, authentication sequence, output semantics, and mutation order.
Temporary HOME/config paths are normalized; structured JSON is compared
semantically, and doctor compares the shared structured report plus stable
failure status while allowing the language-specific error suffix. Watch mode
requires valid object-per-line NDJSON, cancellation exit 130, matching stderr,
and an equivalent final snapshot because poll timing can change the first
in-flight snapshot. The MCP-specific harness is
`scripts/mcp-differential.py`: it runs the Go-generated deterministic oracle and
Rust fixture server against raw Content-Length frames, including initialize,
tools/list, notifications, tool successes, tool errors, invalid params, and
parse errors. There are no skip or `NON-PASS` paths: a required family failure aborts the
run. The only intentional exclusion is interactive auth login (terminal-specific;
covered by injected/secret tests as described above).

The matrix below still tracks repository-wide work outside this issue,
including release/live-box coverage; those rows are not claimed by the
non-MCP CLI harness.

## Rules

- A row moves to **PASS** only when the Rust test and differential comparison are
  executable in CI.
- Byte comparison is mandatory for protocol frames, version/help/error output,
  generated artifacts, and persisted files unless this table records a reason.
- Randomness, clocks, locale, timezone, HOME, and network endpoints must be
  controlled. No unexplained normalization is allowed.
- Live fixtures must be sanitized and must never contain passwords, SIDs, MACs,
  public IPs, phone numbers, or other personal data.
