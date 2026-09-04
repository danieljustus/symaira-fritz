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
| CLI-006 | Command tree | every command in `docs/cli.md` | `make docs` / `--help` | names, aliases, flags, defaults, inherited flags | `tests/cli_contract.rs` | all | semantic inventory/help; byte layout pending | FROZEN |
| CLI-007 | Argument validation | missing/excess args per command | Go binary | exact exit, stdout, stderr | `tests/cli_contract.rs` | all | parse semantics; byte wording pending | PENDING |
| CLI-008 | Structured output | text/JSON/YAML for every command | fake-box scenarios | snake_case, omission, ordering where stable | command parity suite | all | parsed/bytes per row | PENDING |
| CLI-009 | Error taxonomy | auth/config/not-found/transport/timeout/cancel | Go binary | exit codes, kind, message, hint, output stream | negative command suite | all | bytes | FROZEN |
| CLI-010 | Signals | SIGINT/SIGTERM during request/watch/MCP | Go binary | cancellation and interrupted exit code | process tests | macOS/Linux | semantic | PENDING |
| CFG-001 | Defaults | no file/env and timeout matrix | Go loader via generated fixture | host, TLS and 15 s timeout defaults | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-002 | Precedence | global/project TOML plus nested/shorthand env matrix | Go configkit via generated fixture | env overrides project file overrides global file overrides defaults; file zero-values stay ignored | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-003 | Init file | isolated fresh/existing/force writes | Go `initConfigFile` via generated fixture | exact bytes, path-dependent streams, mode and overwrite behavior | `symfritz-core/tests/config_fixtures.rs` | all | bytes + metadata | PASS |
| SEC-001 | Credential order | env/ref/keychain/plaintext success and failure combinations | Go resolver via generated fixture | env → symvault → Keychain → config; configured backend failure stops | `symfritz-core/tests/secret_fixtures.rs` | all/macOS | semantic | PASS |
| SEC-002 | Secret redaction | backend/network failures | Go binary | no password/SID in logs or errors | `symfritz-tr064/tests/tls_transport.rs`, `symfritz-tr064/tests/capabilities.rs`, safe-URL unit tests | all | semantic | PASS |
| TLS-001 | SPKI TOFU | fixed certificate plus live local TLS rotation | Go production pin helper via generated fixture | exact SHA-256 SPKI base64; first trust succeeds; changed certificate fails | pin fixture + local rustls server | all | bytes/semantic | PASS |
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
| MCP-001 | Initialize | raw framed requests | `symfritz mcp` | server name/version/capabilities | raw-frame harness | all | bytes | PENDING |
| MCP-002 | Tool surface | `tools/list` | Go MCP server | 9 names, schemas, descriptions, annotations | schema fixture | all | parsed + selected bytes | FROZEN |
| MCP-003 | Tool calls | success/validation/backend failures | Go fake box | JSON-RPC IDs, content text strings, `isError` behavior | raw-frame suite | all | bytes | FROZEN |
| MCP-004 | Stdio hygiene | initialize/list/call/cancel/malformed frames | Go MCP server | only protocol frames on stdout; logs on stderr | process suite | all | bytes | PENDING |
| DIST-001 | Artifacts | release snapshot | GoReleaser | same binary/archive names and target set | release manifest diff | all | metadata | FROZEN |
| DIST-002 | Trust chain | checksums/sign/notarize/SBOM/Homebrew | release workflow | verifiable artifacts and formula smoke test | prerelease gate | all | cryptographic/semantic | PENDING |
| DOC-001 | Docs/completions | generated CLI docs + four shells | Go/Cobra generation | no command/help drift | generated artifact diff | all | bytes | FROZEN |
| LIVE-001 | Real box | sanitized recordings for supported FRITZ!OS | installed Go binary | request/response and side-effect parity | replay + approved live smoke | macOS/Linux | semantic | PENDING |

## Read-only handler slice

Issue #190 subtask 2b wires the production Rust handlers for detection (`detect`
and `config detect`), diagnostic reports (`diagnose` and `diagnose router`),
`doctor`, mesh topology, both AHA and TR-064 `home list` paths, best-effort
`scrape`, version update checking, and bash/fish/PowerShell/zsh completion
scripts. Detection uses an injected runtime seam and preserves configured-host,
gateway, and common-address probe order; mesh uses separate TR-064 and web
origins with the existing SID flow. The focused CLI tests cover handler dispatch
and completion generation. CLI-008 remains **PENDING** for a full CLI-level
fake-box differential suite; protocol-level service and session fixtures remain
in CAP-001–003 and SCRAPE-001. Real-router checks, live GitHub update responses,
signal handling, and MCP remain intentionally out of this slice. Mutation
commands (`dial`, `hangup`, WOL, guest on/off, home switch/temp, reboot), config
init/auth writes, and `traffic --watch` remain unimplemented.

## Rules

- A row moves to **PASS** only when the Rust test and differential comparison are
  executable in CI.
- Byte comparison is mandatory for protocol frames, version/help/error output,
  generated artifacts, and persisted files unless this table records a reason.
- Randomness, clocks, locale, timezone, HOME, and network endpoints must be
  controlled. No unexplained normalization is allowed.
- Live fixtures must be sanitized and must never contain passwords, SIDs, MACs,
  public IPs, phone numbers, or other personal data.
