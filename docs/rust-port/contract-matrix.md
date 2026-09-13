# Rust contract matrix

**PASS** means the contract remains executable through Rust tests, a strict
fake-box harness, or release validation. The frozen v0.7 oracle column records
provenance; it does not require Go source in the current repository.

| ID | Seam | Fixture / input | Frozen v0.7 oracle | Expected contract | Rust test | Platforms | Compare | Status |
|---|---|---|---|---|---|---|---|---|
| CLI-001 | Version text | `version` | `./symfritz version` | exit 0; exact stdout; empty stderr | `tests/version.rs` + parity harness | all | bytes | PASS |
| CLI-002 | Version flag | `--version` | `./symfritz --version` | Cobra-compatible text | same | all | bytes | PASS |
| CLI-003 | Version JSON | `version --json`, `--output json`, uppercase format | Go binary | compact schema v1 object | same | all | bytes | PASS |
| CLI-004 | Version YAML | `version --output yaml` | Go binary | ordered three-line YAML | same | all | bytes | PASS |
| CLI-005 | Output errors | invalid and conflicting formats | Go binary | exit 9; exact stderr | same | all | bytes | PASS |
| CLI-006 | Command tree | every command in `docs/cli.md` | frozen command fixture / `--help` | names, aliases, flags, defaults, inherited flags | `tests/cli_contract.rs` + `scripts/cli-differential.py` | all | semantic inventory/help | PASS |
| CLI-007 | Argument validation | missing/excess args per command | Go binary | deterministic parse exit/stream behavior | `tests/cli_contract.rs` + `scripts/cli-differential.py` | all | exit/stream semantics | PASS |
| CLI-008 | Structured output | strict fake-box success across typed/raw/web handlers in text/JSON/YAML plus watch NDJSON, including credential and state-changing (mutation) commands (PR #233, closes #219/#220/#224/#225) | Go binary + local fake HTTP | field names, omission, stable values, append/flush; mutation and credential-storage commands (`home switch`, `home temp`, TR-064 `home switch`, `reboot --confirm`, `auth store`) emit the same stable JSON/YAML success payloads as read-only commands, not just text; `--output`/equals-syntax flag placement is preserved after the target or subcommand | `scripts/cli-differential.py` (`home-switch-on-json`, `home-switch-on-yaml`, `reboot-confirmed-json`, `auth-store-symvault-json`, and siblings) | all; signal leg macOS/Linux | text bytes; structured semantic | PASS |
| CLI-009 | Error taxonomy | output/config/auth/transport/confirmation failures | Go binary | exit codes 1/3/9, stream and structured error shape | `scripts/cli-differential.py` | all | bytes/structured semantic | PASS |
| CLI-010 | Signals | SIGINT during traffic watch | Go binary | flushed output and exit 130 | `scripts/cli-differential.py` | macOS/Linux | semantic | PASS |
| CLI-011 | Target selector arity | `host get`/`wol` and MCP `host_get`/`wake_on_lan` with zero, one, and multiple of name/mac/ip | none (Rust-only hardening; issue #224 found no Go equivalent guard) | exactly one target selector accepted per call; identical rejection semantics across the CLI and MCP surfaces; the capability is never invoked on a rejected call | `crates/symfritz-mcp/tests/selector_validation.rs` (`CountingCapabilities`, call-count assertions) + `scripts/cli-differential.py` | all | semantic | PASS |

| CFG-001 | Defaults | no file/env and timeout matrix | Go loader via generated fixture | host, TLS and 15 s timeout defaults | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-002 | Precedence | global/project TOML plus nested/shorthand env matrix | Go configkit via generated fixture | env overrides project file overrides global file overrides defaults; file zero-values stay ignored | `symfritz-core/tests/config_fixtures.rs` | all | semantic | PASS |
| CFG-003 | Init file | isolated fresh/existing/force writes | Go `initConfigFile` via generated fixture | exact bytes, path-dependent streams, mode and overwrite behavior | `symfritz-core/tests/config_fixtures.rs` | all | bytes + metadata | PASS |
| SEC-001 | Credential order | env/ref/keychain/plaintext success and failure combinations | Go resolver via generated fixture | env → symvault → Keychain → config; configured backend failure stops | `symfritz-core/tests/secret_fixtures.rs` | all/macOS | semantic | PASS |
| SEC-002 | Secret redaction | backend/network failures | Go binary | no password/SID in logs or errors | `symfritz-tr064/tests/tls_transport.rs`, `symfritz-tr064/tests/capabilities.rs`, safe-URL unit tests | all | semantic | PASS |
| TLS-001 | SPKI TOFU | fixed certificate plus live local TLS rotation | Go production pin helper via generated fixture | pin-only router identity keyed by configured host; private/local DNS is bound to the socket; the first completed handshake pins exact SHA-256 SPKI before HTTP bytes; changed certificate fails; `insecure_tls` is an explicit opt-out | pin fixture + local rustls server | all | bytes/semantic | PASS |
| TLS-002 | Pin persistence | missing/corrupt/reset stores | Go `PinStore` via generated fixture | exact JSON, modes, refusal to overwrite corrupt data, reset recovery | `symfritz-core/tests/pin_fixtures.rs` | all | bytes + metadata | PASS |
| TLS-003 | HTTP fallback | refused/timeout/unreachable vs certificate/TLS/auth failures; `[box].allow_http_fallback` true/false/absent matrix (PR #228, issue #221) | Go fallback classifier via generated fixture, **diverges**: Rust adds a secure-by-default opt-in the Go oracle never had | fallback requires explicit `allow_http_fallback = true` (config default `false`); only then does it trigger when the endpoint does not answer, emit one warning, and rewrite the port internally; certificate/pin/TLS-handshake failures never downgrade regardless of the flag; the default-`false` path returns an actionable error naming the config key | `symfritz-core/tests/config_fixtures.rs` (`allow_http_fallback` load/precedence), `symfritz-tr064/tests/tls_transport.rs::endpoint_unreachable_requires_explicit_http_fallback_opt_in`, `::endpoint_unreachable_falls_back_once_and_reuses_http` | all | semantic | PASS |
| AUTH-001 | Legacy login | AVM `1234567z` / `äbc` plus surrogate-pair vector | Go production helper via generated fixture | UTF-16LE MD5 responses | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| AUTH-002 | Modern login | PBKDF2 success/error matrix | Go production helper via generated fixture | two-round SHA-256 response; malformed inputs rejected | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| AUTH-003 | SID lifecycle | ready SID, challenge, invalid SID, block time, expiry | Go fake box | request sequence, caching, retry, errors | `symfritz-aha/tests/client.rs` | all | semantic + bytes | PASS |
| DIG-001 | Digest parser | standard, quoted commas, embedded prefix, missing nonce | Go production parser via generated fixture | fields and validity match exactly | `symfritz-core/tests/auth_fixtures.rs` | all | semantic | PASS |
| DIG-002 | Digest header | fixed nonce/cnonce/count vectors | Go production helper with deterministic cnonce seam | RFC-compatible MD5 bytes, qop fallback and 8-digit nc | `symfritz-core/tests/auth_fixtures.rs` | all | bytes | PASS |
| SOAP-001 | Request | empty and multi-argument fixtures | Go production builder with sorted keys | exact XML envelope, lexical argument order and escaping | `symfritz-tr064/tests/fixtures.rs` | all | bytes | PASS |
| SOAP-002 | Response/fault | namespaced, empty, entity, nested, malformed and fault XML | Go production parsers via generated fixture | flat out-args, fault code/description and bounded engine responses | fixture + fake-transport suites | all | semantic/bytes | PASS |
| SOAP-003 | Response stream framing | chunked and content-length bodies split across multiple TCP reads (PR #232, issue #226) | none (Rust-only correctness/perf hardening; Go used per-call reads that this seam does not carry forward) | header and chunk-delimiter parsing reuse one buffered reader so bytes read past a delimiter are retained instead of dropped; a representative chunked response completes in exactly one underlying read | `symfritz-tr064/src/transport.rs` unit tests (`CountingReader`, lines ~1181-1234) | all | semantic | PASS |
| DISC-001 | Discovery inventory | committed `tr64desc.xml`, nested XML and lookup matrix | Go production parser/resolver via generated fixture | recursive services, sorting, cache/refresh and name resolution | fixture + fake-transport suites | all | semantic | PASS |
| DISC-002 | Discovery URL safety | public host, malformed URL, userinfo and cross-origin/downgrade URLs | Go URL/fallback helpers plus adversarial Rust tests | DNS pinned to private/local addresses, same-origin requests, internal-only downgrade and redacted diagnostics | transport fixture + URL policy suites | all | semantic | PASS |
| CAP-001 | Typed capabilities | status/hosts/diagnose/mesh/WLAN/WOL | Go fake-box handlers | exact requests, models and outputs; status failures retain the complete report and prioritized source taxonomy; guest-WLAN index and `radios()` enumerate the indices the box actually advertises in `tr64desc.xml` rather than assuming a fixed dual-band `1..=3` window (a wrong assumption on tri-band boxes let `wlan guest off` target a live 5 GHz radio — fixed in PR #234, found against a real FRITZ!Box 4060); mesh peer names resolve both the `node_1_uid`/`node_2_uid` keys FRITZ!OS sends and the legacy bare `node_1`/`node_2` spelling via `serde(alias)`, with serialized field names unchanged | `symfritz-tr064/tests/capabilities.rs` + Go fixture; `symfritz-tr064/tests/remaining_capabilities.rs::guest_wlan_index_follows_the_box_instead_of_assuming_three`, `::guest_wlan_index_reports_a_box_without_wlan_services`, `::radios_probe_every_advertised_wlan_configuration`; `symfritz-tr064/tests/mesh_optional.rs::mesh_links_resolve_peers_from_the_uid_keys_fritzos_actually_sends`, `::mesh_still_accepts_the_bare_node_key_spelling` | all | semantic/bytes | PASS |
| CAP-002 | AHA capabilities | device/switch/temp/CPU fixtures | Go AHA tests + `port_aha_fixture_test.go` + `status.go` CPU oracle | SID query behavior, XML types, web-origin CPU query, 403 retry, 1 MiB bound, TR-064 Homeauto calls and capability bits | `symfritz-aha/tests/aha.rs`, `symfritz-aha/tests/fixtures.rs`, `symfritz-tr064/tests/homeauto.rs` | all | semantic/bytes | PASS |
| CAP-003 | Phone/traffic/DSL/log/reboot | `testdata/port/capabilities-remaining/contracts.json` | Go `internal/fritz/{dsl,phone,traffic,log}` plus reboot command seam, **diverges** on call/log timestamps (see below, PR #234) | typed models, parsing/filtering, reduced datasets, request actions/arguments and negative behavior; `calls --limit` filters by `--type` first and caps the *filtered* result, sending the router-side `max` cap only when no type filter narrows the list (previously the router cap applied before filtering, so a narrow `--type` could return far fewer than `--limit` rows); call and log timestamps are emitted without a `Z`/UTC suffix because the box reports its own unlabeled wall-clock time, not UTC — a recorded, deliberate divergence from the Go oracle, not a bug | `symfritz-tr064/tests/remaining_capabilities.rs` + Go fixture drift test; `::calls_limit_counts_matching_calls_not_router_rows`, `::calls_without_type_filter_still_caps_router_side`, `::box_timestamps_are_not_labelled_utc` | all | semantic/bytes | PASS |
| SCRAPE-001 | `data.lua` | success/error/oversized JSON fixtures | Go scraper tests | best-effort, bounded, version-fragile behavior | `symfritz-aha/tests/client.rs` + `tests/contracts.rs` | all | semantic | PASS |
| MCP-001 | Initialize | raw framed requests | frozen corekit framing | server name/version/instructions/capabilities | `symfritz-mcp` initialize/line/framed unit tests | all | parsed semantic | PASS |
| MCP-002 | Tool surface | `tools/list` | frozen tool fixture | 9 names, schemas, descriptions, annotations | `symfritz-mcp::tests::tool_surface_is_frozen` | all | parsed semantic | PASS |
| MCP-003 | Tool calls | success/validation/backend failures; missing/non-boolean `home_switch.on` (PR #227, issue #222) | frozen content/error fixtures | JSON-RPC IDs, exact content text strings, `isError` behavior; `home_switch` rejects a missing or non-boolean `on` argument with a tool error before the capability is dispatched (a malformed call could otherwise default to turning a switch off), and its MCP annotations declare it destructive and idempotent | MCP tool tests + production CLI serializer tests; `crates/symfritz-mcp/src/lib.rs::home_switch_rejects_invalid_on_without_calling_capability` | all | content.text bytes; semantic envelope | PASS |
| MCP-004 | Stdio hygiene | initialize/list/call/notifications/malformed frames | frozen corekit behavior | only protocol frames on stdout; logs on stderr; cancellation returns boundedly with exit 130 | framing property tests + cancellation/worker unit tests | all | raw framing + semantic | PASS |
| DIST-001 | Artifacts | release snapshot | v0.7 archive names | six legacy archive names; each contains `symfritz`, LICENSE, README | `scripts/test_release_manifest.py` + local host snapshot | host + native CI matrix | metadata + archive members | PASS |
| DIST-002 | Trust chain | v0.7.0 release plus remote Formula | release workflow | six signed dual-binary archives, six SBOMs, checksums, manifest, exact tag/assets, and installed Formula smoke for both binaries | public v0.7.0 asset/checksum/signature read-back + remote Formula/install verification | all | cryptographic/semantic | PASS |
| DIST-003 | Release ownership | tag or workflow_dispatch channel | custom release workflow | one publisher; stable tag path; prerelease fallback lifecycle; no GoReleaser race | workflow/actionlint + release-cutover docs | all | workflow semantics | PASS |
| DIST-004 | Value gate | v0.7 release-built binaries + loopback fixture | archived Go fallback benchmark | >=20% size or RSS gain and <=10% fake-box p95 regression at cutover | `value-gate-20260905.json` | macOS arm64 | measured values | PASS |
| DIST-005 | Config compatibility | config.toml + pins.json | frozen loader/store fixtures | Rust retains config bytes, 0600 mode, and the frozen SPKI pin shape | fixture tests + `scripts/release_snapshot.py` | all | bytes/metadata | PASS |
| DIST-006 | Rust-only distribution | v0.8.0 release plus remote Formula | v0.7.0 immutable rollback | six signed single-binary archives, six SBOMs, checksums, manifest schema v2, and Formula smoke | public v0.8.0 readback + local archive/signature/Homebrew verification | all | cryptographic/semantic | PASS |
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

`make cli-contract` builds the Rust binary and runs
`scripts/cli-differential.py` against an isolated strict fake TR-064 endpoint.
The retained harness exercises every non-MCP command family through executable
help, validation, success, error, config, auth-test/store, and mutation checks.
It binds the fake box on `0.0.0.0:49000`, discovers the local RFC1918 address,
and validates request method, route, SOAP action, arguments, authentication
sequence, output semantics, and mutation order. Temporary HOME/config paths are
normalized. Watch mode requires valid object-per-line NDJSON, cancellation exit
130, empty diagnostics and stable snapshots. MCP framing, tool calls,
notifications, invalid params, parse errors, cancellation and bounded input are
executable Rust unit/property tests. There are no skip or `NON-PASS` paths.

The matrix below still tracks repository-wide work outside this issue,
including release/live-box coverage; those rows are not claimed by the
non-MCP CLI harness.

## Post-v0.7.0 hardening (2026-09-13 audit)

The rows above were re-verified against the repository at commit `3dd3284`
(branch `phase1-register-20260913`, forked from `origin/main`) on 2026-09-13:
`cargo build --workspace --locked`, `cargo test --workspace --all-features
--locked` (35 test binaries, 0 failures), `make lint`, and `make cli-contract`
(39/39 PASS) all pass locally. Six real, merged PRs landed after the v0.7.0/
v0.8.0 cutover record in this file and are now folded into the rows above
instead of being tracked separately:

- **#227** `fix(mcp): reject malformed home switch arguments` (issue #222) — MCP-003.
- **#228** `fix(transport): require opt-in for HTTP fallback` (issue #221) — TLS-003.
- **#232** `perf: buffer TR-064 response parsing` (issue #226) — new row SOAP-003.
- **#233** `feat: complete structured CLI mutation contracts` (issues #219, #220,
  #224, #225) — CLI-008, new row CLI-011.
- **#234** `fix: correct guest WLAN index, mesh peers, timestamps, and call
  limit` — CAP-001, CAP-003.

**Release gap, flagged for the maintainer:** #234 was merged to `main` at
`8d7eed6` on 2026-09-06T16:37Z, but the latest published tag is `v0.8.1`
(2026-09-06T13:44Z, containing #227/#228/#229/#230/#231/#232/#233 only —
verified via `gh release view v0.8.1`). The guest-WLAN defect that PR fixes is
described in the PR itself as one that "would have disabled a production
5 GHz radio" on tri-band boxes (4060/7690); that fix is in source but **not
yet in any released archive**. DIST-002/DIST-006 above describe the v0.7.0/
v0.8.0 release trust chain, not v0.8.1, and no release trust-chain row yet
exists for a build containing #234. This is a real, evidence-backed gap, not a
speculative one — it is left unresolved here because cutting or verifying a
release is outside Phase 1 register-hygiene scope; see the report accompanying
this audit.

PR #234's "manual verification against the FRITZ!Box 4060" (`wlan radios`,
`wlan guest status`, `--guest-index 3`, `mesh`, `log --json`,
`calls --type missed --limit 20`) was real-device, read-only, and ad hoc: it
was not run through `scripts/live_smoke.py` and produced no sanitized JSON
evidence file comparable to `live-smoke-20260905.json`. The regression tests
listed against CAP-001/CAP-003 above are what make those rows CI-executable
per the Rules below; the ad hoc hardware run is corroborating evidence from
the PR description only and is not itself claimed as a PASS-qualifying
artifact. A future live-smoke run that re-exercises the fixed guest-WLAN/mesh/
call paths against real hardware, gated the same way as LIVE-001/LIVE-002,
would close that gap.

## Rules

- A row moves to **PASS** only when its Rust test, strict harness, or release
  validation is executable in CI.
- Byte comparison is mandatory for protocol frames, version/help/error output,
  generated artifacts, and persisted files unless this table records a reason.
- Randomness, clocks, locale, timezone, HOME, and network endpoints must be
  controlled. No unexplained normalization is allowed.
- Live fixtures must be sanitized and must never contain passwords, SIDs, MACs,
  public IPs, phone numbers, or other personal data.
