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
| CLI-006 | Command tree | every command in `docs/cli.md` | `make docs` / `--help` | names, aliases, flags, defaults, inherited flags | snapshot suite | all | bytes | FROZEN |
| CLI-007 | Argument validation | missing/excess args per command | Go binary | exact exit, stdout, stderr | negative CLI suite | all | bytes | PENDING |
| CLI-008 | Structured output | text/JSON/YAML for every command | fake-box scenarios | snake_case, omission, ordering where stable | command parity suite | all | parsed/bytes per row | PENDING |
| CLI-009 | Error taxonomy | auth/config/not-found/transport/timeout/cancel | Go binary | exit codes, kind, message, hint, output stream | negative command suite | all | bytes | FROZEN |
| CLI-010 | Signals | SIGINT/SIGTERM during request/watch/MCP | Go binary | cancellation and interrupted exit code | process tests | macOS/Linux | semantic | PENDING |
| CFG-001 | Defaults | no file/env | Go loader | host, TLS and 15 s timeout defaults | config tests | all | semantic | FROZEN |
| CFG-002 | Precedence | TOML plus `SYMFRITZ_*` | Go loader | env overrides file overrides defaults | fixture table | all | semantic | FROZEN |
| CFG-003 | Init file | isolated HOME, first/second/force writes | `config init` | exact bytes, path, mode, overwrite behavior | filesystem parity | all | bytes + metadata | PENDING |
| SEC-001 | Credential order | env/ref/keychain/plaintext combinations | Go resolver | env → symvault → Keychain → config; configured backend failure stops | backend-stub suite | all/macOS | semantic | FROZEN |
| SEC-002 | Secret redaction | backend/network failures | Go binary | no password/SID in logs or errors | leak assertions | all | semantic | PENDING |
| TLS-001 | SPKI TOFU | test certificates + isolated pins | Go `PinStore` | exact SHA-256 SPKI base64 and pin JSON | certificate fixtures | all | bytes | FROZEN |
| TLS-002 | Pin persistence | missing/corrupt/read-only/concurrent store | Go `PinStore` | modes, refusal to overwrite corrupt data, reset recovery | filesystem suite | all | bytes + metadata | FROZEN |
| TLS-003 | HTTP fallback | refused TLS vs certificate/auth failures | Go fake transport | fallback only when endpoint does not answer; one warning; port rewrite | transport suite | all | HTTP trace + bytes | FROZEN |
| AUTH-001 | Legacy login | AVM `1234567z` / `äbc` vector | Go session test | `1234567z-9e224a41eeefa284df7bb0f26c2913e2` | vector test | all | bytes | FROZEN |
| AUTH-002 | Modern login | PBKDF2 challenge matrix | Go session code | two-round SHA-256 response; malformed inputs rejected | vector/property tests | all | bytes | PENDING |
| AUTH-003 | SID lifecycle | ready SID, challenge, invalid SID, block time, expiry | Go fake box | request sequence, caching, retry, errors | HTTP trace suite | all | semantic + bytes | FROZEN |
| DIG-001 | Digest parser | quoted commas, qop lists, malformed challenge | Go digest tests | parse/select `auth` exactly | property/vector tests | all | semantic | FROZEN |
| DIG-002 | Digest header | fixed nonce/cnonce/count vector | Go helper with deterministic randomness seam | RFC-compatible MD5 bytes and 8-digit nc | golden vectors | all | bytes | PENDING |
| SOAP-001 | Request | service/action/argument fixtures | Go `buildSOAPRequest` | exact XML envelope and escaping | golden/property tests | all | bytes | FROZEN |
| SOAP-002 | Response/fault | namespaced, empty, malformed, oversized XML | Go parser | flat out-args and error classification | parser suite + fuzz | all | semantic | FROZEN |
| DISC-001 | Discovery | committed `tr64desc.xml` plus adversarial URLs | Go discovery/safe-url tests | service resolution, SSRF/path policy, caching | fixture + property tests | all | semantic | FROZEN |
| CAP-001 | Typed capabilities | status/hosts/diagnose/mesh/WLAN/WOL | Go fake-box handlers | exact requests, models and outputs | per-command slices | all | semantic/bytes | PENDING |
| CAP-002 | AHA capabilities | device/switch/temp fixtures | Go AHA tests | SID query behavior, XML types, retries | per-command slices | all | semantic/bytes | FROZEN |
| CAP-003 | Phone/traffic/DSL/log | Go HTTP fixtures | Go package tests | parsing/filtering/reduced datasets | per-command slices | all | semantic/bytes | FROZEN |
| SCRAPE-001 | `data.lua` | success/error/oversized JSON fixtures | Go scraper tests | best-effort, bounded, version-fragile behavior | fixture suite | all | semantic | FROZEN |
| MCP-001 | Initialize | raw framed requests | `symfritz mcp` | server name/version/capabilities | raw-frame harness | all | bytes | PENDING |
| MCP-002 | Tool surface | `tools/list` | Go MCP server | 9 names, schemas, descriptions, annotations | schema fixture | all | parsed + selected bytes | FROZEN |
| MCP-003 | Tool calls | success/validation/backend failures | Go fake box | JSON-RPC IDs, content text strings, `isError` behavior | raw-frame suite | all | bytes | FROZEN |
| MCP-004 | Stdio hygiene | initialize/list/call/cancel/malformed frames | Go MCP server | only protocol frames on stdout; logs on stderr | process suite | all | bytes | PENDING |
| DIST-001 | Artifacts | release snapshot | GoReleaser | same binary/archive names and target set | release manifest diff | all | metadata | FROZEN |
| DIST-002 | Trust chain | checksums/sign/notarize/SBOM/Homebrew | release workflow | verifiable artifacts and formula smoke test | prerelease gate | all | cryptographic/semantic | PENDING |
| DOC-001 | Docs/completions | generated CLI docs + four shells | Go/Cobra generation | no command/help drift | generated artifact diff | all | bytes | FROZEN |
| LIVE-001 | Real box | sanitized recordings for supported FRITZ!OS | installed Go binary | request/response and side-effect parity | replay + approved live smoke | macOS/Linux | semantic | PENDING |

## Rules

- A row moves to **PASS** only when the Rust test and differential comparison are
  executable in CI.
- Byte comparison is mandatory for protocol frames, version/help/error output,
  generated artifacts, and persisted files unless this table records a reason.
- Randomness, clocks, locale, timezone, HOME, and network endpoints must be
  controlled. No unexplained normalization is allowed.
- Live fixtures must be sanitized and must never contain passwords, SIDs, MACs,
  public IPs, phone numbers, or other personal data.
