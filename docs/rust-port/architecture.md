# Rust port architecture

## Constraints

- Preserve CLI, JSON/YAML, MCP, filesystem, network, and release contracts.
- Keep the Go implementation runnable until post-cutover cleanup.
- Use safe Rust by default (`#![deny(unsafe_code)]`).
- Keep MCP stdout exclusively for JSON-RPC frames; diagnostics go to stderr.
- Keep synchronous code synchronous unless an actual boundary requires async.
- Do not mirror Go package layout, interfaces, goroutines, or error wrappers.

## Intended crate boundaries

Create crates only when their vertical slice starts; empty architecture crates
would be decorative scaffolding.

| Crate | Responsibility | First slice |
|---|---|---|
| `symfritz-cli` | Argument parsing, output formatting, exit mapping | `version` (implemented) |
| `symfritz-core` | Domain types, config/secret policy, error taxonomy, pure parsers | session/digest and config/credential fixtures (implemented) |
| `symfritz-tr064` | SOAP, digest auth, discovery, bounded HTTP/TLS transport policy | raw `call`, private-origin DNS pinning, TOFU and strict fallback (implemented) |
| `symfritz-aha` | SID login, AHA endpoints, data.lua isolation | `home list` |
| `symfritz-mcp` | MCP schemas, handlers, stdio transport | `tools/list` |

The final `symfritz` entrypoint composes adapters but owns no protocol logic.
Serde field names must preserve existing snake_case wire keys rather than Rust
field spelling.

## Dependency direction

```text
symfritz-cli  -> core + tr064 + aha + mcp
symfritz-mcp  -> core + capability interfaces
symfritz-tr064 -> core
symfritz-aha   -> core
symfritz-core  -> no adapter crates
```

No crate may depend on the Go implementation. Differential tests launch both
binaries as black boxes.

## High-risk seams

1. FRITZ!OS legacy MD5 uses UTF-16LE and has an official non-ASCII vector.
2. Modern login uses two PBKDF2-HMAC-SHA256 rounds with hex-decoded salts.
3. TR-064 requires HTTP Digest MD5 with qop selection, random cnonce, and an
   incrementing nonce count.
4. TLS trust is TOFU via persisted SPKI pins; certificate failures must never
   trigger plaintext fallback.
5. TLS endpoint transport failure may trigger exactly one warning and HTTP
   fallback with port rewriting.
6. SOAP/XML parsing is namespace-agnostic and accepts empty action responses.
7. `data.lua` remains explicitly best-effort and FRITZ!OS-version-fragile.
8. MCP tool content is an indented JSON string, not a raw object.
9. Config and pin-store paths, modes, overwrite behavior, and precedence are
   observable contracts.

## Cutover and rollback

During prerelease, publish the Rust candidate without replacing `symfritz`.
Once parity is green, produce the normal Rust `symfritz` artifact and retain the
last Go artifact as `symfritz-go` for one stable release. The fallback must be
explicit; the Rust process must not silently dispatch arbitrary failures to Go.
Rollback restores the previous Homebrew formula/release asset and preserves the
same config and pin files.
