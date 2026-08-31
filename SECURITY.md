# Security Policy

## Reporting a vulnerability

Please report security issues privately to **justus@premium-bnb.de** rather than
opening a public issue. You will get an acknowledgement within a few days.

## Scope & handling notes

`symfritz` holds FRITZ!Box credentials and can change router and smart-home state.

- **Credentials**: store the password with `symfritz auth login`, which keeps it
  in the macOS Keychain or symvault and verifies it before saving. The
  resolution order is `SYMFRITZ_PASSWORD` env → symvault (`password_ref`) →
  Keychain (`keychain = true`) → plaintext `password` in config. The plaintext
  option is the least secure and only for convenience; the config file is
  written `0600`. symvault and the Keychain are accessed via their CLIs, and
  secrets are passed to them over stdin (not argv) where possible.
- **Least privilege**: use a dedicated FRITZ!Box user limited to the permissions
  you need, not the admin account.
- **TLS**: `use_tls = true` is enabled by default, securing TR-064 (port 49443)
  and web sessions (port 443) using Trust-On-First-Use (TOFU) SHA-256 SPKI
  public key pinning stored in `~/.config/symfritz/pins.json`. An automatic
  fallback to HTTP with a warning is performed if TLS endpoints (443/49443) do
  not answer, preserving compatibility with boxes where TR-064 TLS is disabled.
  `insecure_tls = true` can be set to disable certificate pinning for legacy
  setups, and `use_tls = false` disables TLS entirely.
- **No telemetry**: the tool talks only to the configured box (and, for
  `version --check`, the GitHub releases API).
