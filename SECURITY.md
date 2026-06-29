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
- **TLS**: `insecure_tls` disables certificate verification to accommodate the
  box's self-signed certificate. It only relaxes verification for the configured
  host; do not enable it against untrusted networks.
- **No telemetry**: the tool talks only to the configured box (and, for
  `version --check`, the GitHub releases API).
