# Security Policy

## Reporting a vulnerability

Please report security issues privately to **justus@premium-bnb.de** rather than
opening a public issue. You will get an acknowledgement within a few days.

## Scope & handling notes

`symfritz` holds FRITZ!Box credentials and can change router and smart-home state.

- **Credentials**: prefer the `SYMFRITZ_PASSWORD` environment variable or a
  secret manager (symvault). A password in `~/.config/symfritz/config.toml` is
  supported for convenience but is the least secure option; the file is written
  with `0600`.
- **Least privilege**: use a dedicated FRITZ!Box user limited to the permissions
  you need, not the admin account.
- **TLS**: `insecure_tls` disables certificate verification to accommodate the
  box's self-signed certificate. It only relaxes verification for the configured
  host; do not enable it against untrusted networks.
- **No telemetry**: the tool talks only to the configured box (and, for
  `version --check`, the GitHub releases API).
