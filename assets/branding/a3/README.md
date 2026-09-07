# Approved A3 branding handoff

This directory vendors the approved Symaira A3 (Verzahnt) brand package for Symaira Fritz.

- Role: brand-only asset handoff for a CLI/MCP FRITZ!Box controller.
- No GUI target, application bundle, or CLI behavior is introduced.
- The existing Symaira Fritz wordmark and product identity remain unchanged.
- Source handoff: `symaira-icons-release/symaira-fritz/`.
- The `.icon` package is the editable Icon Composer master; the PNG is an opaque branding export for documentation and release communication.
- The package is not currently consumed by a native app bundle or automatically embedded in CLI releases.

The committed manifest records the approved router signet, source handoff, and SHA-256 values for every vendored file. The small asset test validates those records in normal CI.
