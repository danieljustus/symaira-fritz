# Approved branding handoff

This directory vendors the approved Symaira K1v2 brand package for Symaira Fritz (2026-10-23):
the Symaira S in graphite relief with contour lines plus the router signet in champagne glass.
The directory and PNG keep their historical `a3` names as stable paths.

- Role: brand-only asset handoff for a CLI/MCP FRITZ!Box controller.
- No GUI target, application bundle, or CLI behavior is introduced.
- The existing Symaira Fritz wordmark and product identity remain unchanged.
- Source handoff: `icon-k1v2-20261023` (approved Icon Composer master; previously `symaira-icons-release/symaira-fritz/`).
- The `.icon` package is the editable Icon Composer master; the PNG is an opaque branding export for documentation and release communication.
- The package is not currently consumed by a native app bundle or automatically embedded in CLI releases.

The committed manifest records the approved router signet, source handoff, and SHA-256 values for every vendored file. The small asset test validates those records in normal CI.
