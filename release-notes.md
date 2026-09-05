## What's Changed

### Rust migration complete
- Remove the retired Go source, module, generators, and toolchain requirements.
- Ship one Rust `symfritz` binary per archive; the immutable v0.7.0 release
  remains the implementation-level rollback point.
- Update Homebrew to install and verify only the Rust binary.

### Contracts and release safety
- Preserve the language-neutral v0.7 fixtures as permanent Rust regression
  contracts.
- Retain the strict fake-box CLI suite and Rust MCP parser/framing properties
  without requiring a Go compiler.
- Move the release manifest to schema version 2 with a single-binary contract.
- Keep signed native archives, SBOMs, checksums, exact public readback,
  notarization, and downstream Formula smoke verification.

Closes #215.

**Full Changelog**: https://github.com/danieljustus/symaira-fritz/compare/v0.7.0...v0.8.0
