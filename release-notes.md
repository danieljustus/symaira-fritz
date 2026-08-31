## What's Changed

### Features
- #131 Add per-request digest nonces and cache TR-064 challenges
- #132 Add shared client handling, signal cancellation, and traffic watch mode
- #144 Add `symfritz doctor` and global `--output text|json|yaml` formats
- #148 Make TLS with certificate pinning the default with HTTP fallback when TLS is unanswered

### Fixes and performance
- #111 Harden release signing and pin govulncheck
- #130 Redact session identifiers and standardize CLI error handling
- #133 Remove dead router code and cache service discovery
- #134 Parallelize TCP port probes in diagnosis

### Maintenance and documentation
- #135 Update pinned CodeQL actions
- #138 Stop tracking internal working artifacts
- #140 and #142 Update the pinned symaira-corekit dependency
- #141 Restructure the README and clarify command usage
- #143 Clarify one-shot traffic output versus live monitoring

**Full Changelog**: https://github.com/danieljustus/symaira-fritz/compare/v0.4.3...v0.5.0
