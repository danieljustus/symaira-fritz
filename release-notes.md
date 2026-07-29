## What's Changed

### Features
- #82 Pin the FRITZ!Box certificate (TOFU) so `use_tls` no longer requires disabling verification — closes #77
- #82 Add unauthenticated IGD fallback for WAN rates and link capacity — closes #78
- #82 Classify TR-064 faults by numeric UPnP error code instead of English substring match — closes #79
- #71 Integrate versionkit and add `--json` flag to `version` command

### Docs
- #83 Generate CLI command reference from Cobra tree (docs/cli.md)
- #84 Test SCPD discovery against a real FRITZ!Box capture

### Dependencies
- #72 Bump goreleaser/goreleaser-action to 7.2.3
- #73 Bump go-dependencies (2 updates)
- #74 Bump actions/setup-go to 7.0.0
- #75 Bump actions/checkout to 7.0.1
- #76 Bump symaira-corekit to 0.6.0

**Full Changelog**: https://github.com/danieljustus/symaira-fritz/compare/v0.3.2...v0.4.0
