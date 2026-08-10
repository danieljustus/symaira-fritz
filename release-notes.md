## What's Changed

### Fixes
- #104 Return an explicit error for non-200 session-login responses instead of attempting to parse an error page as XML.
- Update `symaira-corekit` to v0.9.1, including its configuration-loader concurrency fix and MCP protocol improvements.

### Tests
- #104 Add protocol-level coverage for legacy MD5 and PBKDF2 session login, ready SIDs, rejected credentials, rate limiting, malformed XML, transport failures, and non-200 responses.

### Documentation
- #103 Align the contributor Go prerequisite with the version required by the module and CI.

**Full Changelog**: https://github.com/danieljustus/symaira-fritz/compare/v0.4.2...v0.4.3
