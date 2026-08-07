## What's Changed

### Fixes
- #92 Return an error instead of calling `os.Exit` on `detect` verification failure, so `symfritz detect --json` emits the standard structured JSON error contract

### Tests
- #99 Raise command-layer coverage from 33.8% to 84.2% with httptest-based command tests — closes #98

**Full Changelog**: https://github.com/danieljustus/symaira-fritz/compare/v0.4.1...v0.4.2
