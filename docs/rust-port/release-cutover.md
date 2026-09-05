# Rust release cutover

This repository uses one release publisher and one archive contract. The old
GoReleaser configuration is removed; `.github/workflows/release.yml` builds and
publishes the complete matrix itself. This avoids two publishers racing over
`checksums.txt`, release assets, or the Homebrew tap.

## Tooling decision

The release-tooling reconnaissance was recorded before implementation:

- [cargo-dist / dist](https://github.com/axodotdev/cargo-dist) 0.32.0 is active
  and supports native application packaging, GitHub releases, and CI
  generation. It does not model this repository's required dual-binary archive
  (Rust primary plus Go rollback) and would require a second publisher or
  post-processing step.
- [cross](https://github.com/cross-rs/cross) 0.2.5 is useful for containerized
  cross compilation, but it cannot certify the native macOS signing and
  notarization path and is unnecessary on the native runner matrix.
- [cargo-zigbuild](https://crates.io/crates/cargo-zigbuild) 0.23.3 is a
  maintained cross-linker option, but native runners plus target toolchains are
  a smaller release surface for the current dependency set.
- [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) 0.7.5
  embeds dependency metadata and remains a useful future hardening option; it
  does not produce the required archive/release/tap flow.
- [Syft](https://github.com/anchore/syft) 1.51.1 is used for per-archive
  CycloneDX SBOMs in the publishing job.

**Decision:** use the repository's custom, deterministic packager and a single
GitHub publisher. Reconsider `dist` only if it can emit both binaries in each
archive, preserve the exact six legacy filenames, run signing/notarization
before archive creation, emit SBOMs/checksums, and update Homebrew without a
second publisher.

## Artifact contract

Every prerelease and stable release contains these six archives:

```text
symaira-fritz_VERSION_darwin_amd64.tar.gz
symaira-fritz_VERSION_darwin_arm64.tar.gz
symaira-fritz_VERSION_linux_amd64.tar.gz
symaira-fritz_VERSION_linux_arm64.tar.gz
symaira-fritz_VERSION_windows_amd64.zip
symaira-fritz_VERSION_windows_arm64.zip
```

Each archive contains `symfritz` (Rust primary), `symfritz-go` (Go fallback),
`LICENSE`, and `README.md`; Windows adds `.exe` to the two binary names. The
release also contains `checksums.txt`, `release-manifest.json`, and one Syft
CycloneDX JSON SBOM per archive. `scripts/release_manifest.py` validates names,
targets, hashes, and archive members; `scripts/test_release_manifest.py` is its
deterministic snapshot suite.

## Signing and notarization

The macOS matrix imports the existing `CERTIFICATE_P12`,
`CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD`, `NOTARY_API_KEY`,
`NOTARY_API_KEY_ID`, and `NOTARY_API_ISSUER` secret names. It calls
`scripts/sign-and-notarize.sh` for both binaries before packaging. In Actions,
missing credentials, invalid API-key material, signing failure, notarization
status other than `Accepted`, or failed verification stops the release. Local
snapshots intentionally skip signing when credentials are unavailable; they do
not claim a trusted artifact.

## Config and pin compatibility

Rust and Go are tested by `scripts/release_snapshot.py` with the same release
version and isolated homes. `config init --force` must produce identical bytes
and mode `0600` before a snapshot is accepted. Both implementations continue to
read the existing TOML path:

```text
~/.config/symfritz/config.toml
```

The TLS TOFU pin file remains compatible and is not migrated or reset during
cutover:

```text
~/.config/symfritz/pins.json
```

Its format is `{ "pins": { "host": "base64-sha256-spki" } }`. A corrupt store
must remain fail-closed; use `symfritz auth trust --reset HOST` only when the
operator has intentionally verified the box certificate.

## Rollback and lifecycle

1. **Prerelease:** install the archive and invoke `symfritz version --json`.
   If parity, live smoke, or the value gate is not proven, invoke the bundled
   `symfritz-go` explicitly. Prereleases do not update Homebrew.
2. **First stable Rust release:** Homebrew's `symfritz` points to the Rust
   binary and also installs `symfritz-go`. Keep both binaries and this rollback
   procedure for the full stable release window.
3. **Rollback:** replace the primary executable with `symfritz-go` (or invoke
   it by that name), keep the same config and pins, and report the parity
   defect. Do not delete or rewrite `config.toml` or `pins.json` as a rollback
   step.
4. **Go removal:** only after one stable Rust release has operated without an
   unexplained parity defect, a separate reviewed change may remove Go source,
   the fallback archive member, and the Homebrew fallback.

The real-router smoke/replay interface is `scripts/live_smoke.py`. It writes
only exit status and timing to its report; it never captures command output or
credentials. Live evidence remains **PENDING** until the parent runs the
sanitized smoke against an actual router.

## Value gate

Run `scripts/benchmark_release.py` with release-built binaries. It measures
binary bytes, startup p95, a representative `services --output json` command
against a loopback fake box serving the committed discovery fixture, and max
RSS. The JSON report passes only when size or RSS improves by at least 20% and
fake-box command p95 does not regress by more than 10%. Values from a 30-run/5-warmup macOS arm64 run were: Rust 7,210,160 bytes
vs Go 7,686,114 (6.2% smaller), Rust max RSS 7,503,872 vs Go 12,009,472
bytes (37.5% lower), startup p95 5.821583 ms vs 6.549541 ms, and fake-box
command p95 6.664458 ms vs 14.912542 ms. The measured gate passed because RSS
improved by more than 20% and command p95 did not regress. Re-run this report
for each release candidate; these values are local evidence, not a promise for
other hardware.

Values must come from
that run; no numbers are inferred or copied from a debug build.

## Gate status

- DIST executable snapshot: **PASS** only after `release_snapshot.py` builds
  both binaries, packages the host archive, validates contents, and confirms
  version/config compatibility.
- DIST release trust chain: **PENDING** until a tag workflow verifies signed,
  notarized, SBOM-bearing public assets and Homebrew read-back.
- LIVE router smoke/replay: **PENDING** until parent evidence.
