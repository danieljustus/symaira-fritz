# Rust release cutover

This repository uses one release publisher and one archive contract. The old
GoReleaser configuration is removed; `.github/workflows/release.yml` builds and
publishes the complete matrix itself. This avoids two publishers racing over
`checksums.txt`, release assets, or the Homebrew tap.

## Tooling decision

The release-tooling reconnaissance was recorded before implementation:

- [cargo-dist / dist](https://github.com/axodotdev/cargo-dist) 0.32.0 is active
  and supports native application packaging, GitHub releases, and CI
  generation. The custom packager remains because its deterministic archive,
  signing, SBOM, readback and Homebrew contracts are already verified.
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
GitHub publisher. Reconsider `dist` only if it preserves the exact six legacy
filenames, runs signing/notarization before archive creation, emits
SBOMs/checksums, and updates Homebrew without a second publisher.

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

Each archive contains the Rust `symfritz`, `LICENSE`, and `README.md`; Windows
adds `.exe` to the binary name. The
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

## Release security boundary

Release execution is tag-only: both stable and prerelease channels require a
strict SemVer `v*` tag push. The GitHub `release` environment uses a custom
deployment policy that admits only `v*` tag refs, so signing and tap credentials
are unavailable to arbitrary branches. Homebrew Git authentication uses the
GitHub CLI credential helper rather than a token-bearing URL or process
argument. After publication, every downloaded public asset is compared
byte-for-byte with the corresponding pre-upload file before the checksum,
manifest, SBOM, and downstream Formula gates can pass.

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

Current releases and Homebrew installations contain only the Rust binary. If a
regression requires implementation-level rollback, download the immutable
v0.7.0 archive and invoke its bundled `symfritz-go`. Keep the same config and
pins and report the defect; do not delete or rewrite `config.toml` or
`pins.json` as a rollback step.

The real-router smoke/replay interface is `scripts/live_smoke.py`. It writes
only exit status and timing to its report; it never captures command output or
credentials. The sanitized live run is recorded in
`live-smoke-20260905.json`; no router identifiers or command output were
persisted.

## Value gate

The completed cutover benchmark measured binary bytes, startup p95, a
representative `services --output json` command against a loopback fake box,
and max RSS. Values from a 50-run/10-warmup macOS arm64 run were: Rust 7,283,184 bytes
vs Go 8,155,458 (10.7% smaller), Rust max RSS 7,503,872 vs Go 12,566,528
bytes (40.3% lower), startup p95 5.835500 ms vs 7.218958 ms, and fake-box
command p95 7.067625 ms vs 10.459709 ms. The measured gate passed because RSS
improved by more than 20% and command p95 did not regress. The exact report is
`value-gate-20260905.json`. These historical values are local evidence, not a
promise for other hardware.

Values must come from
that run; no numbers are inferred or copied from a debug build.

## Gate status

- DIST executable snapshot: **PASS** only after `release_snapshot.py` builds
  the Rust binary, packages the host archive, and validates version/config
  behavior.
- DIST release trust chain: **PASS** for v0.7.0. Six signed migration
  archives, six CycloneDX SBOMs, the manifest, and checksums were downloaded
  and verified; the remote Homebrew Formula installed both `symfritz` and
  `symfritz-go`, which each reported version 0.7.0.
- LIVE router smoke: **PASS** for the sanitized read-only Go↔Rust run recorded
  in `live-smoke-20260905.json`; no command output or router identifiers were
  persisted.
