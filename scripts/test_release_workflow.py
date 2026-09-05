#!/usr/bin/env python3
"""Deterministic policy checks for the release workflow."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
WORKFLOW_TEXT = WORKFLOW.read_text(encoding="utf-8")


class ReleaseWorkflowPolicyTests(unittest.TestCase):
    def test_linux_arm64_uses_a_cross_compiler_and_ring_environment(self) -> None:
        self.assertIn("gcc-aarch64-linux-gnu", WORKFLOW_TEXT)
        self.assertIn("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc", WORKFLOW_TEXT)
        self.assertIn("CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc", WORKFLOW_TEXT)
        self.assertIn("if: matrix.os == 'linux' && matrix.arch == 'arm64'", WORKFLOW_TEXT)

    def test_artifact_actions_are_immutable_and_never_empty(self) -> None:
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4", WORKFLOW_TEXT)
        self.assertIn("actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4", WORKFLOW_TEXT)
        self.assertIn("if-no-files-found: error", WORKFLOW_TEXT)
        self.assertIn("if: matrix.os != 'windows'", WORKFLOW_TEXT)
        self.assertNotIn("if-no-files-found: ignore", WORKFLOW_TEXT)

    def test_release_identity_is_semver_and_sha_bound(self) -> None:
        patterns = re.findall(r"semver_re='([^']+)'", WORKFLOW_TEXT)
        self.assertEqual(len(patterns), 2)
        for pattern in patterns:
            for version in ("0.0.0", "1.2.3-rc.1", "1.2.3+build.7"):
                self.assertRegex(version, pattern)
            for version in ("01.2.3", "1.2", "1.2.3-", "1.2.3+"):
                self.assertIsNone(re.fullmatch(pattern, version))
        self.assertIn("git rev-parse \"${GITHUB_REF}^{commit}\"", WORKFLOW_TEXT)
        self.assertIn('test "$ref_sha" = "$GITHUB_SHA"', WORKFLOW_TEXT)
        self.assertIn('create_args+=(--target "$GITHUB_SHA")', WORKFLOW_TEXT)
        self.assertIn('gh release upload "$TAG" "${assets[@]}" --clobber', WORKFLOW_TEXT)
        self.assertIn('git ls-remote origin "refs/tags/$TAG^{}"', WORKFLOW_TEXT)
        self.assertIn("isPrerelease", WORKFLOW_TEXT)

    def test_release_channel_matches_semver_prerelease_state(self) -> None:
        self.assertEqual(
            WORKFLOW_TEXT.count(
                'if [[ "$version" == *-* ]]; then channel=prerelease; else channel=stable; fi'
            ),
            2,
        )
        self.assertEqual(
            WORKFLOW_TEXT.count(
                '[[ "$version" == *-* && "$channel" != prerelease ]]'
            ),
            2,
        )

    def test_syft_install_is_archive_and_checksum_verified(self) -> None:
        self.assertIn("syft_archive=\"syft_${syft_version}_linux_amd64.tar.gz\"", WORKFLOW_TEXT)
        self.assertIn("syft_${syft_version}_checksums.txt", WORKFLOW_TEXT)
        self.assertIn("sha256sum -c", WORKFLOW_TEXT)
        self.assertNotIn("raw.githubusercontent.com/anchore/syft/v1.51.1/install.sh |", WORKFLOW_TEXT)

    def test_release_readback_covers_assets_hashes_and_sboms(self) -> None:
        self.assertIn("gh release view \"$TAG\" --json assets,isPrerelease,tagName", WORKFLOW_TEXT)
        self.assertIn("gh release download \"$TAG\"", WORKFLOW_TEXT)
        self.assertIn("release-manifest.json", WORKFLOW_TEXT)
        self.assertIn(".sbom.cdx.json", WORKFLOW_TEXT)
        self.assertIn("sha256sum -c checksums.txt", WORKFLOW_TEXT)

    def test_homebrew_readback_and_smoke_are_explicit(self) -> None:
        renderer = (ROOT / "scripts" / "render_homebrew_formula.py").read_text()
        self.assertIn("verify_homebrew_formula.py", WORKFLOW_TEXT)
        self.assertIn("brew style", WORKFLOW_TEXT)
        self.assertIn("brew install --formula", WORKFLOW_TEXT)
        self.assertIn("cmp -- \"$formula\" \"$remote_formula\"", WORKFLOW_TEXT)
        self.assertIn('symfritz version', WORKFLOW_TEXT)
        self.assertIn('symfritz-go version', WORKFLOW_TEXT)
        self.assertIn('version "{version}"', renderer)
        self.assertIn("# typed: strict", renderer)
        self.assertNotIn("# typed: false", renderer)

    def test_macos_signing_remains_fail_closed(self) -> None:
        self.assertIn("Refusing an unsigned or unnotarized release.", WORKFLOW_TEXT)
        self.assertIn("Notarization failed", (ROOT / "scripts" / "sign-and-notarize.sh").read_text())
        self.assertIn("codesign --verify --strict", (ROOT / "scripts" / "sign-and-notarize.sh").read_text())


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "scripts"))
    unittest.main()
