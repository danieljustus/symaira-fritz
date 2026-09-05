#!/usr/bin/env python3
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release_manifest as manifest  # noqa: E402
import release_snapshot as snapshot  # noqa: E402


class ReleaseManifestTests(unittest.TestCase):
    def test_target_and_archive_contract(self):
        version = "1.2.3"
        self.assertEqual(
            [manifest.archive_name(version, *target) for target in manifest.TARGETS],
            [
                "symaira-fritz_1.2.3_darwin_amd64.tar.gz",
                "symaira-fritz_1.2.3_darwin_arm64.tar.gz",
                "symaira-fritz_1.2.3_linux_amd64.tar.gz",
                "symaira-fritz_1.2.3_linux_arm64.tar.gz",
                "symaira-fritz_1.2.3_windows_amd64.zip",
                "symaira-fritz_1.2.3_windows_arm64.zip",
            ],
        )
        self.assertEqual(manifest.binary_names("darwin"), ("symfritz", "symfritz-go"))
        self.assertEqual(manifest.binary_names("windows"), ("symfritz.exe", "symfritz-go.exe"))

    def test_package_contents_and_manifest_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "LICENSE").write_bytes(b"license\n")
            (root / "README.md").write_bytes(b"readme\n")
            rust = root / "rust"
            go = root / "go"
            rust.write_bytes(b"rust binary")
            go.write_bytes(b"go binary")
            first = root / "one"
            second = root / "two"
            first.mkdir()
            second.mkdir()
            archive_one = snapshot.package_archive(root, first, "1.2.3", "darwin", "arm64", rust, go)
            archive_two = snapshot.package_archive(root, second, "1.2.3", "darwin", "arm64", rust, go)
            self.assertEqual(hashlib.sha256(archive_one.read_bytes()).digest(), hashlib.sha256(archive_two.read_bytes()).digest())
            self.assertEqual(
                manifest.archive_members(archive_one),
                ["LICENSE", "README.md", "symfritz", "symfritz-go"],
            )
            result = cast(dict[str, object], manifest.build_manifest("1.2.3", first, [("darwin", "arm64")]))
            self.assertEqual(result["binary_names"], {"rust_primary": "symfritz", "go_fallback": "symfritz-go"})
            targets = cast(list[dict[str, object]], result["targets"])
            self.assertEqual(targets[0]["archive"], archive_one.name)

    def test_windows_contents_are_validated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "LICENSE").write_bytes(b"license")
            (root / "README.md").write_bytes(b"readme")
            rust = root / "rust.exe"
            go = root / "go.exe"
            rust.write_bytes(b"rust")
            go.write_bytes(b"go")
            archive = snapshot.package_archive(root, root, "1.2.3", "windows", "arm64", rust, go)
            self.assertEqual(
                manifest.archive_members(archive),
                ["LICENSE", "README.md", "symfritz-go.exe", "symfritz.exe"],
            )


if __name__ == "__main__":
    unittest.main()
