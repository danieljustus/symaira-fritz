#!/usr/bin/env python3
"""Exercise the actual pinned-oracle extractor, including its older-Python path."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oracle_runner", ROOT / "scripts/run-cli-differential.py")
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OracleArchiveTests(unittest.TestCase):
    def extract(self, member, version):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as bundle:
            payload = b"oracle"
            member.size = len(payload) if member.isfile() else 0
            bundle.addfile(member, io.BytesIO(payload) if member.isfile() else None)
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "out"
            destination.mkdir()
            result = subprocess.CompletedProcess([], 0, stdout=archive.getvalue())
            with patch.object(runner.subprocess, "run", return_value=result), patch.object(runner.sys, "version_info", version):
                runner.extract_oracle(ROOT, destination)
            return (destination / "source.go").read_bytes()

    def test_regular_file_on_both_extraction_paths(self):
        for version in ((3, 11), (3, 12)):
            with self.subTest(version=version):
                self.assertEqual(self.extract(tarfile.TarInfo("source.go"), version), b"oracle")

    def test_rejects_unsafe_members_on_both_paths(self):
        for version in ((3, 11), (3, 12)):
            for kind in ("traversal", "symlink", "hardlink", "fifo", "setuid", "setgid"):
                with self.subTest(version=version, kind=kind):
                    member = tarfile.TarInfo("../escape" if kind == "traversal" else "source.go")
                    if kind in ("symlink", "hardlink", "fifo"):
                        member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                        member.linkname = "../escape"
                    if kind == "setuid":
                        member.mode = 0o4755
                    if kind == "setgid":
                        member.mode = 0o2755
                    with self.assertRaises(RuntimeError):
                        self.extract(member, version)


if __name__ == "__main__":
    unittest.main()
