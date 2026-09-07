#!/usr/bin/env python3
"""Verify the vendored approved A3 brand package without building the CLI."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "branding" / "a3"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_info(path: Path) -> tuple[tuple[int, int], str]:
    data = path.read_bytes()
    assert data.startswith(PNG_SIGNATURE), f"{path} is not a PNG"
    width, height, bit_depth, color_type = struct.unpack(">IIBB", data[16:26])
    assert bit_depth == 8, f"{path} must use 8-bit channels"
    modes = {2: "RGB", 6: "RGBA"}
    assert color_type in modes, f"{path} has unsupported PNG color type {color_type}"
    return (width, height), modes[color_type]


def main() -> None:
    manifest = json.loads((BRAND / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["product"] == "symaira-fritz"
    assert manifest["design"] == "A3 (Verzahnt)"
    assert manifest["role"] == "brand-only"
    assert manifest["native_app_bundle"] is False
    assert manifest["existing_wordmark_preserved"] is True

    for relative, expected_hash in manifest["files"].items():
        path = BRAND / relative
        assert path.is_file(), f"missing vendored asset: {relative}"
        assert sha256(path) == expected_hash, f"hash mismatch: {relative}"

    icon = json.loads((BRAND / "AppIcon.icon" / "icon.json").read_text(encoding="utf-8"))
    assert {"refractivity", "specular-location"} <= set(icon["features"])
    assert icon["supported-platforms"]["squares"] == "shared"
    assert len(icon["groups"]) == 2
    assert icon["groups"][0]["name"] == manifest["product_signet_group"]
    image_names = {
        layer["image-name"]
        for group in icon["groups"]
        for layer in group["layers"]
        if "image-name" in layer
    }
    assert image_names == {"S.png", "signet.png"}
    assert all((BRAND / "AppIcon.icon" / "Assets" / name).is_file() for name in image_names)

    for name in ("S.png", "signet.png"):
        assert png_info(BRAND / "AppIcon.icon" / "Assets" / name) == ((1024, 1024), "RGBA")

    svg = (BRAND / "source" / "signet.svg").read_text(encoding="utf-8")
    assert "<svg" in svg and "viewBox=" in svg

    export_name, contract = next(iter(manifest["png_contract"].items()))
    export = BRAND / export_name
    assert png_info(export) == (tuple(contract["dimensions"]), contract["color_mode"])
    readme = (BRAND / "README.md").read_text(encoding="utf-8")
    for phrase in ("brand-only", "No GUI target", "not currently consumed", "Source handoff"):
        assert phrase in readme, f"provenance README missing: {phrase}"

    print(f"verified approved A3 brand assets for {manifest['product']}")


if __name__ == "__main__":
    main()
