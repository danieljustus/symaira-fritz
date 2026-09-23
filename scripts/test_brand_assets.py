#!/usr/bin/env python3
"""Verify the vendored approved A3 brand package without building the CLI."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "branding" / "a3"
PUBLIC_KIT = ROOT / "assets" / "branding" / "public-kit"
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

    public = json.loads((PUBLIC_KIT / "manifest.json").read_text(encoding="utf-8"))
    assert public["schema_version"] == 1 and public["product"] == "symaira-router"
    dimensions = {
        "brand/foreground-mark": (1024, 1024),
        "brand/foreground-mark-monochrome": (1024, 1024),
        "social/github-social-en": (1280, 640),
        "social/open-graph-de": (1200, 630),
        "social/square-de": (1080, 1080),
        "social/portrait-de": (1080, 1350),
        "social/story-de": (1080, 1920),
        "release/release-card-en": (1600, 900),
        "readme/readme-hero-de": (1600, 900),
        "readme/terminal-demo": (1600, 900),
    }
    expected_files = {
        name + ext
        for name in dimensions
        for ext in ((".svg",) if name.startswith("brand/") else (".svg", ".png"))
    }
    assert set(public["files"]) == expected_files
    for relative, contract in public["files"].items():
        path = PUBLIC_KIT / relative
        assert path.is_file(), f"missing public asset: {relative}"
        assert sha256(path) == contract["sha256"], f"hash mismatch: {relative}"
        expected = dimensions[relative.rsplit(".", 1)[0]]
        assert tuple(contract["dimensions"]) == expected
        if path.suffix == ".png":
            assert png_info(path)[0] == expected
            continue
        source = path.read_text(encoding="utf-8")
        assert "Symaira Fritz" not in source, f"third-party name used as a wordmark: {relative}"
        assert "github.com/danieljustus/symaira-fritz" not in source, f"old slug in public artwork: {relative}"
        for encoded in re.findall(r"data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)", source):
            embedded = base64.b64decode(encoded, validate=True).decode("utf-8")
            assert "Symaira Fritz" not in embedded, f"embedded mark uses third-party name: {relative}"
        root = ET.fromstring(source)
        assert root.tag == "{http://www.w3.org/2000/svg}svg"
        assert (root.get("width"), root.get("height")) == tuple(map(str, expected))
        assert not re.search(r"(?:192\.168\.|10\.\d+\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.|/Users/|javascript:)", source, re.I), relative
        for element in root.iter():
            assert element.tag.rsplit("}", 1)[-1] != "script", relative
            assert all(not key.lower().startswith("on") for key in element.attrib), relative
            assert all(
                not value.startswith(("http:", "https:", "file:"))
                for key, value in element.attrib.items()
                if key.rsplit("}", 1)[-1] == "href"
            ), relative
    assert "Synthetic illustration" in (PUBLIC_KIT / "readme/terminal-demo.svg").read_text()

    print(f"verified approved A3 brand assets for {manifest['product']}")
    print(f"verified {len(expected_files)} public SVG/PNG assets for {public['product']}")


if __name__ == "__main__":
    main()
