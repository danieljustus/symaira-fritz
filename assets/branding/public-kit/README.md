# Symaira Router public asset kit

Editable, local-first communications assets for the CLI/MCP product. This adapts the approved A3 brand handoff in `../a3/` without changing that handoff or implying a native app, cloud dashboard, or Apple app icon. The public artwork uses the independent **Symaira Router** wordmark. FRITZ!Box appears only as a factual compatibility description, separate from the product name; this is an unofficial project, not affiliated with FRITZ! GmbH (formerly AVM). The existing repository slug and `symfritz` executable are compatibility contracts, not a claim of trademark clearance.

| Use | Editable source | PNG export | Dimensions |
|---|---|---|---|
| GitHub social preview | `social/github-social-en.svg` | `social/github-social-en.png` | 1280×640 |
| Open Graph / link preview | `social/open-graph-de.svg` | `social/open-graph-de.png` | 1200×630 |
| Square post | `social/square-de.svg` | `social/square-de.png` | 1080×1080 |
| Portrait post | `social/portrait-de.svg` | `social/portrait-de.png` | 1080×1350 |
| Story cover | `social/story-de.svg` | `social/story-de.png` | 1080×1920 |
| Release card | `release/release-card-en.svg` | `release/release-card-en.png` | 1600×900 |
| README hero | `readme/readme-hero-de.svg` | `readme/readme-hero-de.png` | 1600×900 |
| Synthetic terminal illustration | `readme/terminal-demo.svg` | `readme/terminal-demo.png` | 1600×900 |

`brand/foreground-mark.svg` is the transparent editable router/radio mark; `brand/foreground-mark-monochrome.svg` is its single-color variant. Keep at least 10% of the 1024-unit canvas as clear space around the artwork. Use the mark at **64 px or larger**; below that, its status dots and radio strokes may not be legible. Do not use either mark as a claim that the product has a GUI. The SVGs are editable sources; distribute adjacent PNGs when SVG/foreignObject text support is uncertain.

## Provenance and QA

- Sources: the local OpenDesign `symaira-fritz` Brand & Assets handoff (version 0.23.0), adapted to the independent public wordmark. Each derivative source/export is bound by SHA-256 and dimensions in `manifest.json`. The monochrome variant is derived from the foreground mark by using its light foreground color. The terminal illustration's command and output were corrected to a **clearly synthetic text-format** example, then re-rendered from its SVG. The 1x PNG exports were rendered from the paired SVGs with headless Chromium; the SVGs remain the editable source.
- The pre-existing `assets/branding/product-logo.png`, approved A3 signet, and `docs/assets/social-preview.png` remain untouched. Repository assets are canonical after this reviewed import; the OpenDesign project is not a runtime dependency.
- SVGs are transparent for the foreground marks and contain no external image URLs or scripts. Social/release/README exports use synthetic copy and the public GitHub profile URL; the terminal illustration says explicitly that it contains no router data.
- Visual inspection at full size and thumbnail: headline and router mark stay readable; secondary copy/URL is not promised at tiny preview sizes. The terminal graphic was checked after regeneration for text and clipping. `python3 scripts/test_brand_assets.py` validates every manifest hash, SVG/PNG dimensions, and a basic private-network/secret-pattern guard in CI.

Before publishing a release-specific card, check its copy against the actual release and rerender if details change. No storefront screenshots are fabricated for this CLI/MCP-only product.
