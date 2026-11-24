---
version: alpha
name: Symaira Brand & Assets
description: Shared Symaira visual system for product marks, GitHub previews, documentation graphics, social assets, and future app-icon sources.
colors:
  primary: "#E5C397"
  secondary: "#F8E6CD"
  tertiary: "#D4B285"
  neutral: "#0D0C0A"
  surface: "#171510"
typography:
  display:
    fontFamily: "Roboto Flex Variable, system-ui, -apple-system, sans-serif"
    fontSize: 48px
    fontWeight: 600
    lineHeight: 1.05
  body:
    fontFamily: "Roboto Flex Variable, system-ui, -apple-system, sans-serif"
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.6
rounded:
  control: 10px
  card: 12px
  panel: 16px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
  section: 32px
  spacious: 48px
---

## Overview

This is a **Brand & Assets** workspace for a Symaira CLI/MCP product without its own GUI. It is not an app-shell specification. Use the shared Symaira identity while allowing the product to own a recognizable foreground glyph and a clear product name.

## Colors

Use warm-black `#0D0C0A` and deep warm-black `#070605` as the structural canvas. Champagne primary `#E5C397`, champagne secondary `#F8E6CD`, gold shadow `#C29965`, ice/sand `#EEDCC4` and `#D4B285` provide the restrained brand accents. Primary text is `#F5F4F0`, secondary text `#B5AEA5`, and readable muted text `#837D74`.

Do not introduce Apple blue, generic SaaS purple, or unrelated neon colors. Glows and grids are atmospheric only and never carry meaning alone.

## Typography

Use Roboto Flex Variable for public asset headings, product names, technical labels, and documentation graphics, with system fallbacks. Keep product names legible at thumbnail size. Use the mono face for commands, paths, versions, and structured output when it improves scanning.

## Asset Surfaces

Create GitHub social previews at the target platform's required dimensions, Open Graph/social variants, README hero graphics, terminal/demo compositions, documentation diagrams, release visuals, and product-mark explorations. Keep editable vector/source artwork separate from flattened exports and record provenance for generated or third-party material.

## Product Marks & App Icons

Every named Symaira product may own a recognizable foreground glyph. The complete umbrella Symaira S remains reserved for the umbrella brand; do not put abbreviations or text inside a product glyph. CLI/web/docs assets use the foreground mark without a baked Apple glass container. If the product later receives a native Apple GUI, build a layered `.icon` package with a clear/system Liquid Glass background and the product glyph centered in the foreground, then render every used variant with `ictool`.

## Composition Rules

Keep one clear focal mark, generous safe space, restrained glow, and strong small-size contrast. Product name and command should remain separate from the glyph. Do not turn an asset board into a fake product dashboard. For social previews, show the product's real job and boundary; never imply a GUI that does not exist.

## Accessibility & Export Quality

Use actual contrast pairs, avoid text embedded in raster artwork where live text is possible, and preserve readable labels in exported previews. Check 1:1 thumbnail readability, 1280×640 GitHub/social variants where required, 1200×630 Open Graph variants where required, transparent bounds for marks, and the final file dimensions/alpha channel.

## Do's and Don'ts

### Do

- Reuse the shared Symaira palette and product-mark language.
- Keep CLI/MCP products operator- and asset-oriented.
- Preserve editable SVG/source files beside exports.
- Use synthetic/demo data only.
- Make platform and product boundaries explicit in public graphics.

### Don't

- Do not invent a GUI for Browse or Fritz.
- Do not bake Apple Liquid Glass into CLI/web artwork.
- Do not place secrets, cookies, credentials, or private network data in assets.
- Do not use decorative gradients or glow as the only information carrier.
- Do not revive deleted Symaira products in brand materials.

## Source of Truth

Derived from the shared Symaira UI Foundation in `symaira-appkit`, its Brand README, the current Symaira workspace inventory, and the adjacent `PRODUCT_CONTEXT.md`.