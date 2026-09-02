# Brand assets

Source of truth for macverify's marks.

Palette: ink `#0F1012`, accent `#E3A62F`, icon tile `#FAFAF9`, social ground
`#FFFFFF`.

The mark is a checkmark drawn as a grid of rounded squares, with the final
stroke in amber. It ships as PNG on a self-contained light tile, so it needs no
light and dark pair — the tile carries its own background and sits correctly on
any page. The wordmark is the name set as type and ships as vector, in a light
and a dark variant to follow the reader's theme.

| File | Size | Use |
|---|---|---|
| `wordmark-light.svg` / `wordmark-dark.svg` | vector | Name set as type. Used at the top of the root `README.md`. `-light` carries dark ink for light backgrounds; `-dark` is inverted |
| `icon-256.png` | 256×256 | Mark on its own, docs and slides |
| `icon-512.png` | 512×512 | Mark at display size. Also the file to upload as the GitHub account avatar |
| `icon-1024.png` | 1024×1024 | Mark at full size, for resizing down |
| `favicon-16.png` / `favicon-32.png` / `favicon-48.png` / `favicon-64.png` | 16–64 | Favicons |
| `apple-touch-icon-180.png` | 180×180 | iOS home screen |
| `android-chrome-192.png` | 192×192 | Android home screen |
| `social-preview.png` | 1280×640 | GitHub social preview. Upload via **Settings → General → Social preview**; it is not read from the repository |

Referencing the wordmark in Markdown so it follows the reader's theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/wordmark-dark.svg">
  <img alt="macverify" src=".github/brand/wordmark-light.svg" width="340">
</picture>
```

The mark has no vector source in this repository. The earlier mark — five
rounded bars, a small chart rather than a checkmark — was vector, and its
`icon-*.svg`, `logo-*.svg` and `avatar-*.svg` files were removed when the mark
was replaced rather than left behind showing a retired identity. If a scalable
version of the current mark is needed, add the SVG here and this table should
list it as the source the PNGs are exported from.

These assets are part of the repository, not the Python package:
`pyproject.toml` declares `packages = ["macverify", "macverify.collectors"]`,
so nothing here is included in a wheel or an installed copy. The HTML report
embeds no brand asset at all, which is why it stays self-contained and offline.
