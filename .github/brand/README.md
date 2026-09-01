# Brand assets

Source of truth for macverify's marks. SVG is authoritative; the PNGs are
exports for the places that will not take vector.

Palette: ink `#0F1012`, paper `#EDEDE6`, accent `#E3A62F`.

Every mark ships in a light and a dark variant. `-light` carries dark ink
(`#0F1012`) and is for light backgrounds; `-dark` carries light ink (`#EDEDE6`)
and is for dark backgrounds. The amber accent is the same in both. Pair them
with `prefers-color-scheme` rather than picking one.

| File | Size | Use |
|---|---|---|
| `wordmark-light.svg` / `wordmark-dark.svg` | vector | Name set as type. Used at the top of the root `README.md` |
| `logo-light.svg` / `logo-dark.svg` | vector | Mark plus wordmark lockup. Docs headers, slides |
| `icon-light.svg` / `icon-dark.svg` | vector | Mark on its own, no text. Small sizes, inline use |
| `avatar-light.svg` / `avatar-dark.svg` | vector | Square, padded for a circular crop |
| `avatar-light.png` / `avatar-dark.png` | 512×512 | GitHub organisation or user avatar |
| `favicon-32.png` | 32×32 | Favicon |
| `favicon-64.png` | 64×64 | Favicon, retina |
| `social-preview.png` | 1280×640 | GitHub social preview. Upload via **Settings → General → Social preview**; it is not read from the repository |

Referencing a mark in Markdown so it follows the reader's theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/wordmark-dark.svg">
  <img alt="macverify" src=".github/brand/wordmark-light.svg" width="340">
</picture>
```

This is the published subset that the README and GitHub need. The working
folder at `macverify/brand/` is gitignored.

These assets are part of the repository, not the Python package: `pyproject.toml`
declares `packages = ["macverify", "macverify.collectors"]`, so nothing here is
included in a wheel or an installed copy.
