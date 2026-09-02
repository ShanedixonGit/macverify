# Changelog

Notable changes to macverify. Dates are ISO 8601.

## [1.1.0] - 2026-09-02

### Added

- macverify now asks where to save before it starts collecting, so the reports
  land somewhere findable instead of only under `~/.macverify/reports`. Press
  Enter for the default, or type a folder; an unusable folder is reported and
  asked again rather than failing after the run. `--out DIR` names the folder
  outright and `--no-prompt` takes the default without asking, and a run whose
  input is not a terminal never asks, so scripts, CI and `SKILL.md` are
  unaffected. A directory macverify creates is still `0700` and every report
  file `0600`, wherever it is written.
- The finished report's path is printed as a `file://` link so it opens straight
  from the terminal.

### Changed

- New mark: a checkmark drawn as a grid of rounded squares with an amber final
  stroke, replacing the five-bar chart mark. Ink `#0F1012` and accent `#E3A62F`
  are unchanged, so the wordmark is untouched and the root `README.md` header
  needed no edit. The mark now ships as PNG across favicon, touch-icon and
  display sizes; `icon-*.svg`, `logo-*.svg` and `avatar-*.svg` were removed
  rather than left behind showing the retired identity, which leaves the current
  mark with no vector source — noted in `.github/brand/README.md`.
- `Development Status` classifier moved from Beta to Production/Stable.

### Removed

- The gitignored `macverify/brand/` working folder, which held a second copy of
  the retired mark inside the importable package directory, and the `.gitignore`
  rule that existed only to hide it.

### Fixed

- A run that could not create its output directory printed the error but exited
  `0`, so a caller saw success and no reports. It now exits `1`.

- The source distribution shipped `tests/` without `tests/__init__.py`, so the
  verification command the README gives — `python3 -m unittest discover -s tests
  -t .` — failed on an sdist with `ImportError: Start directory is not
  importable`. A `MANIFEST.in` now defines the sdist explicitly, and CI extracts
  the built sdist and runs its test suite so the promise holds for anyone who
  checks the tool before trusting it.

## [1.0.1] - 2026-09-01

### Fixed

- **The HTML report rendered as a nav bar above a blank page.** `STYLE` and
  `SCRIPT` in `report_html.py` were plain Python triple-quoted strings, so
  Python consumed the escape sequences meant for the browser. `lines.join("\n")`
  reached the page as a string literal broken across a real newline, which is a
  JavaScript syntax error; because the whole report script is a single IIFE, the
  parse failure took every behaviour with it. Tab counts still rendered (they are
  static markup) but no section was ever unhidden, tabs did not respond to
  clicks, and search, copy buttons and tooltips were all dead. Both blocks are
  now raw string literals.
- Two CSS rules emitted `content: "\x912"` instead of `content: "\2212"`, from
  the same cause — Python read `\221` as an octal escape — so the collapse
  marker on the manual-steps and scope sections was a control character rather
  than a minus sign.
- The verification greps in `README.md` and `SECURITY.md` were documented as
  returning nothing, but matched `tests/test_guarantees.py`, which names the
  forbidden constructs in order to assert their absence. They are now scoped to
  `macverify/`, the shipped package, so each claim holds as written again.

### Added

- Report integrity tests (`tests/test_report_html.py`): the rendered document
  carries no control characters, parses, has a section behind every tab and jump
  target, and its inline script closes every string literal on the line that
  opens it. Five of the ten fail against the source as it shipped in 1.0.0.

## [1.0.0] - 2026-09-01

First public release.

### Added

- Sixteen read-only collectors: `toolchain`, `packages`, `shell_env`,
  `hardware`, `storage`, `services`, `containers`, `network`, `security`,
  `identity`, `secrets`, `permissions`, `claude_code`, `github_copilot`,
  `openai_codex`, `ai_assistants`.
- AI-assistant family covering Claude Code, GitHub Copilot and OpenAI Codex,
  with per-item context cost and a cross-tool collector that flags a project
  carrying more than one of `CLAUDE.md`, `AGENTS.md` and
  `.github/copilot-instructions.md`.
- Self-contained HTML report, full JSON dataset, `remediation.md` quick-fix
  plan, and `ai_assistant_findings.json`.
- Quick-fix tiers: `inspect` (read-only), `apply` (reversible), `careful`
  (destructive, elevated or not trivially undone), plus manual steps.
- `--check` to report what this Mac can be audited for without collecting.
- English and Spanish report labels via `--lang`.
- `SKILL.md`, a self-contained skill that lets Claude Code or Codex run the
  audit and triage the findings.
- Test suite (stdlib `unittest`, no test dependencies) asserting the read-only,
  offline, no-elevation and no-secret-capture guarantees directly against the
  source, plus redaction, degradation, CLI and packaging tests.
- GitHub Actions CI on macOS across Python 3.9-3.13, the runner's stock
  `/usr/bin/python3`, and a job that builds the distributions and checks the
  wheel ships only the package.
- Release workflow publishing to PyPI on a GitHub Release via Trusted
  Publishing, gated on the tag matching the version in `pyproject.toml`.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, and Dependabot for
  GitHub Actions.

### Fixed

- Quick-fix tiering classified cache-clearing commands (`npm cache clean`,
  `yarn cache clean`, `git clean`, `pip cache purge`) as `apply`, the
  "reversible" tier, when they delete data. They are now `careful`. Found by the
  new tiering tests; no collector emitted one of these commands, so no report
  ever mislabelled a fix.
- `SKILL.md` pointed at `macverify/reports/` and at running from the directory
  above a clone, both stale since the default output moved to
  `~/.macverify/reports`.
- `design_notes.md` documented only the Claude Code collector and described the
  context-cost model as Claude-Code-only.
- Test credentials are assembled at runtime so no credential-shaped literal is
  committed; this was tripping GitHub secret scanning and macverify's own
  detector.

### Security

- Read-only by construction. `sudo`, `su`, `doas`, `sudoedit`, `security` and
  `systemsetup` are refused by the command runner before execution.
- No network calls, no telemetry, no third-party dependencies.
- Every subprocess call is list-form with no shell; no `eval`, `exec` or
  `pickle` on external input.
- Secret values are never captured — only file, line, detector label and a
  masked four-character prefix.
- Codex session transcripts are never opened; only file metadata is recorded.
- Reports are written to `~/.macverify/reports` with the directory `0700` and
  every file `0600`.
