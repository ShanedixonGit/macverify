# Changelog

Notable changes to macverify. Dates are ISO 8601.

## Unreleased

### Added

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
