# Changelog

Notable changes to macverify. Dates are ISO 8601.

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
