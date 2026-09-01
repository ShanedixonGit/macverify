<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/wordmark-dark.svg">
  <img alt="macverify" src=".github/brand/wordmark-light.svg" width="340">
</picture>

[![CI](https://github.com/ShanedixonGit/macverify/actions/workflows/ci.yml/badge.svg)](https://github.com/ShanedixonGit/macverify/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/macverify.svg)](https://pypi.org/project/macverify/) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **macverify 1.0.1** — macOS 11+, Python 3.9+, zero dependencies, fully offline.

A read-only, offline inventory of a Mac: what is installed, what runs at login,
what listens on the network, which protections are on, where credential-shaped
values sit in plain files, and how your AI assistants (Claude Code, GitHub
Copilot, OpenAI Codex) are configured and what they cost to load. It writes an
HTML report, a JSON dataset and a list of remediation commands, then stops.

## What this is NOT

**macverify is not antivirus. It is not malware detection. It is not real-time
protection. It does not scan for known threats.** It has no signature database,
computes no file hashes, consults no reputation service, and makes no network
request, so nothing it sees is ever compared against a threat feed.

It takes a point-in-time, read-only inventory of your toolchain, config hygiene
and AI-assistant setup, and flags things worth reviewing yourself. A launchd job
that exists, is signed and starts at login looks the same from here whether it
is a printer helper or a backdoor.

Run a real scanner alongside it: [Malwarebytes](https://www.malwarebytes.com/mac),
[KnockKnock](https://objective-see.org/products/knockknock.html) or
[LuLu](https://objective-see.org/products/lulu.html). Scan first — removing
adware changes what this report is built from.

## Installation

```sh
pipx install macverify
```

Or with pip, if you do not use pipx:

```sh
pip install --user macverify
```

No build step, no dependencies. To install nothing at all, clone and run in
place:

```sh
git clone https://github.com/ShanedixonGit/macverify.git
cd macverify
python3 -m macverify
```

### Verify it before you run it

This tool reads your machine, so do not take its word for it. From a clone,
these must all return nothing:

```sh
grep -rn "shell=True\|os\.system\|os\.popen" --include='*.py' macverify/
grep -rnE "\b(eval|exec)[[:space:]]*\(|pickle" --include='*.py' macverify/
grep -rn "urllib\|requests\.\|http\.client\|urlopen\|httpx" --include='*.py' macverify/
```

No shell execution, no dynamic evaluation, no network client. The same claims
are enforced as tests, which CI re-runs on every push:

```sh
/usr/bin/python3 -m compileall -q macverify
/usr/bin/python3 -m unittest discover -s tests -t .
```

[SECURITY.md](SECURITY.md) lists each claim and how it is checked.

## Usage

```sh
macverify --check     # what this Mac can be audited for, then exit
macverify             # the full run
```

`--check` collects nothing, and is the safe way to see what a run would cover.
A full run takes 30-60 seconds, writing to `~/.macverify/reports` (`0700`):

```
  -h, --help      show this help message and exit
  --version       print the installed version and exit
  --only DOMAIN   run only this domain (repeatable)
  --skip DOMAIN   skip this domain (repeatable)
  --json-only     write the JSON dataset only
  --html-only     write the HTML report only
  --out DIR       output directory (default: ~/.macverify/reports)
  --timeout S     per-command timeout in seconds (default: 8)
  --lang {en,es}  report label language (default: en)
  --project PATH  extra project root to inspect for AI assistant config
                  (repeatable)
  --verbose       print per-domain progress to stderr
  --list-domains  list domain names and exit
  --quick-fixes   print the quick-fix plan to stdout as well as writing the
                  reports
  --check         report what this machine can be audited for, then exit
                  without collecting
```

```sh
macverify --quick-fixes
macverify --only security --only network
```

A run writes `audit_<timestamp>.html` (self-contained), `audit_<timestamp>.json`
(full dataset), `remediation.md` and `ai_assistant_findings.json`. See
[examples/](examples/) for the JSON shape and how to pull findings out of it.

## What it reads, and what it never does

Sixteen domains: `toolchain`, `packages`, `shell_env`, `hardware`, `storage`,
`services`, `containers`, `network`, `security`, `identity`, `secrets`,
`permissions`, `claude_code`, `github_copilot`, `openai_codex`, `ai_assistants`.
Missing tools are reported as unavailable, never as an error.

It never makes a network request. It never calls `sudo` — `sudo`, `su`, `doas`,
`sudoedit`, `security` and `systemsetup` are refused by its command runner, so
no code path can elevate. It never modifies system state; fixes are printed,
never executed. It never captures a secret value: the secrets domain records the
file, line, detector and a masked prefix, never the value. It never reads AI
session transcripts, only their file metadata.

Reports are sensitive: an `audit_*.json` names your host, user, applications,
SSH key paths, privacy grants and anything credential-shaped. Read one before
you send it anywhere.

## Let an AI assistant triage the report

[`SKILL.md`](SKILL.md) is a self-contained skill that runs the audit, reads the
dataset and returns a short ranked list of fixes rather than eighty raw
findings. For Claude Code, copy it to `~/.claude/skills/macverify-review/`; for
Codex, append it to your `AGENTS.md`. It never runs a destructive command
without asking, and never runs `sudo` on your behalf.

## Requirements

macOS 11+ and Python 3.9+; every Mac since macOS 12.3 ships a suitable
`python3`. No third-party packages, at install time or runtime.

## License

MIT. See [LICENSE](LICENSE). Also [CONTRIBUTING.md](CONTRIBUTING.md),
[CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md) and
[design_notes.md](design_notes.md).
