# macverify design notes

## Guarantees

- Read-only. No collector writes, moves, deletes, prunes, installs, links or upgrades anything. Remediation commands are strings that are rendered, never executed.
- No elevation. `sudo`, `su`, `doas`, `sudoedit`, `security` and `systemsetup` are refused by the command runner itself, so no code path can invoke them by accident. Anything that would need root is reported as `requires_privileges` with the command that was deliberately not run.
- Offline. No collector performs a network request. Where a capability is only meaningful online (`npm outdated`, `softwareupdate -l`) the field is reported as `unavailable` with the reason, and the manual command is printed instead.
- No secret values. The secrets collector reports path, line number, variable name, detector and severity. Any incidental capture is masked to the first four characters followed by a fixed-length mask, so neither the value nor its length is disclosed.

## Command execution

Every external binary call goes through `shell.run(cmd, timeout)`, which returns
`{cmd, ok, stdout, stderr, rc, skipped_reason}`. A missing binary, a non-zero exit
or a timeout produces a `skipped_reason` rather than an exception. Collectors turn
that into `{"status": "unavailable", "reason": ...}`.

`runner.run_all` executes collectors in a thread pool. A collector that raises is
recorded as `{"status": "error", "reason": ...}` and does not affect the others. A
collector that exceeds the global timeout is recorded as `unavailable`.

## Severity rules

Severity is assigned by rule, not by judgement. A finding takes the highest
severity whose rule it satisfies.

### critical

1. A protection that is designed to be on is off: SIP disabled, FileVault off, Gatekeeper assessments disabled.
2. A credential value is present in a file that is neither a keychain nor a secrets manager, matched by a provider-specific detector (AWS, GitHub, Slack, Anthropic, OpenAI, Google, Stripe, npm, Hugging Face), a private key block, or credentials embedded in a URL.
3. An SSH private key is unusable-by-policy or trivially copyable: DSA algorithm, or file mode granting group or other any access.
4. A directory on `PATH` is world-writable, or `PATH` contains an empty element, both of which allow local command hijacking.
5. A socket bound to `0.0.0.0` or `::` on a port belonging to a known remote-access or datastore service.
6. A volume with less than 5 percent free space.

### warning

1. A setting weakens a boundary without removing it: application firewall disabled, guest account enabled, a remote access service explicitly enabled.
2. A socket bound to all interfaces on any other port.
3. Credential-shaped material identified by variable name rather than by a provider signature, or a credential file readable beyond its owner.
4. An SSH key below current strength guidance (RSA under 3072 bits), or a private key with no passphrase.
5. `~/.ssh` with a mode other than 0700.
6. A state that makes the toolchain behave differently from what is configured: a system binary shadowing a version-managed one, more than one Node manager holding installed runtimes, missing Xcode Command Line Tools, the audit running under Rosetta, one package installed by two managers, an alias defined differently in two profiles, a profile sourcing a file that no longer exists.
7. Resource pressure with a user-visible effect: memory pressure at or above 85 percent, swap above 4 GB, an active thermal or power limit, a volume below 10 percent free, more than 20 GB of reclaimable caches, unused container volumes.
8. An orphaned launchd job whose target binary no longer exists.
9. A disabled Homebrew formula still installed.
10. Claude Code: a duplicate skill, agent or command name across scopes; an MCP server that duplicates a native capability; hooks that fire on every occurrence of their event; a session-startup context above 12000 estimated tokens.
11. A privacy grant in the high-risk set (Full Disk Access, Accessibility, Screen Recording, Input Monitoring, synthetic events).

### info

Everything else that is worth recording but implies no defect: outdated packages,
deprecated formulae, unlinked kegs, duplicate or dead `PATH` entries, stopped
containers, dangling images, local snapshots, battery capacity below 80 percent,
uptime over 30 days, custom `/etc/hosts` entries, an enabled system proxy,
long-lived SSH keys, expired GPG keys, unreachable permission rules, vague skill
descriptions, and memory files that duplicate a skill.

## Context cost model for Claude Code

The distinction that matters is what is paid for on every request versus what is
paid for only when used.

**Always loaded** (counted in the session-startup total):

- `CLAUDE.md` bodies that are in scope for the current directory, in full.
- Skill frontmatter: `name` plus `description`. The body is not loaded until the skill fires.
- Agent `name` plus `description`, which appear in the agent list.
- Command name plus `description`, which appear in the command list.

**Loaded on demand** (measured but excluded from the startup total):

- Skill bodies and their bundled reference files.
- Command bodies and agent bodies.
- `CLAUDE.md` files that exist but are out of scope.

**Not measurable offline**: an enabled MCP server injects its tool schemas into
every request, but the schemas only exist once the server is running. Because
this audit never starts a server, those entries are reported with a null
always-loaded figure and listed under `context_budget.unmeasurable` rather than
being guessed at.

Token counts are an estimate of bytes divided by four, applied uniformly so that
figures are comparable with each other.

## Host compatibility

`compat.preflight()` runs before any collector and decides three things: whether
this host can be audited at all, what will be short, and why. It is the reason a
report on an unfamiliar Mac reads as incomplete rather than wrong.

- **Refusal.** A non-Darwin platform or a Python below 3.8 stops the run with a
  reason on stderr and a non-zero exit, rather than producing a report full of
  `unavailable`.
- **Warnings.** macOS older than 11 or newer than the release the rules were
  verified against, an interpreter translated by Rosetta, or a run as root. Each
  is printed and recorded in `compatibility.warnings`.
- **Capability notes.** Per-domain statements of what this particular Mac can be
  asked: no Homebrew means the package checks are skipped rather than failed; a
  standard account cannot read the system TCC database; Apple silicon puts the
  boot policy behind `bputil`, which the runner refuses.

Version-dependent facts live in `compat` rather than in the collector that needs
them, so there is one place to change when Apple moves something:

- `xprotect_info_plist()` resolves the XProtect bundle at the Catalina-and-later
  path or the legacy `/System/Library` path.
- `gatekeeper_reenable_command()` returns the Settings path instead of
  `spctl --master-enable` on macOS 15 and later, where that verb was withdrawn.

The privacy collector enumerates every `.app` bundle in the standard locations
rather than probing a fixed list of applications, so it works on a Mac whose
tools nobody anticipated. The curated list survives only as a
`commonly_privileged` annotation.

## Quick fixes

`quickfix.py` classifies the `suggested_action` string each finding already
carries. It executes nothing; it decides only what running the string would do.

A compound action is split on `&&`, `||`, `;` and `|`, and takes the highest
tier across its segments. A trailing two-space `# comment` is separated from the
command and kept as a note. An action of the form `<prose> (or: <command>)`
yields both.

| Tier | Meaning |
| --- | --- |
| `inspect` | Read-only. Changes nothing; shows what a fix would act on. |
| `apply` | Changes state, reversible by the ordinary means. |
| `careful` | Deletes data, needs elevation, or is not trivially undone. |
| `manual` | No command. A Settings pane or a decision. |

The tier comes from a table keyed by binary, with subcommand overrides where one
binary spans tiers (`brew doctor` against `brew uninstall`, `launchctl print`
against `launchctl bootout`, `crontab -l` against `crontab -r`). An unrecognised
binary is treated as `apply` rather than assumed harmless; anything containing
`sudo` or a destructive verb is promoted to `careful` regardless of the table.

Identical commands are merged so the same paste is never offered twice, keeping
the highest tier, the most severe severity, and every finding id that produced
it. The plan is written to `quick_fixes` in the dataset, rendered as a tab in the
HTML report, printed by `--quick-fixes`, and reproduced in `remediation.md`.

## Stated scope

`scope.py` holds the one thing this tool must not leave implicit: it reads
configuration, never file contents, so a clean report is not a clean machine. The
text enumerates what is read, what cannot be seen, and which anti-malware tools
cover the difference. It is rendered in the HTML overview, in the Quick fixes
tab, in `remediation.md` and in the README, in English and Spanish, from that
single source.

## Determinism

Reports are byte-identical between runs apart from timestamps and genuinely
changed system state. Every list is sorted by a stable key, collector durations
are excluded from the dataset, and finding identifiers are derived from a SHA-1
of the domain, title and a stable evidence key rather than from run order.
