---
name: macverify-review
description: Use when the user wants their Mac audited, reviewed or cleaned up - "audit my machine", "check my Mac", "why is my disk full", "is my setup secure", "review my Claude Code config", "what should I fix on this laptop" - or when a macverify report already exists and they want it read, triaged and turned into fixes. Runs the read-only macverify collector, then evaluates the findings and proposes specific fixes in the order they should be applied.
---

# macverify review

Run the read-only macOS audit, read the result, and turn it into a short ordered
list of fixes the user can actually act on. The audit changes nothing; you
propose, the user decides.

## What macverify is

A read-only inventory of a Mac. It never writes, never elevates (`sudo`, `su`,
`security` and `systemsetup` are refused by its own command runner), and never
opens a network connection. It reads sixteen domains: `toolchain`, `packages`,
`shell_env`, `hardware`, `storage`, `services`, `containers`, `network`,
`security`, `identity`, `secrets`, `permissions`, and the AI-assistant family
`claude_code`, `github_copilot`, `openai_codex`, `ai_assistants`.

It reads configuration, not file contents. **It cannot detect malware** - no
signatures, no hashes, no reputation lookups. Say so when you summarise, and
recommend a real scan alongside it (see "Always say this" below).

## Step 1 - locate or produce a report

If `macverify` is on `PATH`, run it from anywhere. If the user has a clone
instead, run `python3 -m macverify` from inside it.

```sh
macverify --quick-fixes
```

Reports land in `~/.macverify/reports/`, owner-only. A run takes 30-60 seconds.

If a recent report already exists (`ls -t ~/.macverify/reports/audit_*.json | head -1`,
check `generated_at`), read that instead of re-running. Re-run when the user has
applied fixes since, or the report is more than a few days old.

If it refuses to run, `macverify --check` prints why - wrong platform,
Python too old, or a capability this Mac does not have.

## Step 2 - read the dataset, not the HTML

Load the newest `~/.macverify/reports/audit_*.json`. Never paste the whole file into context;
it is megabytes. Pull only these keys:

- `summary.finding_counts` - critical / warning / info tally.
- `findings[]` - each has `id`, `domain`, `severity`, `title`, `evidence`,
  `why_it_matters`, `suggested_action`, `reversible`.
- `quick_fixes.commands[]` - deduplicated pasteable commands, each with
  `tier` (`inspect` | `apply` | `careful`), `needs_elevation`, `reversible`,
  `titles` (what it addresses).
- `quick_fixes.manual_steps[]` - findings that need a decision or a GUI change.
- `compatibility.warnings` and `compatibility.capability_notes` - what this
  particular Mac could not be asked, so you do not read a gap as a clean result.
- `run.statuses` - a domain that is not `ok` was not fully collected. An
  assistant that is not installed reports `unavailable`, which is an absence,
  not a failure.

A compact digest, safe to run as one command:

```sh
python3 - <<'PY'
import glob, json, os
path = max(glob.glob(os.path.expanduser("~/.macverify/reports/audit_*.json")), key=os.path.getmtime)
d = json.load(open(path))
print(path, d["generated_at"], d["summary"]["finding_counts"])
print("degraded:", d["summary"]["domains_degraded"])
for w in d.get("compatibility", {}).get("warnings", []):
    print("compat:", w)
for f in d["findings"]:
    if f["severity"] in ("critical", "warning"):
        print("[%s] %s | %s | fix: %s" % (f["severity"], f["domain"], f["title"], f["suggested_action"]))
q = d.get("quick_fixes", {})
print("commands:", q.get("counts"))
for c in q.get("commands", []):
    print(" ", c["tier"], "|", c["command"])
PY
```

## Step 3 - triage

Rank by real consequence on *this* machine, not by the severity label alone:

1. **Anything that removes a protection.** SIP off, FileVault off, Gatekeeper
   assessments off, a world-writable or empty `PATH` element, a credential in a
   plain file, a private key readable by group or other. These come first, every
   time.
2. **Anything reachable from the network.** A socket on `0.0.0.0`, the
   application firewall off, an enabled sharing service. Check the port and the
   process before you call it a problem - a dev server on 3000 is not the same
   finding as `sshd`.
3. **Anything that will stop work soon.** A volume under 10% free, memory
   pressure, an orphaned launchd job filling the log.
4. **Correctness of the toolchain.** A system binary shadowing a version-managed
   one, two package managers owning the same command, a profile sourcing a file
   that no longer exists.
5. **Cost and tidiness.** Reclaimable caches, outdated packages, Claude Code
   startup context, duplicate skill and agent names.

Discard noise honestly. Fifteen "PATH entry does not exist" findings are one
sentence about the user's shell profile, not fifteen items.

## Step 4 - propose fixes

Present at most 5-8 items. For each: what is wrong, why it matters here, and the
exact command or setting. Use the `quick_fixes` tiers as the running order:

- `inspect` - read-only. Suggest these first; they cost nothing and often change
  the diagnosis.
- `apply` - reversible state change. Safe to recommend directly.
- `careful` - deletes data, needs elevation, or is not trivially undone. Never
  run one of these without saying exactly what it will remove and getting an
  explicit yes.
- `manual_steps` - a GUI change or a decision. Give the precise pane path.

Rules while doing this:

- Do not run any fix the user has not agreed to. `careful` items are always a
  question, never an action.
- Never run `sudo` on the user's behalf. Print the command and let them run it.
- Group commands that belong together into one block the user can paste once.
- Prefer the narrow fix over the broad one: `brew upgrade git` over `brew upgrade`
  unless they asked for everything.
- For `secrets` findings, never echo the value. Give the file and line, and move
  the value to the keychain or a secrets manager.

## Step 5 - verify

After the user applies fixes, re-run and diff the counts:

```sh
macverify --json-only
```

Compare `summary.finding_counts` and confirm the specific finding `id`s are gone.
A fix that did not change the count did not work.

## Step 6 - the AI assistant synthesis

When the user asks about their AI tooling specifically, write
`~/.macverify/reports/ai_assistant_audit.md` from the
`ai_assistant_findings.json` beside it. That
file carries all four assistant domains: `claude_code`, `github_copilot`,
`openai_codex` and the cross-tool `ai_assistants`.

Reason across all three tools, not one of them. Use this structure:

- **A. Essential** - what must stay, for each tool. Name the item, its scope, its
  always-loaded cost, and what it is the only source of.
- **B. Useful** - what earns its context cost. Say what it earns.
- **C. Redundant** - the same capability configured twice. This is where
  cross-tool duplication lands: `analysis.instruction_file_overlaps` in the
  `ai_assistants` domain gives you the directory, the pairwise vocabulary
  overlap and lines quoted from both files. An overlap at 100% between
  `CLAUDE.md` and `AGENTS.md` is one instruction set maintained twice.
- **D. Missing** - what the data shows is absent. A tool installed with no
  instruction file, a permissive Codex `approval_policy` or `sandbox_mode`, an
  empty instructions file.
- **E. Recommended architecture** - which file should own which rule across the
  three tools, given what is actually installed.

Rules, unchanged from the rest of this skill:

- State only what the data supports. Mark anything beyond it `[inferred]`.
- No claim about a file without a quoted or paraphrased line from that file.
- `context_cost` of `n/a` means the tool has no equivalent loading concept.
  Report it as `n/a`; never substitute a guess.
- Change no configuration. Propose, and let the user decide.

## Always say this

Close every summary with the limit, in your own words but not softer than this:

> macverify reads configuration; it cannot detect malware. It has no signatures,
> computes no hashes, and makes no network request, so it cannot see adware and
> browser hijackers (Adload, Bundlore, Genieo, Pirrit), infostealers targeting
> the keychain and browser cookies (Atomic Stealer/AMOS, Poseidon, Banshee),
> cryptominers, keyloggers, stalkerware or RATs. A backdoor in a signed binary
> that starts at login looks exactly like a printer helper from here.
>
> Run a scan as well: **Malwarebytes for Mac** (free on-demand, best coverage of
> the adware families above), **KnockKnock** from Objective-See (enumerates
> everything persistent and checks it against VirusTotal), **LuLu** from
> Objective-See (outbound firewall, catches what a listening-socket audit
> cannot), or **ClamAV** (`brew install clamav`) if a scriptable offline engine
> is preferred. Scan first, then re-run macverify - a scanner that removes an
> adware LaunchAgent changes these findings.

Also report anything in `compatibility.warnings` or any domain in
`summary.domains_degraded`, so an incomplete audit is never read as a clean one.
