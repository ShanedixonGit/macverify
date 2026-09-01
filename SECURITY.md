# Security

## What macverify does not do

Every claim here was verified against the source, not assumed. The commands that
verify each one are listed under "How to check this yourself".

**No telemetry.** There is no analytics, crash reporting, usage counter or
phone-home of any kind, and no code path that would emit one.

**No network calls.** The source contains no `urllib`, `requests`,
`http.client`, `urlopen`, `httpx`, `ftplib` or `smtplib`. It opens no
connection, resolves no name and sends no packet. The tool is fully functional
with the machine offline.

There is exactly one use of the `socket` module in the codebase:
`socket.gethostname()` in `macverify/sysinfo.py`, which reads the machine's
configured hostname. That is a local `gethostname(3)` syscall — no resolver, no
network traffic. It is named here so that a `grep` for `socket` does not look
like an undisclosed exception.

**No data leaves the machine.** Reports are written to `~/.macverify/reports`
(or `--out`) and nowhere else. Nothing is uploaded, and no report is transmitted
anywhere by this tool. Sharing a report is entirely your action.

**No elevation.** `sudo`, `su`, `doas`, `sudoedit`, `security` and `systemsetup`
are refused by the command runner in `macverify/shell.py` before execution.
Suggested fixes — including any that would need `sudo` — are strings printed for
you to review and run yourself. macverify never runs them.

**No shell.** Every subprocess call goes through a single `subprocess.run()` in
`macverify/shell.py` with a list argument vector and no shell. There is no
`shell=True`, `os.system` or `os.popen` anywhere, and no caller builds a command
by string interpolation, so there is no command-injection surface.

**No dynamic execution.** No `eval`, `exec`, `pickle`, `marshal` or `yaml.load`
is used on command output, file contents or any other external input.

**No modification of system state.** The tool reads. The only files it writes
are its own reports.

**No secret values captured.** The `secrets` domain records where
credential-shaped values live — file, line number, variable name, detector
label — and a masked four-character prefix. The value itself is never written to
the JSON, the HTML, the markdown, or a log. This is tested by running the
collector against planted credentials and asserting that neither the full value
nor a fragment of its body appears in any output.

**No AI session transcripts read.** The `openai_codex` domain records the file
count, byte total and timestamps of `~/.codex/sessions`. It never opens a
transcript.

**No third-party dependencies.** Standard library only, at install time and at
runtime. `pip show macverify` lists an empty `Requires:`.

## Report handling

A generated report is sensitive even though it contains no secret values. An
`audit_*.json` names your host and user, and lists installed applications, SSH
key paths, privacy grants, listening ports, and the file and line of anything
credential-shaped.

macverify therefore creates `~/.macverify/reports` mode `0700` and writes every
report mode `0600`, so reports are readable only by the account that produced
them. `reports/`, `audit_*.json` and `audit_*.html` are gitignored. Read a
report before you send it anywhere.

## How to check this yourself

Every claim above is also an automated test. The suite parses each module with
`ast` and asserts these properties against the code itself, so a change that
breaks one fails CI rather than quietly shipping:

```sh
/usr/bin/python3 -m unittest discover -s tests -t .
```

`tests/test_guarantees.py` covers the imports, calls and constants;
`tests/test_redaction.py` plants credentials in a temporary `$HOME` and asserts
none of them reach any output; `tests/test_degradation.py` runs every collector
against an empty home and asserts none raise.

To check by hand instead, run these in a checkout. Each should produce the
stated result. They are scoped to `macverify/`, the shipped package; the test
suite names these same constructs in order to assert their absence, so an
unscoped grep matches the tests that enforce the claim.

```sh
grep -rn "shell=True\|os\.system\|os\.popen\|check_output" --include='*.py' macverify/
grep -rnE "\b(eval|exec)[[:space:]]*\(|pickle|marshal\.loads|yaml\.load" --include='*.py' macverify/
grep -rn "urllib\|requests\.\|http\.client\|urlopen\|httpx\|ftplib\|smtplib" --include='*.py' macverify/
```

All three return nothing.

```sh
grep -rn "socket\." --include='*.py' macverify/
```

Returns exactly one line: `socket.gethostname()` in `macverify/sysinfo.py`.

```sh
grep -rn "subprocess" --include='*.py' macverify/shell.py
```

Shows the single `subprocess.run()` call, with a list argument vector.

You can also confirm the offline claim empirically by disabling networking and
running `macverify` — the output is identical.

## Reporting a vulnerability

Report privately, not in a public issue. Use GitHub's private vulnerability
reporting on this repository: **Security → Report a vulnerability**.

Please include the macverify version (`macverify --version`), your macOS version,
and the steps to reproduce. If the report involves a generated report file,
review it for host and account details before attaching it, or describe the
relevant fields instead of attaching the file.

This is a personal project with no paid support and no guaranteed response time. Reports are handled on a best-effort basis.