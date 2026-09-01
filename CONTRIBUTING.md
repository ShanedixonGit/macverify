# Contributing

## The guarantees

These are not style preferences. A change that breaks one of them will not be
merged, however useful it is otherwise.

1. **Read-only.** macverify inspects. It never modifies system state. Suggested
   fixes are strings that get printed, never executed.
2. **No elevation.** Nothing may call `sudo` or any blocked binary. If a check
   needs root, report it as `requires_privileges` with the command the user
   could run themselves.
3. **Offline.** No network call, ever. No telemetry, no version check, no
   reputation lookup.
4. **No third-party dependencies.** Standard library only, at install time and
   at runtime. Open an issue before proposing one.
5. **No secret values.** Record where a credential lives — file, line, detector
   label, masked prefix. Never the value.
6. **Python 3.9.** That is what a stock Mac ships. No `tomllib`, no `match`, no
   `X | Y` unions.

## Conventions

- **No code comments.** The codebase has none. Name things so they do not need
  one. Docstrings at module top are used for design notes in a few files.
- Every subprocess call goes through `macverify/shell.py`, list-form, no shell.
- A collector returns a dict with `status` and `findings`. Missing tools return
  `status: "unavailable"` with a specific reason — never an exception, never a
  silent empty result.
- Findings are built with `findings.finding(...)` and need evidence, why it
  matters, and a suggested action. No finding without a factual basis.

## Adding a collector

1. Write `macverify/collectors/<name>.py` exposing `collect(ctx)`.
2. Add the name to `registry.DOMAINS`.
3. Add labels to `i18n.DOMAIN_LABELS` for both `en` and `es`.
4. Optionally add a fact builder to `report_html.FACT_BUILDERS`.

## Before you open a PR

Run the checks from [SECURITY.md](SECURITY.md) — all three greps must return
nothing. Then:

```sh
/usr/bin/python3 -m compileall -q macverify
/usr/bin/python3 -m macverify --check
/usr/bin/python3 -m macverify --verbose
```

`/usr/bin/python3` is the stock 3.9 interpreter; use it rather than a newer
pyenv build, or you will not catch a 3.9 incompatibility.

Test degradation too. Run against a home directory with none of the optional
tools present and confirm every domain reports `unavailable` rather than
erroring:

```sh
mkdir -p /tmp/emptyhome/project
env HOME=/tmp/emptyhome /usr/bin/python3 -m macverify --verbose
```

## Releasing

The version lives in `pyproject.toml`. Bump it there, add a `CHANGELOG.md`
entry, and update the version line at the top of `README.md`.
`macverify --version` reads installed package metadata, so it needs no edit.
