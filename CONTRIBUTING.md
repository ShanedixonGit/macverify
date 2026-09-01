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

## Tests

The guarantees above are enforced by the test suite, not just by this document.
`tests/test_guarantees.py` parses every module with `ast` and asserts that no
network module is imported, that `subprocess` appears only in `shell.py` and
only as `subprocess.run`, that `shell=True` is never passed, that `socket` is
used solely for `gethostname`, and that no string constant hardcodes a home
directory. `tests/test_redaction.py` plants real-shaped credentials in a
temporary `$HOME` and asserts that neither the value nor a fragment of its body
reaches the JSON, the HTML or the markdown. `tests/test_degradation.py` runs all
sixteen collectors against an empty home and asserts none of them raise.

Stdlib `unittest`, no test dependencies:

```sh
/usr/bin/python3 -m unittest discover -s tests -t .
```

Use `/usr/bin/python3` — the stock 3.9 interpreter — rather than a newer pyenv
build, or you will not catch a 3.9 incompatibility. CI runs the suite on 3.9
through 3.13 and on the runner's own system interpreter.

If you weaken a guarantee, a test will fail. That is the point: fix the change,
not the test.

## Before you open a PR

```sh
/usr/bin/python3 -m compileall -q macverify
/usr/bin/python3 -m unittest discover -s tests -t .
/usr/bin/python3 -m macverify --check
```

Add a test with any new collector: one that it degrades to `unavailable` when
its tool is absent, and one that its findings carry evidence.

## Releasing

The version lives in `pyproject.toml`. Bump it there, add a `CHANGELOG.md`
entry, and update the version line at the top of `README.md`.
`macverify --version` reads installed package metadata, so it needs no edit.

Then tag on `main` and publish a GitHub Release; `.github/workflows/publish.yml`
builds and uploads to PyPI via Trusted Publishing, and refuses to run if the tag
does not match the version in `pyproject.toml`.

```sh
git tag -a v1.2.3 -m "macverify 1.2.3"
git push origin v1.2.3
gh release create v1.2.3 --notes-from-tag
```
