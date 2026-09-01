## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Guarantees

macverify is read-only, offline, never elevates, and has no dependencies. Confirm
none of that changed:

- [ ] No network call added (no `urllib`, `requests`, `http.client`, sockets)
- [ ] No `sudo` and no new entry removed from `shell.BLOCKED_BINARIES`
- [ ] Nothing on the machine is modified; suggested fixes are printed, never run
- [ ] No third-party runtime dependency added
- [ ] No secret value captured — location and masked prefix only
- [ ] No code comments added (project convention)

## Checks

```sh
/usr/bin/python3 -m compileall -q macverify
/usr/bin/python3 -m unittest discover -s tests -t .
```

- [ ] Both pass on `/usr/bin/python3` (the stock 3.9 interpreter, not a newer pyenv build)
- [ ] Any new collector degrades to `unavailable` with a reason when its tool is absent
- [ ] Any new finding carries evidence, why it matters, and a suggested action
