# Example output

What macverify writes, and what the JSON looks like, so you can see the shape
before running anything.

## Files a run produces

| File | What it is |
|---|---|
| `audit_<timestamp>.html` | The report. Self-contained, opens offline in any browser |
| `audit_<timestamp>.json` | The full dataset, including every raw collector payload |
| `remediation.md` | The quick-fix plan as pasteable markdown |
| `ai_assistant_findings.json` | The four AI-assistant domains on their own |

All four land in `~/.macverify/reports` (directory `0700`, files `0600`).

## Top level of `audit_<timestamp>.json`

| Key | Type | Contents |
|---|---|---|
| `schema_version` | int | Currently `1`. Bumped if the shape changes incompatibly |
| `tool` | object | `name`, `version`, `mode` (always `"read-only"`) |
| `generated_at` | string | UTC ISO 8601 |
| `system` | object | `architecture`, `macos`, `homebrew`, `shell`, `hostname`, `python` |
| `compatibility` | object | Whether this Mac is supported, and every capability that could not be checked |
| `scope` | object | `reads`, `cannot_detect`, `recommended_scanners` — what the audit can and cannot see |
| `run` | object | `domains`, `statuses`, timeout, language, extra project roots |
| `summary` | object | `finding_counts`, `total_findings`, `domains_ok`, `domains_degraded` |
| `findings` | array | Every finding, sorted critical → warning → info. See `sample-finding.json` |
| `quick_fixes` | object | `counts`, `commands`, `manual_steps`. See `sample-quick-fix.json` |
| `domains` | object | The raw payload from each collector, keyed by domain name |

Read `compatibility.warnings` and `summary.domains_degraded` before you read the
findings. A domain that did not fully collect is a gap, not a clean result.

## The two shapes worth knowing

- **[`sample-finding.json`](sample-finding.json)** — one entry from `findings`.
  Every finding carries its own evidence, why it matters, and a suggested action.
- **[`sample-quick-fix.json`](sample-quick-fix.json)** — one entry from
  `quick_fixes.commands`. `tier` is `inspect` (read-only), `apply` (reversible)
  or `careful` (deletes data, needs elevation, or is not trivially undone).

Both were copied from a real run and edited only to remove host detail.

## Pulling the useful parts out

The dataset is large. This prints the summary and everything above `info`:

```sh
python3 - <<'PY'
import glob, json, os
path = max(glob.glob(os.path.expanduser("~/.macverify/reports/audit_*.json")), key=os.path.getmtime)
data = json.load(open(path))
print(data["generated_at"], data["summary"]["finding_counts"])
print("degraded:", data["summary"]["domains_degraded"])
for item in data["findings"]:
    if item["severity"] in ("critical", "warning"):
        print("[%s] %s | %s" % (item["severity"], item["domain"], item["title"]))
        print("    fix:", item["suggested_action"])
PY
```

## A note on sharing

There is no sample `audit_*.json` in this directory on purpose. A real one names
your host and account and lists your applications, SSH key paths, privacy grants,
listening ports and the location of anything credential-shaped. Read one before
you send it anywhere.
