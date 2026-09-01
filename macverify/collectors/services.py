import os

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

AGENT_DIRS = (
    ("user_agents", "~/Library/LaunchAgents", "gui"),
    ("system_agents", "/Library/LaunchAgents", "gui"),
    ("system_daemons", "/Library/LaunchDaemons", "system"),
)


def _program(payload):
    program = payload.get("Program")
    arguments = payload.get("ProgramArguments")
    if program:
        return program, list(arguments or [])
    if isinstance(arguments, list) and arguments:
        return arguments[0], list(arguments)
    return None, []


def _loaded_labels(ctx):
    res = shell.run(["launchctl", "list"], timeout=ctx.timeout)
    if not res["ok"]:
        return None, shell.failure_reason(res)
    labels = {}
    for line in res["stdout"].splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        pid, status, label = parts[0].strip(), parts[1].strip(), parts[2].strip()
        labels[label] = {"pid": None if pid == "-" else pid, "last_exit_status": status}
    return labels, None


def _scan(directory, domain, loaded, loaded_reason):
    path = os.path.expanduser(directory)
    if not fsutil.exists(path):
        return {"path": fsutil.tilde(path), "status": "unavailable", "reason": "directory does not exist", "entries": []}
    names = [name for name in fsutil.listdir(path) if name.endswith(".plist")]
    if not names and not os.access(path, os.R_OK):
        return {"path": fsutil.tilde(path), "status": "requires_privileges", "reason": "directory is not readable by this user", "entries": []}
    entries = []
    for name in names:
        full = os.path.join(path, name)
        payload, reason = fsutil.read_plist(full)
        if payload is None:
            entries.append({"file": name, "status": "unavailable", "reason": reason})
            continue
        program, arguments = _program(payload)
        target_exists = fsutil.exists(program) if program else None
        label = payload.get("Label") or os.path.splitext(name)[0]
        state = "unknown"
        detail = None
        if loaded is None:
            state = "unknown"
            detail = loaded_reason
        elif label in loaded:
            state = "loaded"
            detail = loaded[label]
        else:
            state = "not_loaded_in_user_domain" if domain == "gui" else "unknown_requires_privileges"
            if domain == "system":
                detail = "system domain state is only readable by root"
        entries.append({
            "file": name,
            "label": label,
            "program": program,
            "program_arguments": arguments[:12],
            "run_at_load": bool(payload.get("RunAtLoad")),
            "keep_alive": bool(payload.get("KeepAlive")),
            "start_interval": payload.get("StartInterval"),
            "disabled_in_plist": bool(payload.get("Disabled")),
            "loaded_state": state,
            "loaded_detail": detail,
            "target_exists": target_exists,
            "orphaned": target_exists is False,
        })
    return {"path": fsutil.tilde(path), "status": "ok", "count": len(entries), "entries": sorted(entries, key=lambda item: item.get("label") or item.get("file"))}


def _login_items(ctx):
    script = 'tell application "System Events" to get the name of every login item'
    res = shell.run(["osascript", "-e", script], timeout=min(ctx.timeout, 6))
    btm = fsutil.exists(os.path.expanduser("~/Library/Application Support/com.apple.backgroundtaskmanagementagent"))
    if res["ok"]:
        names = [item.strip() for item in res["stdout"].strip().split(",") if item.strip()]
        return {"status": "ok", "source": "System Events", "count": len(names), "items": sorted(names), "background_task_store_present": btm}
    return shell.requires_privileges(
        "reading login items needs an Automation grant for System Events, which this audit will not request",
        {
            "detail": shell.failure_reason(res),
            "background_task_store_present": btm,
            "manual_check": "System Settings > General > Login Items and Extensions",
        },
    )


def _cron(ctx):
    res = shell.run(["crontab", "-l"], timeout=ctx.timeout)
    if res["skipped_reason"]:
        return shell.unavailable(res["skipped_reason"])
    text = res["stdout"].strip()
    if not res["ok"] and "no crontab" in (res["stderr"] or "").lower():
        return {"status": "ok", "entry_count": 0, "entries": [], "note": "no crontab for this user"}
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    entries = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    return {"status": "ok", "entry_count": len(entries), "entries": entries}


def _at_jobs(ctx):
    res = shell.run(["atq"], timeout=ctx.timeout)
    if res["skipped_reason"]:
        return shell.unavailable(res["skipped_reason"])
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    lines = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
    return {"status": "ok", "job_count": len(lines), "jobs": lines}


def collect(ctx=None):
    ctx = default_context(ctx)
    loaded, loaded_reason = _loaded_labels(ctx)
    result = {
        "status": "ok",
        "launchctl_list": {"status": "ok", "label_count": len(loaded)} if loaded is not None else shell.unavailable(loaded_reason),
        "scope_note": "launchctl in a user session reports the gui domain only; system daemon state needs root and is reported as unknown",
    }
    for key, directory, domain in AGENT_DIRS:
        result[key] = _scan(directory, domain, loaded, loaded_reason)
    result["login_items"] = _login_items(ctx)
    result["crontab"] = _cron(ctx)
    result["at_jobs"] = _at_jobs(ctx)

    findings = []
    for key, _, _ in AGENT_DIRS:
        section = result[key]
        if section.get("status") != "ok":
            continue
        for entry in section["entries"]:
            if entry.get("orphaned"):
                findings.append(F.finding(
                    "services",
                    "warning",
                    "Orphaned launchd job: %s" % entry["label"],
                    "%s/%s points at %s, which does not exist" % (section["path"], entry["file"], entry["program"]),
                    "launchd retries the missing binary on every load, filling the system log and leaving a stale definition from software that was removed.",
                    "rm %s/%s   # after confirming the software is genuinely uninstalled" % (section["path"], entry["file"]),
                    False,
                    key="orphan-%s-%s" % (key, entry["file"]),
                ))
            if entry.get("run_at_load") and entry.get("keep_alive") and not entry.get("orphaned"):
                findings.append(F.finding(
                    "services",
                    "info",
                    "Always-running launchd job: %s" % entry["label"],
                    "%s (RunAtLoad and KeepAlive both set)" % entry["program"],
                    "The job starts at login and is restarted whenever it exits, so it consumes memory for the whole session whether used or not.",
                    "launchctl print gui/$(id -u)/%s   # unload with: launchctl bootout gui/$(id -u)/%s" % (entry["label"], entry["label"]),
                    True,
                    key="always-on-%s" % entry["label"],
                ))

    cron = result["crontab"]
    if isinstance(cron, dict) and cron.get("entry_count"):
        findings.append(F.finding(
            "services",
            "info",
            "%d crontab entries are scheduled" % cron["entry_count"],
            "; ".join(cron["entries"])[:400],
            "cron on macOS runs outside launchd, so these jobs are invisible in Login Items and easy to forget about.",
            "crontab -l",
            True,
            key="crontab",
        ))

    result["findings"] = findings
    return result
