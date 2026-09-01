"""Classify the suggested action on each finding into a reviewable fix plan.

Nothing in this module runs a command. It reads the `suggested_action` string a
finding already carries and decides three things: whether the string is a
command you can paste or a step you have to take by hand, what that command
would change, and whether it needs elevation. The report uses that to separate
fixes you can apply in a second from fixes that need a decision first.
"""

import re

TIERS = ("inspect", "apply", "careful")
TIER_RANK = {"inspect": 0, "apply": 1, "careful": 2}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}

SPLIT_PATTERN = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
COMMENT_PATTERN = re.compile(r"\s{2,}#\s*(.+)$")
ALTERNATIVE_PATTERN = re.compile(r"\(\s*(?:or|o)\s*:\s*(.+?)\s*\)\s*$")
BINARY_PATTERN = re.compile(r"^[a-z_][a-z0-9_.+-]*$")

GUI_MARKERS = ("system settings", "system preferences", "recovery", "startup security utility")

DESTRUCTIVE = ("rm ", "rm -", "prune", "uninstall", "bootout", "unload", "--delete", "delete", " clean", "cleanup", "purge", "erase", "trash", "--force")

DEFAULT_TIERS = {
    "cat": "inspect", "df": "inspect", "du": "inspect", "file": "inspect", "grep": "inspect",
    "head": "inspect", "id": "inspect", "ls": "inspect", "lsof": "inspect", "ps": "inspect",
    "stat": "inspect", "tail": "inspect", "wc": "inspect", "which": "inspect", "whoami": "inspect",
    "printenv": "inspect", "sw_vers": "inspect", "uname": "inspect", "pkgutil": "inspect",
    "defaults": "inspect", "networksetup": "inspect", "fdesetup": "inspect", "dscl": "inspect",
    "system_profiler": "inspect", "diskutil": "inspect", "ioreg": "inspect", "sysctl": "inspect",
    "chmod": "apply", "chflags": "apply", "arch": "apply", "ln": "apply", "touch": "apply",
    "chown": "careful", "rm": "careful", "rmdir": "careful", "mv": "careful",
    "kill": "careful", "killall": "careful",
}

SUBCOMMAND_TIERS = {
    "brew": {
        "doctor": "inspect", "info": "inspect", "list": "inspect", "outdated": "inspect",
        "uses": "inspect", "deps": "inspect", "config": "inspect",
        "upgrade": "apply", "link": "apply", "unlink": "apply", "update": "apply", "install": "apply",
        "uninstall": "careful", "remove": "careful", "cleanup": "careful", "autoremove": "careful",
    },
    "git": {"status": "inspect", "log": "inspect", "remote": "apply", "config": "apply"},
    "docker": {
        "ps": "inspect", "images": "inspect", "info": "inspect",
        "container": "careful", "image": "careful", "volume": "careful", "system": "careful",
    },
    "podman": {
        "ps": "inspect", "images": "inspect", "info": "inspect",
        "container": "careful", "image": "careful", "volume": "careful", "system": "careful",
    },
    "launchctl": {
        "print": "inspect", "list": "inspect", "print-disabled": "inspect", "dumpstate": "inspect",
        "bootout": "careful", "unload": "careful", "disable": "careful", "remove": "careful",
    },
    "crontab": {"-l": "inspect", "-e": "apply", "-r": "careful"},
    "tmutil": {
        "listlocalsnapshots": "inspect", "listbackups": "inspect",
        "deletelocalsnapshots": "careful", "thinlocalsnapshots": "careful", "delete": "careful",
    },
    "softwareupdate": {"-l": "inspect", "--list": "inspect", "-i": "careful", "--install": "careful"},
    "ssh-keygen": {"-l": "inspect", "-y": "inspect", "-p": "apply", "-t": "apply", "-R": "apply"},
    "gpg": {"--list-keys": "inspect", "--list-secret-keys": "inspect", "--edit-key": "apply", "--delete-key": "careful"},
    "pyenv": {"versions": "inspect", "version": "inspect", "which": "inspect", "global": "apply", "install": "apply", "uninstall": "careful"},
    "npm": {"ls": "inspect", "outdated": "inspect", "update": "apply", "install": "apply", "uninstall": "careful"},
    "pnpm": {"list": "inspect", "outdated": "inspect", "update": "apply", "remove": "careful"},
    "yarn": {"list": "inspect", "outdated": "inspect", "upgrade": "apply", "remove": "careful"},
    "pip": {"list": "inspect", "show": "inspect", "install": "apply", "uninstall": "careful"},
    "pip3": {"list": "inspect", "show": "inspect", "install": "apply", "uninstall": "careful"},
    "claude": {"mcp": "apply", "doctor": "inspect"},
    "codex": {"mcp": "apply"},
    "xcode-select": {"-p": "inspect", "--print-path": "inspect", "--install": "apply", "--reset": "careful"},
    "scutil": {"--proxy": "inspect", "--get": "inspect", "--set": "careful"},
    "pmset": {"-g": "inspect"},
    "spctl": {"--status": "inspect", "--assess": "inspect", "--master-enable": "careful", "--master-disable": "careful"},
    "csrutil": {"status": "inspect", "enable": "careful", "disable": "careful"},
    "nvram": {"-p": "inspect"},
}


def _split_note(action):
    """Separate the pasteable command from a trailing two-space `# comment`."""
    match = COMMENT_PATTERN.search(action)
    if not match:
        return action.strip(), None
    return action[:match.start()].strip(), match.group(1).strip()


def _looks_like_gui(text):
    lowered = text.lower()
    if any(marker in lowered for marker in GUI_MARKERS):
        return True
    return " > " in text and not text.lstrip().startswith(("cat ", "grep ", "echo "))


def _segment_tier(segment):
    parts = segment.split()
    if not parts:
        return None, False
    elevated = parts[0] == "sudo"
    if elevated:
        parts = parts[1:]
        if not parts:
            return None, True
    binary = parts[0].rsplit("/", 1)[-1]
    if not BINARY_PATTERN.match(binary):
        return None, elevated
    table = SUBCOMMAND_TIERS.get(binary)
    tier = None
    if table:
        for token in parts[1:]:
            if token in table:
                tier = table[token]
                break
        if tier is None:
            tier = "inspect" if all(value == "inspect" for value in table.values()) else "apply"
    if tier is None:
        tier = DEFAULT_TIERS.get(binary, "apply")
    lowered = segment.lower()
    if any(marker in lowered for marker in DESTRUCTIVE):
        tier = "careful"
    if elevated:
        tier = "careful"
    return tier, elevated


def _command_tier(command):
    """Highest tier across every segment of a compound command."""
    tier = None
    elevated = False
    for segment in SPLIT_PATTERN.split(command):
        segment = segment.strip()
        if not segment:
            continue
        segment_tier, segment_elevated = _segment_tier(segment)
        elevated = elevated or segment_elevated
        if segment_tier is None:
            return None, elevated
        if tier is None or TIER_RANK[segment_tier] > TIER_RANK[tier]:
            tier = segment_tier
    return tier, elevated


def classify(item):
    """Map one finding onto a fix entry. Never returns None."""
    entry = {
        "finding_id": item.get("id"),
        "domain": item.get("domain"),
        "severity": item.get("severity", "info"),
        "title": item.get("title", ""),
        "reversible": bool(item.get("reversible")),
        "tier": "manual",
        "command": None,
        "note": None,
        "manual_step": None,
        "needs_elevation": False,
    }
    action = (item.get("suggested_action") or "").strip()
    if not action:
        return entry

    body, note = _split_note(action)
    entry["note"] = note

    alternative = ALTERNATIVE_PATTERN.search(body)
    if alternative:
        candidate = alternative.group(1).strip()
        prose = body[:alternative.start()].strip()
        tier, elevated = _command_tier(candidate)
        if tier:
            entry.update({"tier": tier, "command": candidate, "needs_elevation": elevated, "manual_step": prose or None})
            return entry
        body = prose or body

    if _looks_like_gui(body):
        entry["manual_step"] = body
        return entry

    tier, elevated = _command_tier(body)
    if tier is None:
        entry["manual_step"] = body
        return entry
    entry.update({"tier": tier, "command": body, "needs_elevation": elevated})
    return entry


def _merge(entries):
    """Collapse identical commands so the same paste is not offered twice."""
    merged = {}
    for entry in entries:
        key = entry["command"]
        existing = merged.get(key)
        if existing is None:
            merged[key] = {
                "command": key,
                "tier": entry["tier"],
                "needs_elevation": entry["needs_elevation"],
                "note": entry["note"],
                "severity": entry["severity"],
                "domains": [entry["domain"]],
                "titles": [entry["title"]],
                "finding_ids": [entry["finding_id"]],
                "reversible": entry["reversible"],
            }
            continue
        existing["finding_ids"].append(entry["finding_id"])
        if entry["title"] not in existing["titles"]:
            existing["titles"].append(entry["title"])
        if entry["domain"] not in existing["domains"]:
            existing["domains"].append(entry["domain"])
        if SEVERITY_RANK.get(entry["severity"], 3) < SEVERITY_RANK.get(existing["severity"], 3):
            existing["severity"] = entry["severity"]
        if TIER_RANK[entry["tier"]] > TIER_RANK[existing["tier"]]:
            existing["tier"] = entry["tier"]
        existing["needs_elevation"] = existing["needs_elevation"] or entry["needs_elevation"]
        existing["reversible"] = existing["reversible"] and entry["reversible"]
        if existing["note"] is None:
            existing["note"] = entry["note"]
    return list(merged.values())


def build(findings):
    """Return the whole fix plan for a run, ordered and deduplicated."""
    classified = [classify(item) for item in findings or []]
    with_command = [entry for entry in classified if entry["command"]]
    manual = [entry for entry in classified if not entry["command"] and entry["manual_step"]]
    undecided = [entry for entry in classified if not entry["command"] and not entry["manual_step"]]

    commands = _merge(with_command)
    commands.sort(key=lambda entry: (
        TIER_RANK[entry["tier"]],
        SEVERITY_RANK.get(entry["severity"], 3),
        entry["command"],
    ))

    manual_merged = {}
    for entry in manual:
        key = entry["manual_step"]
        record = manual_merged.setdefault(key, {
            "manual_step": key,
            "severity": entry["severity"],
            "domains": [],
            "titles": [],
            "finding_ids": [],
        })
        record["finding_ids"].append(entry["finding_id"])
        if entry["title"] not in record["titles"]:
            record["titles"].append(entry["title"])
        if entry["domain"] not in record["domains"]:
            record["domains"].append(entry["domain"])
        if SEVERITY_RANK.get(entry["severity"], 3) < SEVERITY_RANK.get(record["severity"], 3):
            record["severity"] = entry["severity"]
    manual_steps = sorted(manual_merged.values(), key=lambda entry: (
        SEVERITY_RANK.get(entry["severity"], 3),
        entry["manual_step"],
    ))

    counts = {tier: 0 for tier in TIERS}
    for entry in commands:
        counts[entry["tier"]] += 1

    return {
        "note": "Commands are classified from the suggested action text. macverify executed none of them.",
        "counts": {
            "commands": len(commands),
            "manual_steps": len(manual_steps),
            "no_action": len(undecided),
            "inspect": counts["inspect"],
            "apply": counts["apply"],
            "careful": counts["careful"],
            "needs_elevation": len([entry for entry in commands if entry["needs_elevation"]]),
        },
        "commands": commands,
        "manual_steps": manual_steps,
    }


def by_tier(plan, tier):
    return [entry for entry in plan.get("commands") or [] if entry["tier"] == tier]
