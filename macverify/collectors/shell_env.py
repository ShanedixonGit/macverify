import os
import re
import stat as statmod

from .. import findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context
from .secrets import redact

PROFILES = (
    ("zsh", "~/.zshenv"),
    ("zsh", "~/.zprofile"),
    ("zsh", "~/.zshrc"),
    ("zsh", "~/.zlogin"),
    ("bash", "~/.bash_profile"),
    ("bash", "~/.bash_login"),
    ("bash", "~/.bashrc"),
    ("sh", "~/.profile"),
    ("fish", "~/.config/fish/config.fish"),
)

SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/System")

MANAGER_HINTS = (
    ("pyenv", "/.pyenv/"),
    ("rbenv", "/.rbenv/"),
    ("nodenv", "/.nodenv/"),
    ("asdf", "/.asdf/"),
    ("nvm", "/.nvm/"),
    ("fnm", "/fnm/"),
    ("volta", "/.volta/"),
    ("cargo", "/.cargo/"),
    ("pipx", "/.local/bin"),
    ("bun", "/.bun/"),
    ("deno", "/.deno/"),
)

ALIAS_ZSH = re.compile(r"^\s*alias\s+(?:-[gs]\s+)?([A-Za-z0-9_.:+-]+)=(.*)$")
ALIAS_FISH = re.compile(r"^\s*alias\s+([A-Za-z0-9_.:+-]+)[= ](.*)$")
FUNCTION_POSIX = re.compile(r"^\s*(?:function\s+)?([A-Za-z0-9_.:+-]+)\s*\(\s*\)\s*\{?")
FUNCTION_KEYWORD = re.compile(r"^\s*function\s+([A-Za-z0-9_.:+-]+)\s*\{?")
EXPORT_POSIX = re.compile(r"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$")
EXPORT_FISH = re.compile(r"^\s*set\s+(?:-\w+\s+)*(?:-\w*x\w*|--export)\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$")
SOURCE_LINE = re.compile(r"^\s*(?:source|\.)\s+(\"[^\"]+\"|'[^']+'|\S+)")
PATH_ASSIGN = re.compile(r"^\s*(?:export\s+)?PATH=(.*)$")


def _path_entries():
    raw = os.environ.get("PATH") or ""
    entries = []
    seen = {}
    for index, item in enumerate(raw.split(os.pathsep)):
        record = {
            "order": index,
            "path": item,
            "display": fsutil.tilde(item) if item else "(empty)",
            "exists": False,
            "is_directory": False,
            "world_writable": False,
            "symlink_target": None,
            "duplicate_of": None,
            "manager": None,
        }
        if not item:
            record["issue"] = "empty PATH element resolves to the current directory"
            entries.append(record)
            continue
        normalised = os.path.normpath(item)
        if normalised in seen:
            record["duplicate_of"] = seen[normalised]
        else:
            seen[normalised] = index
        st = fsutil.stat(item, follow=True)
        if st is not None:
            record["exists"] = True
            record["is_directory"] = statmod.S_ISDIR(st.st_mode)
            record["world_writable"] = fsutil.is_world_writable(item)
        if os.path.islink(item):
            try:
                record["symlink_target"] = os.readlink(item)
            except OSError:
                record["symlink_target"] = None
        for label, hint in MANAGER_HINTS:
            if hint in normalised + "/":
                record["manager"] = label
                break
        brew = sysinfo.homebrew()
        if brew.get("prefix") and normalised.startswith(brew["prefix"] + "/"):
            record["manager"] = "homebrew"
        entries.append(record)
    return entries


def _executables(directory):
    names = set()
    try:
        with os.scandir(directory) as handle:
            for entry in handle:
                try:
                    if entry.is_dir(follow_symlinks=True):
                        continue
                    info = entry.stat(follow_symlinks=True)
                    if info.st_mode & 0o111:
                        names.add(entry.name)
                except (OSError, ValueError):
                    continue
    except (OSError, ValueError):
        return names
    return names


def _shadowing(entries):
    index = {}
    for record in entries:
        if not record["exists"] or not record["is_directory"] or record["duplicate_of"] is not None:
            continue
        for name in _executables(record["path"]):
            index.setdefault(name, []).append(record)
    shadowed = []
    for name in sorted(index):
        providers = index[name]
        if len(providers) < 2:
            continue
        winner = providers[0]
        losers = providers[1:]
        entry = {
            "command": name,
            "resolves_to": winner["display"],
            "winner_manager": winner["manager"],
            "shadowed": [{"path": item["display"], "manager": item["manager"]} for item in losers],
        }
        winner_is_system = any(winner["path"].startswith(prefix) for prefix in SYSTEM_DIRS) and winner["manager"] is None
        managed_losers = [item for item in losers if item["manager"]]
        entry["system_shadows_manager"] = bool(winner_is_system and managed_losers)
        shadowed.append(entry)
    return shadowed


def _expand_source(raw):
    value = raw.strip().strip("\"'")
    expanded = os.path.expanduser(os.path.expandvars(value))
    unresolved = "$" in expanded
    return value, expanded, unresolved


def _parse_profile(family, path):
    text = fsutil.read_text(path)
    if text is None:
        return None
    record = {
        "path": fsutil.tilde(path),
        "family": family,
        "bytes": fsutil.file_size(path),
        "aliases": [],
        "functions": [],
        "exports": [],
        "sourced": [],
        "path_mutations": [],
    }
    in_function = 0
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        alias_match = ALIAS_FISH.match(line) if family == "fish" else ALIAS_ZSH.match(line)
        if alias_match:
            name = alias_match.group(1)
            value = alias_match.group(2).strip().strip("\"'")
            record["aliases"].append({"name": name, "line": number, "value": redact(name, value)})
            continue
        export_match = EXPORT_FISH.match(line) if family == "fish" else EXPORT_POSIX.match(line)
        if export_match:
            name = export_match.group(1)
            value = (export_match.group(2) or "").strip().strip("\"'")
            record["exports"].append({"name": name, "line": number, "value": redact(name, value) if value else None})
            continue
        source_match = SOURCE_LINE.match(line)
        if source_match:
            raw, expanded, unresolved = _expand_source(source_match.group(1))
            record["sourced"].append({
                "line": number,
                "raw": raw,
                "resolved": fsutil.tilde(expanded) if not unresolved else None,
                "unresolved_variable": unresolved,
                "exists": fsutil.exists(expanded) if not unresolved else None,
            })
            continue
        path_match = PATH_ASSIGN.match(line)
        if path_match:
            record["path_mutations"].append({"line": number, "statement": stripped[:200]})
            continue
        function_match = FUNCTION_KEYWORD.match(line) or FUNCTION_POSIX.match(line)
        if function_match and not stripped.startswith(("if", "for", "while", "case", "elif", "else", "return")):
            record["functions"].append({"name": function_match.group(1), "line": number})
            continue
        if family == "fish" and stripped.startswith("function "):
            record["functions"].append({"name": stripped.split()[1], "line": number})
            in_function += 1
    for key in ("aliases", "functions", "exports"):
        record[key] = sorted(record[key], key=lambda item: (item["name"], item["line"]))
    record["counts"] = {key: len(record[key]) for key in ("aliases", "functions", "exports", "sourced", "path_mutations")}
    return record


def collect(ctx=None):
    ctx = default_context(ctx)
    entries = _path_entries()
    shadowing = _shadowing(entries)

    profiles = []
    missing = []
    for family, pattern in PROFILES:
        path = os.path.expanduser(pattern)
        if not fsutil.exists(path):
            missing.append(fsutil.tilde(path))
            continue
        parsed = _parse_profile(family, path)
        if parsed is None:
            profiles.append({"path": fsutil.tilde(path), "family": family, "status": "unavailable", "reason": "file is not readable text"})
        else:
            profiles.append(parsed)

    alias_index = {}
    for profile in profiles:
        for alias in profile.get("aliases") or []:
            alias_index.setdefault(alias["name"], []).append({"file": profile["path"], "line": alias["line"], "value": alias["value"]})
    conflicts = []
    for name in sorted(alias_index):
        definitions = alias_index[name]
        if len(definitions) < 2:
            continue
        values = {item["value"] for item in definitions}
        conflicts.append({
            "alias": name,
            "definitions": definitions,
            "identical": len(values) == 1,
            "effective": definitions[-1],
        })

    broken_sources = []
    for profile in profiles:
        for item in profile.get("sourced") or []:
            if item.get("exists") is False:
                broken_sources.append({"file": profile["path"], "line": item["line"], "target": item["raw"]})

    shell_info = sysinfo.login_shell()
    result = {
        "status": "ok",
        "login_shell": shell_info,
        "path": {
            "source": "PATH inherited by the audit process",
            "entry_count": len(entries),
            "entries": entries,
            "duplicates": [entry["display"] for entry in entries if entry["duplicate_of"] is not None],
            "missing_directories": [entry["display"] for entry in entries if not entry["exists"]],
            "world_writable_directories": [entry["display"] for entry in entries if entry["world_writable"]],
        },
        "shadowed_commands": {
            "total": len(shadowing),
            "system_shadows_manager": [item for item in shadowing if item["system_shadows_manager"]],
            "all": shadowing[:300],
            "truncated": len(shadowing) > 300,
        },
        "profiles": profiles,
        "missing_profiles": missing,
        "alias_conflicts": conflicts,
        "broken_sourced_files": broken_sources,
    }

    findings = []
    for entry in entries:
        if entry["duplicate_of"] is not None:
            findings.append(F.finding(
                "shell_env",
                "info",
                "Duplicate PATH entry: %s" % entry["display"],
                "position %d repeats position %d" % (entry["order"], entry["duplicate_of"]),
                "Duplicate entries lengthen every command lookup and hide the real precedence when debugging PATH order.",
                "Remove the later duplicate from the profile that appends it",
                True,
                key="path-dup-%s-%s" % (entry["display"], entry["order"]),
            ))
        if not entry["exists"]:
            findings.append(F.finding(
                "shell_env",
                "info",
                "PATH entry does not exist: %s" % entry["display"],
                "position %d in PATH" % entry["order"],
                "Non-existent PATH entries are dead weight from removed tools and make PATH harder to reason about.",
                "Remove the stale entry from your shell profile",
                True,
                key="path-missing-%s" % entry["display"],
            ))
        if entry["world_writable"]:
            findings.append(F.finding(
                "shell_env",
                "critical",
                "World-writable directory on PATH: %s" % entry["display"],
                "position %d, world-writable without the sticky bit" % entry["order"],
                "Any local process can drop an executable into that directory and have it run as you the next time you type a common command name.",
                "chmod o-w %s" % entry["display"],
                True,
                key="path-writable-%s" % entry["display"],
            ))
        if entry["path"] == "":
            findings.append(F.finding(
                "shell_env",
                "critical",
                "Empty element in PATH resolves to the current directory",
                "position %d is an empty string" % entry["order"],
                "An empty PATH element makes the working directory searchable for commands, so cd-ing into an untrusted repository can hijack a command name.",
                "Remove the leading, trailing or doubled colon from the PATH assignment in your shell profile",
                True,
                key="path-empty-%s" % entry["order"],
            ))

    for item in result["shadowed_commands"]["system_shadows_manager"]:
        findings.append(F.finding(
            "shell_env",
            "warning",
            "System copy of %s shadows a version-managed copy" % item["command"],
            "%s wins over %s" % (item["resolves_to"], ", ".join("%s (%s)" % (entry["path"], entry["manager"]) for entry in item["shadowed"] if entry["manager"])),
            "The interpreter or tool you configured through a version manager is not the one your shell actually runs, so installs and upgrades land somewhere you are not using.",
            "Move the manager directory ahead of the system directories in your PATH export",
            True,
            key="shadow-%s" % item["command"],
        ))

    for conflict in conflicts:
        findings.append(F.finding(
            "shell_env",
            "info" if conflict["identical"] else "warning",
            "Alias %s is defined in more than one profile" % conflict["alias"],
            "; ".join("%s:%s" % (item["file"], item["line"]) for item in conflict["definitions"]) + (" (identical definitions)" if conflict["identical"] else " (differing definitions)"),
            "Whichever profile is sourced last silently wins, so the alias behaves differently depending on how the shell was started.",
            "Keep one definition and delete the others",
            True,
            key="alias-%s" % conflict["alias"],
        ))

    for item in broken_sources:
        findings.append(F.finding(
            "shell_env",
            "warning",
            "Profile sources a file that no longer exists",
            "%s:%s sources %s" % (item["file"], item["line"], item["target"]),
            "Every new shell pays the cost of a failed source, and any configuration that file used to provide is silently missing.",
            "Remove the source line, or restore the file it points at",
            True,
            key="source-%s-%s" % (item["file"], item["line"]),
        ))

    result["findings"] = findings
    return result
