import os
import re

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

EXTRA_TOOLS = (
    ("ruflo", ("~/.ruflo", "~/.config/ruflo", "~/.claude/ruflo.config.json", "./ruflo.config.json", "./.ruflo")),
    ("ruv-flow", ("~/.ruv-flow", "~/.config/ruv-flow", "./.ruv-flow")),
    ("claude-flow", ("~/.claude-flow", "~/.claude/.claude-flow", "./.claude-flow", "./claude-flow.config.json", "./.swarm")),
    ("agentdb", ("~/.agentdb", "./.agentdb")),
)

SETTINGS_PRECEDENCE = ("managed", "project_local", "project_shared", "user_local", "user")

NATIVE_CAPABILITIES = {
    "filesystem": ("Read", "Write", "Edit", "Glob"),
    "file": ("Read", "Write", "Edit"),
    "git": ("Bash",),
    "shell": ("Bash",),
    "terminal": ("Bash",),
    "fetch": ("WebFetch",),
    "web": ("WebFetch", "WebSearch"),
    "search": ("Grep", "Glob", "WebSearch"),
    "sequentialthinking": ("extended thinking",),
    "todo": ("TodoWrite",),
}

STOPWORDS = {
    "the", "a", "an", "and", "or", "for", "with", "when", "use", "using", "used", "this", "that", "to", "of", "in",
    "on", "by", "is", "are", "be", "it", "its", "as", "at", "from", "into", "you", "your", "should", "can", "will",
    "any", "all", "not", "but", "if", "then", "than", "also", "via", "per", "up", "out", "over", "before", "after",
    "skill", "skills", "agent", "agents", "command", "commands", "claude", "code", "user", "users", "need", "needs",
    "have", "has", "was", "were", "there", "their", "them", "they", "what", "which", "who", "how", "why", "more",
}

VAGUE_MINIMUM_CHARS = 40
TRIGGER_HINTS = ("use when", "when you", "when the", "triggers on", "invoke when", "for when", "use this when", "activates")


def parse_frontmatter(text):
    if not text or not text.startswith("---"):
        return {}, text or ""
    lines = text.split("\n")
    if lines[0].strip() != "---":
        return {}, text
    end = None
    for index in range(1, len(lines)):
        if lines[index].strip() in ("---", "..."):
            end = index
            break
    if end is None:
        return {}, text
    meta = {}
    key = None
    block = None
    for raw in lines[1:end]:
        if block is not None and (raw.startswith("  ") or raw.startswith("\t") or not raw.strip()):
            meta[block] = (meta.get(block, "") + " " + raw.strip()).strip()
            continue
        block = None
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if raw.startswith((" ", "\t")) and key:
            stripped = raw.strip()
            if stripped.startswith("- "):
                if not isinstance(meta.get(key), list):
                    meta[key] = []
                meta[key].append(stripped[2:].strip().strip("\"'"))
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$", raw)
        if not match:
            continue
        key = match.group(1)
        value = match.group(2).strip()
        if value in ("|", ">", "|-", ">-", "|+", ">+"):
            block = key
            meta[key] = ""
            continue
        if value.startswith("[") and value.endswith("]"):
            meta[key] = [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
            continue
        meta[key] = value.strip().strip("\"'")
    return meta, "\n".join(lines[end + 1:])


def _tokens(text):
    words = re.findall(r"[a-z][a-z0-9_-]{2,}", (text or "").lower())
    return {word for word in words if word not in STOPWORDS}


def _similarity(left, right):
    if not left or not right:
        return 0.0, []
    shared = left & right
    union = left | right
    if not union:
        return 0.0, []
    return round(len(shared) / float(len(union)), 3), sorted(shared)


def _cost(always_bytes, on_demand_bytes):
    return {
        "always_loaded_bytes": always_bytes,
        "always_loaded_tokens_estimate": always_bytes // 4,
        "on_demand_bytes": on_demand_bytes,
        "on_demand_tokens_estimate": on_demand_bytes // 4,
    }


def _headings(body, limit=40):
    outline = []
    for line in (body or "").splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*$", line)
        if match:
            outline.append({"level": len(match.group(1)), "text": match.group(2)[:120]})
        if len(outline) >= limit:
            break
    return outline


def _read_settings(path, scope):
    if not fsutil.exists(path):
        return None
    payload, reason = fsutil.read_json(path)
    if payload is None:
        return {"scope": scope, "path": fsutil.tilde(path), "status": "unavailable", "reason": reason, "keys": [], "data": {}}
    return {
        "scope": scope,
        "path": fsutil.tilde(path),
        "status": "ok",
        "bytes": fsutil.file_size(path),
        "keys": sorted(payload.keys()),
        "data": payload,
    }


def _skill_entry(path, scope, scope_detail, active, active_reason):
    text = fsutil.read_text(path) or ""
    meta, body = parse_frontmatter(text)
    directory = os.path.dirname(path)
    name = meta.get("name") or os.path.basename(directory)
    description = meta.get("description")
    references = []
    reference_bytes = 0
    for entry in fsutil.listdir(directory):
        if entry == "SKILL.md":
            continue
        full = os.path.join(directory, entry)
        if os.path.isdir(full):
            size = fsutil.dir_size(full, max_entries=5000) or 0
            references.append({"name": entry, "kind": "directory", "bytes": size})
        else:
            size = fsutil.file_size(full) or 0
            references.append({"name": entry, "kind": "file", "bytes": size})
        reference_bytes += size
    frontmatter_bytes = len(("name: %s\ndescription: %s\n" % (name, description or "")).encode("utf-8"))
    return {
        "kind": "skill",
        "name": name,
        "scope": scope,
        "scope_detail": scope_detail,
        "path": fsutil.tilde(path),
        "purpose": description if description else "undeclared",
        "purpose_declared": bool(description),
        "active": active,
        "active_reason": active_reason,
        "file_bytes": fsutil.file_size(path),
        "reference_files": sorted(references, key=lambda item: item["name"]),
        "reference_file_count": len(references),
        "reference_bytes": reference_bytes,
        "allowed_tools": meta.get("allowed-tools") or meta.get("allowedTools"),
        "model": meta.get("model"),
        "context_cost": _cost(frontmatter_bytes, len(body.encode("utf-8")) + reference_bytes),
    }


def _agent_entry(path, scope, scope_detail, active, active_reason):
    text = fsutil.read_text(path) or ""
    meta, body = parse_frontmatter(text)
    name = meta.get("name") or os.path.splitext(os.path.basename(path))[0]
    description = meta.get("description")
    return {
        "kind": "agent",
        "name": name,
        "scope": scope,
        "scope_detail": scope_detail,
        "path": fsutil.tilde(path),
        "purpose": description if description else "undeclared",
        "purpose_declared": bool(description),
        "active": active,
        "active_reason": active_reason,
        "model": meta.get("model"),
        "tools": meta.get("tools"),
        "file_bytes": fsutil.file_size(path),
        "context_cost": _cost(len(("%s: %s" % (name, description or "")).encode("utf-8")), len(body.encode("utf-8"))),
    }


def _command_entry(path, root, scope, scope_detail, active, active_reason, prefix=None):
    text = fsutil.read_text(path) or ""
    meta, body = parse_frontmatter(text)
    relative = os.path.relpath(path, root)
    name = os.path.splitext(relative)[0].replace(os.sep, ":")
    if prefix:
        name = "%s:%s" % (prefix, name)
    description = meta.get("description")
    return {
        "kind": "command",
        "name": name,
        "scope": scope,
        "scope_detail": scope_detail,
        "path": fsutil.tilde(path),
        "purpose": description if description else "undeclared",
        "purpose_declared": bool(description),
        "argument_hint": meta.get("argument-hint") or meta.get("argumentHint"),
        "allowed_tools": meta.get("allowed-tools") or meta.get("allowedTools"),
        "model": meta.get("model"),
        "active": active,
        "active_reason": active_reason,
        "file_bytes": fsutil.file_size(path),
        "context_cost": _cost(len(("/%s %s" % (name, description or "")).encode("utf-8")), len(body.encode("utf-8"))),
    }


def _claude_md_entry(path, scope, active, active_reason):
    text = fsutil.read_text(path) or ""
    size = len(text.encode("utf-8"))
    return {
        "kind": "claude_md",
        "name": fsutil.tilde(path),
        "scope": scope,
        "path": fsutil.tilde(path),
        "purpose": "instructions loaded verbatim as memory" if active else "present but out of scope for the current directory",
        "purpose_declared": True,
        "active": active,
        "active_reason": active_reason,
        "file_bytes": size,
        "heading_outline": _headings(text),
        "context_cost": _cost(size if active else 0, 0 if active else size),
    }


def _find(root, filename, max_depth=4):
    if not fsutil.exists(root):
        return []
    return fsutil.walk_files(root, lambda name: name == filename, max_depth=max_depth)


def _find_markdown(root, max_depth=4):
    if not fsutil.exists(root):
        return []
    return fsutil.walk_files(root, lambda name: name.endswith(".md"), max_depth=max_depth)


def _marketplace_index(claude_home, marketplaces):
    index = {}
    for name, record in sorted((marketplaces or {}).items()):
        location = (record or {}).get("installLocation") or os.path.join(claude_home, "plugins", "marketplaces", name)
        payload, _ = fsutil.read_json(os.path.join(location, ".claude-plugin", "marketplace.json"))
        entries = {}
        for entry in (payload or {}).get("plugins") or []:
            if isinstance(entry, dict) and entry.get("name"):
                entries[entry["name"]] = entry
        index[name] = entries
    return index


def _declared_paths(root, declared, filename):
    paths = []
    for relative in declared or []:
        if not isinstance(relative, str):
            continue
        target = os.path.normpath(os.path.join(root, relative))
        if os.path.isdir(target):
            candidate = os.path.join(target, filename)
            if fsutil.exists(candidate):
                paths.append(candidate)
            else:
                paths.extend(_find(target, filename))
        elif fsutil.exists(target):
            paths.append(target)
    return sorted(set(paths))


def _plugins(claude_home, enabled_map):
    installed_path = os.path.join(claude_home, "plugins", "installed_plugins.json")
    marketplaces_path = os.path.join(claude_home, "plugins", "known_marketplaces.json")
    installed, installed_reason = fsutil.read_json(installed_path)
    marketplaces, _ = fsutil.read_json(marketplaces_path)
    catalogue = _marketplace_index(claude_home, marketplaces)
    if installed is None:
        return shell.unavailable(installed_reason or "no installed_plugins.json present"), []
    entries = []
    for identifier, records in sorted((installed.get("plugins") or {}).items()):
        record = (records or [{}])[0] if isinstance(records, list) else {}
        install_path = record.get("installPath")
        name, _, marketplace = identifier.partition("@")
        manifest = {}
        if install_path:
            manifest_data, _ = fsutil.read_json(os.path.join(install_path, ".claude-plugin", "plugin.json"))
            manifest = manifest_data or {}
        source = ((marketplaces or {}).get(marketplace) or {}).get("source") or {}
        catalogue_entry = (catalogue.get(marketplace) or {}).get(name) or {}
        entries.append({
            "identifier": identifier,
            "name": manifest.get("name") or catalogue_entry.get("name") or name,
            "marketplace": marketplace,
            "marketplace_source": source.get("repo") or source.get("url") or source.get("source"),
            "version": manifest.get("version") or record.get("version"),
            "description": manifest.get("description") or catalogue_entry.get("description") or "undeclared",
            "declared_skills": catalogue_entry.get("skills"),
            "declared_agents": catalogue_entry.get("agents"),
            "declared_commands": catalogue_entry.get("commands"),
            "shares_checkout": catalogue_entry.get("source") in ("./", "."),
            "scope": record.get("scope"),
            "install_path": fsutil.tilde(install_path) if install_path else None,
            "install_path_exists": fsutil.exists(install_path) if install_path else False,
            "installed_at": record.get("installedAt"),
            "last_updated": record.get("lastUpdated"),
            "enabled": bool(enabled_map.get(identifier)),
            "_root": install_path,
        })
    summary = {
        "status": "ok",
        "count": len(entries),
        "enabled_count": sum(1 for item in entries if item["enabled"]),
        "marketplaces": sorted((marketplaces or {}).keys()),
        "plugins": [{key: value for key, value in item.items() if key != "_root"} for item in entries],
    }
    return summary, entries


def _mcp_entry(name, config, scope, source, active, reason):
    config = config or {}
    transport = config.get("type") or ("http" if config.get("url") else "stdio")
    endpoint = config.get("url") or " ".join([str(config.get("command") or "")] + [str(item) for item in (config.get("args") or [])]).strip()
    declared_tools = config.get("tools")
    return {
        "kind": "mcp_server",
        "name": name,
        "scope": scope,
        "source": source,
        "transport": transport,
        "endpoint": endpoint or None,
        "purpose": config.get("description") or "undeclared",
        "purpose_declared": bool(config.get("description")),
        "active": active,
        "active_reason": reason,
        "declared_tool_count": len(declared_tools) if isinstance(declared_tools, list) else None,
        "tool_count_note": "tool definitions are only available by starting the server, which this audit never does",
        "context_cost": {
            "always_loaded_bytes": None,
            "always_loaded_tokens_estimate": None,
            "on_demand_bytes": 0,
            "on_demand_tokens_estimate": 0,
            "measurement_note": "an enabled MCP server injects its tool schemas into every session prompt; the size cannot be measured without connecting to the server",
        },
    }


def _mcp_servers(project_roots, settings_by_scope, cwd):
    servers = []
    global_config, _ = fsutil.read_json(os.path.expanduser("~/.claude.json"))
    global_config = global_config or {}
    for name, config in sorted((global_config.get("mcpServers") or {}).items()):
        servers.append(_mcp_entry(name, config, "user", "~/.claude.json", True, "declared at user scope, loaded in every project"))
    project_entry = (global_config.get("projects") or {}).get(cwd) or {}
    for name, config in sorted((project_entry.get("mcpServers") or {}).items()):
        servers.append(_mcp_entry(name, config, "local", "~/.claude.json", True, "declared for this directory only in the local project record"))
    enabled_json = set()
    disabled_json = set()
    enable_all = False
    for scope in SETTINGS_PRECEDENCE:
        data = (settings_by_scope.get(scope) or {}).get("data") or {}
        enabled_json.update(data.get("enabledMcpjsonServers") or [])
        disabled_json.update(data.get("disabledMcpjsonServers") or [])
        if data.get("enableAllProjectMcpServers"):
            enable_all = True
    for root in project_roots:
        path = os.path.join(root, ".mcp.json")
        payload, _ = fsutil.read_json(path)
        if not payload:
            continue
        for name, config in sorted((payload.get("mcpServers") or {}).items()):
            if name in disabled_json:
                active, reason = False, "listed in disabledMcpjsonServers"
            elif enable_all:
                active, reason = True, "enableAllProjectMcpServers is set"
            elif name in enabled_json:
                active, reason = True, "listed in enabledMcpjsonServers"
            else:
                active, reason = False, "project server awaiting approval; not listed in enabledMcpjsonServers"
            servers.append(_mcp_entry(name, config, "project", fsutil.tilde(path), active, reason))
    return sorted(servers, key=lambda item: (item["name"], item["scope"]))


def _hooks(settings_by_scope):
    hooks = []
    for scope in SETTINGS_PRECEDENCE:
        entry = settings_by_scope.get(scope)
        data = (entry or {}).get("data") or {}
        for event, matchers in sorted((data.get("hooks") or {}).items()):
            if not isinstance(matchers, list):
                continue
            for group in matchers:
                if not isinstance(group, dict):
                    continue
                matcher = group.get("matcher")
                for hook in group.get("hooks") or []:
                    if not isinstance(hook, dict):
                        continue
                    hooks.append({
                        "kind": "hook",
                        "event": event,
                        "matcher": matcher if matcher not in (None, "") else "*",
                        "matcher_is_wildcard": matcher in (None, "", "*", ".*"),
                        "type": hook.get("type"),
                        "command": str(hook.get("command") or "")[:400],
                        "timeout_ms": hook.get("timeout"),
                        "scope": scope,
                        "source": entry.get("path"),
                    })
    return sorted(hooks, key=lambda item: (item["event"], item["scope"], item["command"]))


def _parse_rule(rule):
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$", str(rule).strip())
    if match:
        return match.group(1), match.group(2)
    return str(rule).strip(), None


def _pattern_shape(pattern):
    if pattern is None:
        return "tool_wide", None
    value = pattern.strip()
    if value in ("*", ":*"):
        return "all", None
    if value.endswith(":*"):
        return "prefix", value[:-2].strip() + " "
    if value.endswith(" *"):
        return "prefix", value[:-2].strip() + " "
    if value.endswith("*"):
        return "prefix", value[:-1]
    return "exact", value


def _covers(broad, narrow):
    broad_tool, broad_pattern = broad
    narrow_tool, narrow_pattern = narrow
    if broad_tool != narrow_tool:
        return False
    broad_kind, broad_value = _pattern_shape(broad_pattern)
    narrow_kind, narrow_value = _pattern_shape(narrow_pattern)
    if broad_kind == "tool_wide":
        return narrow_kind != "tool_wide"
    if broad_kind == "all":
        return narrow_kind not in ("all", "tool_wide")
    if broad_kind != "prefix":
        return False
    if narrow_kind == "exact":
        return narrow_value.startswith(broad_value) or narrow_value == broad_value.strip()
    if narrow_kind == "prefix":
        return narrow_value != broad_value and narrow_value.startswith(broad_value)
    return False


def _permissions(settings_by_scope):
    rules = []
    for scope in SETTINGS_PRECEDENCE:
        entry = settings_by_scope.get(scope)
        if not entry:
            continue
        permissions = (entry.get("data") or {}).get("permissions") or {}
        for bucket in ("allow", "ask", "deny"):
            for rule in permissions.get(bucket) or []:
                rules.append({"bucket": bucket, "rule": rule, "scope": scope, "source": entry.get("path"), "parsed": _parse_rule(rule)})
        for key in ("defaultMode", "additionalDirectories", "disableBypassPermissionsMode"):
            if key in permissions:
                rules.append({"bucket": "setting", "rule": "%s=%s" % (key, permissions[key]), "scope": scope, "source": entry.get("path"), "parsed": (key, None)})
    dead = []
    for bucket in ("allow", "ask", "deny"):
        bucket_rules = [item for item in rules if item["bucket"] == bucket]
        for index, item in enumerate(bucket_rules):
            for other_index, other in enumerate(bucket_rules):
                if other_index == index or not _covers(other["parsed"], item["parsed"]):
                    continue
                dead.append({
                    "rule": item["rule"],
                    "bucket": bucket,
                    "scope": item["scope"],
                    "source": item["source"],
                    "covered_by": other["rule"],
                    "covered_by_source": other["source"],
                    "position": index,
                    "covered_by_position": other_index,
                })
                break
    return {
        "evaluation_order": "deny is checked first, then ask, then allow; anything unmatched falls through to the default mode",
        "precedence_order": list(SETTINGS_PRECEDENCE),
        "rules": [{key: value for key, value in item.items() if key != "parsed"} for item in rules],
        "rule_count": len(rules),
        "merged": {bucket: [item["rule"] for item in rules if item["bucket"] == bucket] for bucket in ("allow", "ask", "deny")},
        "dead_rules": dead,
    }


def _overridden_settings(settings_by_scope):
    seen = {}
    overrides = []
    for scope in SETTINGS_PRECEDENCE:
        entry = settings_by_scope.get(scope)
        if not entry or entry.get("status") != "ok":
            continue
        for key in entry["keys"]:
            if key in seen:
                overrides.append({
                    "key": key,
                    "effective_scope": seen[key]["scope"],
                    "effective_source": seen[key]["path"],
                    "overridden_scope": scope,
                    "overridden_source": entry["path"],
                })
            else:
                seen[key] = entry
    return sorted(overrides, key=lambda item: (item["key"], item["overridden_scope"]))


def _extra_tools(cwd):
    results = []
    for name, candidates in EXTRA_TOOLS:
        found = []
        checked = []
        for candidate in candidates:
            path = os.path.join(cwd, candidate[2:]) if candidate.startswith("./") else os.path.expanduser(candidate)
            checked.append(fsutil.tilde(path))
            if fsutil.exists(path):
                found.append(fsutil.tilde(path))
        results.append({"tool": name, "present": bool(found), "paths_found": sorted(found), "paths_checked": checked})
    return results


def _ancestor_claude_md(cwd, home):
    paths = []
    current = os.path.abspath(cwd)
    while True:
        candidate = os.path.join(current, "CLAUDE.md")
        if fsutil.exists(candidate):
            paths.append(candidate)
        parent = os.path.dirname(current)
        if parent == current or current == home or len(paths) > 12:
            break
        current = parent
    return paths


def collect(ctx=None):
    ctx = default_context(ctx)
    home = fsutil.home()
    claude_home = os.path.join(home, ".claude")
    cwd = os.path.abspath(ctx.cwd)
    project_roots = []
    for root in [cwd] + list(ctx.projects):
        absolute = os.path.abspath(root)
        if absolute not in project_roots:
            project_roots.append(absolute)

    if not fsutil.exists(claude_home) and not any(fsutil.exists(os.path.join(root, ".claude")) for root in project_roots):
        return {
            "status": "unavailable",
            "reason": "no Claude Code configuration found at ~/.claude or in the inspected project roots",
            "inventory": {},
            "context_budget": {},
            "analysis": {},
            "findings": [],
        }

    settings_by_scope = {}
    for scope, path in (
        ("managed", "/Library/Application Support/ClaudeCode/managed-settings.json"),
        ("project_local", os.path.join(cwd, ".claude", "settings.local.json")),
        ("project_shared", os.path.join(cwd, ".claude", "settings.json")),
        ("user_local", os.path.join(claude_home, "settings.local.json")),
        ("user", os.path.join(claude_home, "settings.json")),
    ):
        entry = _read_settings(path, scope)
        if entry:
            settings_by_scope[scope] = entry

    enabled_plugins = {}
    for scope in reversed(SETTINGS_PRECEDENCE):
        entry = settings_by_scope.get(scope)
        if entry and entry.get("status") == "ok":
            enabled_plugins.update((entry.get("data") or {}).get("enabledPlugins") or {})

    plugin_summary, plugin_entries = _plugins(claude_home, enabled_plugins)

    items = []
    user_skill_root = os.path.join(claude_home, "skills")
    for path in _find(user_skill_root, "SKILL.md"):
        items.append(_skill_entry(path, "user", "~/.claude/skills", True, "user scope skills are offered in every session"))
    user_agent_root = os.path.join(claude_home, "agents")
    for path in _find_markdown(user_agent_root):
        items.append(_agent_entry(path, "user", "~/.claude/agents", True, "user scope agents are offered in every session"))
    user_command_root = os.path.join(claude_home, "commands")
    for path in _find_markdown(user_command_root):
        items.append(_command_entry(path, user_command_root, "user", "~/.claude/commands", True, "user scope commands are offered in every session"))

    for root in project_roots:
        project_claude = os.path.join(root, ".claude")
        if not fsutil.exists(project_claude):
            continue
        in_scope = root == cwd
        reason = "the current working directory" if in_scope else "loaded only when Claude Code runs inside %s" % fsutil.tilde(root)
        for path in _find(os.path.join(project_claude, "skills"), "SKILL.md"):
            items.append(_skill_entry(path, "project", fsutil.tilde(root), in_scope, reason))
        for path in _find_markdown(os.path.join(project_claude, "agents")):
            items.append(_agent_entry(path, "project", fsutil.tilde(root), in_scope, reason))
        command_root = os.path.join(project_claude, "commands")
        for path in _find_markdown(command_root):
            items.append(_command_entry(path, command_root, "project", fsutil.tilde(root), in_scope, reason))

    for plugin in plugin_entries:
        root = plugin.get("_root")
        if not root or not fsutil.exists(root):
            continue
        enabled = plugin["enabled"]
        reason = "plugin %s is enabled in settings" % plugin["identifier"] if enabled else "plugin %s is installed but not enabled" % plugin["identifier"]
        declared_skills = plugin.get("declared_skills")
        skill_paths = _declared_paths(root, declared_skills, "SKILL.md") if declared_skills else _find(os.path.join(root, "skills"), "SKILL.md")
        scope_detail = plugin["identifier"] if declared_skills else "%s (whole checkout)" % plugin["identifier"]
        for path in skill_paths:
            items.append(_skill_entry(path, "plugin", scope_detail, enabled, reason))
        declared_agents = plugin.get("declared_agents")
        agent_paths = _declared_paths(root, declared_agents, "AGENT.md") if declared_agents else _find_markdown(os.path.join(root, "agents"))
        for path in agent_paths:
            items.append(_agent_entry(path, "plugin", plugin["identifier"], enabled, reason))
        command_root = os.path.join(root, "commands")
        declared_commands = plugin.get("declared_commands")
        command_paths = _declared_paths(root, declared_commands, "COMMAND.md") if declared_commands else _find_markdown(command_root)
        for path in command_paths:
            items.append(_command_entry(path, command_root if path.startswith(command_root) else root, "plugin", plugin["identifier"], enabled, reason, prefix=plugin["name"]))

    recorded_md = set()
    user_md = os.path.join(claude_home, "CLAUDE.md")
    if fsutil.exists(user_md):
        items.append(_claude_md_entry(user_md, "user", True, "user memory file, loaded verbatim at the start of every session"))
        recorded_md.add(user_md)
    for path in _ancestor_claude_md(cwd, home):
        if path in recorded_md:
            continue
        scope = "project" if os.path.dirname(path) == cwd else "ancestor"
        reason = "in the current directory" if scope == "project" else "ancestor of the current directory, loaded as project memory"
        items.append(_claude_md_entry(path, scope, True, reason))
        recorded_md.add(path)
    for root in project_roots[1:]:
        candidate = os.path.join(root, "CLAUDE.md")
        if fsutil.exists(candidate) and candidate not in recorded_md:
            items.append(_claude_md_entry(candidate, "project", False, "belongs to %s, which is not the current directory" % fsutil.tilde(root)))
            recorded_md.add(candidate)
    for plugin in plugin_entries:
        root = plugin.get("_root")
        candidate = os.path.join(root, "CLAUDE.md") if root else None
        if candidate and fsutil.exists(candidate) and candidate not in recorded_md:
            items.append(_claude_md_entry(candidate, "plugin", False, "plugin repository memory file; not loaded as user or project memory"))
            recorded_md.add(candidate)

    mcp_servers = _mcp_servers(project_roots, settings_by_scope, cwd)
    items.extend(mcp_servers)
    hooks = _hooks(settings_by_scope)

    comparable = [item for item in items if item["kind"] in ("skill", "agent", "command") and item.get("purpose_declared")]
    token_map = {index: _tokens("%s %s" % (item["name"], item["purpose"])) for index, item in enumerate(comparable)}
    for index, item in enumerate(comparable):
        candidates = []
        for other_index, other in enumerate(comparable):
            if other_index == index:
                continue
            score, shared = _similarity(token_map[index], token_map[other_index])
            if score >= 0.22 and len(shared) >= 3:
                candidates.append({
                    "name": other["name"],
                    "kind": other["kind"],
                    "scope": other["scope"],
                    "score": score,
                    "shared_terms": shared[:12],
                    "evidence": "%d shared domain terms between the two declared purposes" % len(shared),
                })
        item["overlap_candidates"] = sorted(candidates, key=lambda entry: (-entry["score"], entry["name"]))[:5]
    for item in items:
        item.setdefault("overlap_candidates", [])

    startup_total = 0
    per_item = []
    unmeasured = []
    for item in sorted([entry for entry in items if entry.get("active")], key=lambda entry: -((entry["context_cost"].get("always_loaded_bytes") or 0))):
        always = item["context_cost"].get("always_loaded_bytes")
        if always is None:
            unmeasured.append({"name": item["name"], "kind": item["kind"], "reason": item["context_cost"].get("measurement_note")})
            continue
        startup_total += always
        if always:
            per_item.append({
                "name": item["name"],
                "kind": item["kind"],
                "scope": item["scope"],
                "always_loaded_bytes": always,
                "always_loaded_tokens_estimate": always // 4,
            })
    on_demand_total = sum((item["context_cost"].get("on_demand_bytes") or 0) for item in items)

    by_kind = {}
    for item in items:
        bucket = by_kind.setdefault(item["kind"], {"total": 0, "active": 0, "always_loaded_bytes": 0, "always_loaded_tokens_estimate": 0})
        bucket["total"] += 1
        if item.get("active"):
            bucket["active"] += 1
            bucket["always_loaded_bytes"] += item["context_cost"].get("always_loaded_bytes") or 0
            bucket["always_loaded_tokens_estimate"] = bucket["always_loaded_bytes"] // 4

    name_index = {}
    for item in items:
        if item["kind"] in ("skill", "agent", "command"):
            name_index.setdefault((item["kind"], item["name"]), []).append(item)
    collisions = []
    for (kind, name), group in sorted(name_index.items()):
        if len(group) > 1:
            collisions.append({
                "kind": kind,
                "name": name,
                "definitions": [{"scope": item["scope"], "scope_detail": item.get("scope_detail"), "path": item["path"], "active": item["active"]} for item in group],
            })

    vague = []
    for item in items:
        if item["kind"] != "skill":
            continue
        description = item["purpose"] if item["purpose_declared"] else ""
        reasons = []
        if not item["purpose_declared"]:
            reasons.append("no description declared in the frontmatter")
        else:
            if len(description) < VAGUE_MINIMUM_CHARS:
                reasons.append("description is only %d characters" % len(description))
            if not any(hint in description.lower() for hint in TRIGGER_HINTS):
                reasons.append("description states what it is but never states when to use it")
        if reasons:
            vague.append({"name": item["name"], "scope": item["scope"], "path": item["path"], "active": item["active"], "description": description or None, "reasons": reasons})

    mcp_native = []
    for server in mcp_servers:
        lowered = server["name"].lower()
        for keyword in sorted(NATIVE_CAPABILITIES):
            if keyword in lowered:
                mcp_native.append({
                    "server": server["name"],
                    "scope": server["scope"],
                    "active": server["active"],
                    "native_equivalent": list(NATIVE_CAPABILITIES[keyword]),
                    "evidence": "server name contains '%s', naming a capability Claude Code already provides natively" % keyword,
                })
                break

    always_on_hooks = [hook for hook in hooks if hook["matcher_is_wildcard"]]
    hook_events = {}
    for hook in hooks:
        hook_events[hook["event"]] = hook_events.get(hook["event"], 0) + 1

    permissions = _permissions(settings_by_scope)
    overrides = _overridden_settings(settings_by_scope)

    skill_tokens = {item["name"]: _tokens(item["purpose"]) for item in items if item["kind"] == "skill" and item["purpose_declared"] and item["active"]}
    claude_md_overlap = []
    for item in items:
        if item["kind"] != "claude_md" or not item["active"]:
            continue
        md_tokens = _tokens(fsutil.read_text(os.path.expanduser(item["path"])) or "")
        for skill_name in sorted(skill_tokens):
            score, shared = _similarity(md_tokens, skill_tokens[skill_name])
            if score >= 0.12 and len(shared) >= 5:
                claude_md_overlap.append({
                    "claude_md": item["path"],
                    "skill": skill_name,
                    "score": score,
                    "shared_terms": shared[:12],
                    "evidence": "%d domain terms appear in both the memory file and the skill description" % len(shared),
                })

    inventory = {
        "installation": {
            "user_directory": "~/.claude",
            "user_directory_present": fsutil.exists(claude_home),
            "subdirectories": [name for name in fsutil.listdir(claude_home) if os.path.isdir(os.path.join(claude_home, name))],
            "settings_files": [
                {"scope": scope, "path": entry["path"], "status": entry.get("status"), "bytes": entry.get("bytes"), "keys": entry.get("keys")}
                for scope, entry in sorted(settings_by_scope.items())
            ],
            "project_roots_inspected": [fsutil.tilde(root) for root in project_roots],
        },
        "plugins": plugin_summary,
        "skills": [item for item in items if item["kind"] == "skill"],
        "agents": [item for item in items if item["kind"] == "agent"],
        "commands": [item for item in items if item["kind"] == "command"],
        "claude_md_files": [item for item in items if item["kind"] == "claude_md"],
        "mcp_servers": mcp_servers,
        "hooks": hooks,
        "permissions": permissions,
        "settings_overrides": overrides,
        "extra_tools": _extra_tools(cwd),
    }

    context_budget = {
        "session_startup_bytes": startup_total,
        "session_startup_tokens_estimate": startup_total // 4,
        "on_demand_bytes_total": on_demand_total,
        "on_demand_tokens_estimate": on_demand_total // 4,
        "per_item_always_loaded": per_item,
        "by_kind": dict(sorted(by_kind.items())),
        "unmeasurable": unmeasured,
        "method": "always-loaded counts in-scope CLAUDE.md bodies, skill name plus description frontmatter, agent name plus description, and command name plus description; on-demand counts skill and command bodies plus bundled reference files; tokens are estimated as bytes divided by four",
    }

    analysis = {
        "duplicate_name_collisions": collisions,
        "vague_skill_descriptions": vague,
        "mcp_servers_duplicating_native_capability": mcp_native,
        "hooks_firing_on_every_event": always_on_hooks,
        "hook_event_counts": dict(sorted(hook_events.items())),
        "dead_permission_rules": permissions["dead_rules"],
        "claude_md_duplicating_skills": claude_md_overlap,
    }

    findings = []
    if startup_total:
        findings.append(F.finding(
            "claude_code",
            "warning" if startup_total // 4 > 12000 else "info",
            "Session startup context is about %d tokens" % (startup_total // 4),
            "%s always-loaded across %d active items; largest: %s" % (
                fsutil.human_bytes(startup_total),
                len(per_item),
                ", ".join("%s (%d tokens)" % (entry["name"], entry["always_loaded_tokens_estimate"]) for entry in per_item[:5]),
            ),
            "Everything always-loaded is paid for on every request in the session, before any work begins, and it competes with the code you actually want in context.",
            "Review the per-item startup table and disable what is not earning its place",
            True,
            key="startup-tokens",
        ))
    for collision in collisions:
        findings.append(F.finding(
            "claude_code",
            "warning",
            "Duplicate %s name across scopes: %s" % (collision["kind"], collision["name"]),
            "; ".join("%s at %s" % (item["scope"], item["path"]) for item in collision["definitions"]),
            "When two definitions share a name only one can win, and which one that is depends on scope precedence rather than on intent.",
            "Rename one of the definitions, or remove the copy you no longer use",
            True,
            key="collision-%s-%s" % (collision["kind"], collision["name"]),
        ))
    for entry in vague:
        if entry["active"]:
            findings.append(F.finding(
                "claude_code",
                "info",
                "Skill description will not trigger reliably: %s" % entry["name"],
                "%s: %s" % (entry["path"], "; ".join(entry["reasons"])),
                "A skill is selected from its description alone, so a description that omits the triggering situation is paid for at startup but rarely invoked.",
                "Rewrite the description to state the situations that should invoke it, in the form 'Use when ...'",
                True,
                key="vague-%s-%s" % (entry["scope"], entry["name"]),
            ))
    for entry in mcp_native:
        findings.append(F.finding(
            "claude_code",
            "warning" if entry["active"] else "info",
            "MCP server %s overlaps a native capability" % entry["server"],
            "%s; native equivalent: %s" % (entry["evidence"], ", ".join(entry["native_equivalent"])),
            "Every enabled MCP server injects its tool schemas into the prompt on every request, so duplicating a built-in tool pays that cost for no new capability.",
            "claude mcp remove %s   # or disable it for this project" % entry["server"],
            True,
            key="mcp-native-%s" % entry["server"],
        ))
    if always_on_hooks:
        findings.append(F.finding(
            "claude_code",
            "warning",
            "%d hooks fire on every occurrence of their event without a filter" % len(always_on_hooks),
            "; ".join("%s (%s) from %s" % (hook["event"], hook["matcher"], hook["source"]) for hook in always_on_hooks[:6]),
            "An unfiltered hook runs a subprocess every time the event occurs, adding latency to each tool call and each session start.",
            "Add a matcher so the hook only runs for the tools or events it actually needs",
            True,
            key="wildcard-hooks",
        ))
    for dead in permissions["dead_rules"]:
        findings.append(F.finding(
            "claude_code",
            "info",
            "Permission rule is unreachable: %s" % dead["rule"],
            "%s in %s is already covered by %s" % (dead["rule"], dead["source"], dead["covered_by"]),
            "A rule that a broader rule already covers never changes an outcome, so it makes the permission set look more precise than it is.",
            "Remove the redundant rule from %s" % dead["source"],
            True,
            key="dead-rule-%s-%s" % (dead["bucket"], dead["rule"]),
        ))
    for overlap in claude_md_overlap:
        findings.append(F.finding(
            "claude_code",
            "info",
            "Memory file overlaps skill %s" % overlap["skill"],
            "%s shares %d domain terms with the skill description: %s" % (overlap["claude_md"], len(overlap["shared_terms"]), ", ".join(overlap["shared_terms"][:8])),
            "Instructions duplicated between an always-loaded memory file and an on-demand skill are paid for twice and drift apart over time.",
            "Keep the instruction in one place: the memory file if it always applies, the skill if it applies only sometimes",
            True,
            key="md-skill-%s-%s" % (overlap["claude_md"], overlap["skill"]),
        ))

    return {
        "status": "ok",
        "inventory": inventory,
        "context_budget": context_budget,
        "analysis": analysis,
        "findings": findings,
    }
