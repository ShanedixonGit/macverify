import os
import re

from .. import aicommon
from .. import findings as F
from .. import fsutil
from ..context import default_context

CODEX_HOME = "~/.codex"

CONFIG_NAME = "config.toml"

LEGACY_CONFIG_NAMES = ("config.json", "config.yaml", "config.yml")

AGENTS_FILENAME = "AGENTS.md"

SESSION_DIRS = ("sessions", "history", "archived_sessions")

APPROVAL_KEYS = ("approval_policy", "approvalMode", "approval_mode", "ask_for_approval")

SANDBOX_KEYS = ("sandbox_mode", "sandbox", "sandbox_permissions", "sandboxMode")

PERMISSIVE_APPROVALS = {"never", "full-auto", "full_auto", "auto", "on-failure", "yolo"}

PERMISSIVE_SANDBOXES = {"danger-full-access", "danger_full_access", "disabled", "none", "off"}

SCALAR = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$')

SECTION = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*$")


def _scalar(raw):
    text = raw.strip()
    if text.startswith("#"):
        return None
    inline = re.match(r'^("(?:[^"\\]|\\.)*"|\'[^\']*\')\s*(?:#.*)?$', text)
    if inline:
        quoted = inline.group(1)
        return quoted[1:-1]
    if text.startswith("["):
        body = text[1:text.rfind("]")] if "]" in text else text[1:]
        return [part.strip().strip("\"'") for part in body.split(",") if part.strip()]
    text = text.split("#", 1)[0].strip()
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text.strip("\"'")


def _parse_toml(text):
    tables = {"": {}}
    current = ""
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        section = SECTION.match(stripped)
        if section:
            current = section.group(1).strip().replace('"', "").replace("'", "")
            tables.setdefault(current, {})
            continue
        match = SCALAR.match(stripped)
        if not match:
            continue
        value = _scalar(match.group(2))
        if value is None:
            continue
        tables.setdefault(current, {})[match.group(1)] = value
    return tables


def _read_config(path):
    text = fsutil.read_text(path)
    if text is None:
        return None, "unreadable: %s" % fsutil.tilde(path)
    return _parse_toml(text), None


def _lookup(tables, keys, table=""):
    for key in keys:
        if key in (tables.get(table) or {}):
            return key, (tables.get(table) or {})[key]
    return None, None


def _agents_entry(path, scope, active, active_reason):
    text = fsutil.read_text(path) or ""
    size = len(text.encode("utf-8"))
    first_line = next((line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    return {
        "kind": "agents_md",
        "name": fsutil.tilde(path),
        "scope": scope,
        "scope_detail": fsutil.tilde(os.path.dirname(path)),
        "path": fsutil.tilde(path),
        "purpose": first_line[:200] if first_line else "undeclared",
        "purpose_declared": bool(first_line),
        "active": active,
        "active_reason": active_reason,
        "file_bytes": size,
        "empty": not text.strip(),
        "heading_outline": aicommon.headings(text),
        "context_cost": aicommon.cost(size if active else 0, 0 if active else size),
        "overlap_candidates": [],
    }


def _mcp_entry(name, config, source):
    config = config or {}
    command = config.get("command")
    args = config.get("args")
    if isinstance(args, list):
        rendered = " ".join([str(command or "")] + [str(item) for item in args]).strip()
    else:
        rendered = str(command or "").strip()
    url = config.get("url")
    return {
        "kind": "mcp_server",
        "name": name,
        "scope": "user",
        "source": source,
        "transport": "http" if url else "stdio",
        "endpoint": url or rendered or None,
        "purpose": config.get("description") or "undeclared",
        "purpose_declared": bool(config.get("description")),
        "active": True,
        "active_reason": "declared in the Codex configuration, which loads it for every Codex session",
        "startup_timeout_ms": config.get("startup_timeout_ms"),
        "tool_count_note": "tool definitions are only available by starting the server, which this audit never does",
        "context_cost": aicommon.no_cost("an enabled MCP server injects its tool schemas into every request; the size cannot be measured without connecting to the server"),
        "overlap_candidates": [],
    }


def _sessions(codex_home):
    summary = []
    for name in SESSION_DIRS:
        directory = os.path.join(codex_home, name)
        if not fsutil.exists(directory):
            continue
        count = 0
        total = 0
        newest = None
        oldest = None
        stack = [directory]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                                continue
                            info = entry.stat(follow_symlinks=False)
                        except (OSError, ValueError):
                            continue
                        count += 1
                        total += int(info.st_size)
                        stamp = info.st_mtime
                        newest = stamp if newest is None or stamp > newest else newest
                        oldest = stamp if oldest is None or stamp < oldest else oldest
            except (OSError, ValueError):
                continue
        summary.append({
            "directory": fsutil.tilde(directory),
            "file_count": count,
            "total_bytes": total,
            "total_human": fsutil.human_bytes(total),
            "newest_modified": fsutil.iso_time(newest),
            "oldest_modified": fsutil.iso_time(oldest),
            "content_policy": "file presence, size and timestamps only; no session transcript is opened or read",
        })
    return summary


def collect(ctx=None):
    ctx = default_context(ctx)
    home = fsutil.home()
    cwd = os.path.abspath(ctx.cwd)
    codex_home = os.path.expanduser(CODEX_HOME)
    roots = aicommon.project_roots(ctx)

    agents = []
    seen_paths = set()
    for root in roots:
        for directory in aicommon.ancestors(root, home):
            path = os.path.join(directory, AGENTS_FILENAME)
            if path in seen_paths or not fsutil.exists(path):
                continue
            seen_paths.add(path)
            if directory == cwd:
                scope, active, reason = "project", True, "in the current directory, loaded into every Codex session started here"
            elif cwd == directory or cwd.startswith(directory.rstrip(os.sep) + os.sep):
                scope, active, reason = "ancestor", True, "ancestor of the current directory; Codex merges AGENTS.md files up the tree"
            else:
                scope, active, reason = "project", False, "belongs to %s, which is not the current directory" % fsutil.tilde(directory)
            agents.append(_agents_entry(path, scope, active, reason))
    codex_agents = os.path.join(codex_home, AGENTS_FILENAME)
    if fsutil.exists(codex_agents) and codex_agents not in seen_paths:
        seen_paths.add(codex_agents)
        agents.append(_agents_entry(codex_agents, "user", True, "global Codex instructions, loaded in every session"))

    codex_present = fsutil.exists(codex_home)
    if not codex_present and not agents:
        return {
            "status": "unavailable",
            "reason": "no OpenAI Codex configuration found: no %s directory and no AGENTS.md in the inspected project roots" % fsutil.tilde(codex_home),
            "inventory": {},
            "context_budget": {},
            "analysis": {},
            "findings": [],
        }

    config_path = os.path.join(codex_home, CONFIG_NAME)
    config_tables = {}
    config_status = "absent"
    config_reason = "no %s" % fsutil.tilde(config_path)
    if fsutil.exists(config_path):
        parsed, reason = _read_config(config_path)
        if parsed is None:
            config_status, config_reason = "unavailable", reason
        else:
            config_tables, config_status, config_reason = parsed, "ok", None

    legacy_configs = [
        {"path": fsutil.tilde(os.path.join(codex_home, name)), "bytes": fsutil.file_size(os.path.join(codex_home, name))}
        for name in LEGACY_CONFIG_NAMES if fsutil.exists(os.path.join(codex_home, name))
    ]

    approval_key, approval_value = _lookup(config_tables, APPROVAL_KEYS)
    sandbox_key, sandbox_value = _lookup(config_tables, SANDBOX_KEYS)
    root_table = config_tables.get("") or {}

    mcp_servers = []
    for table_name in sorted(config_tables):
        if not table_name.startswith("mcp_servers."):
            continue
        name = table_name.split(".", 1)[1]
        mcp_servers.append(_mcp_entry(name, config_tables[table_name], fsutil.tilde(config_path)))
    for name, config in sorted((config_tables.get("mcp_servers") or {}).items()):
        if isinstance(config, dict):
            mcp_servers.append(_mcp_entry(name, config, fsutil.tilde(config_path)))

    sessions = _sessions(codex_home)

    subdirectories = [name for name in fsutil.listdir(codex_home) if os.path.isdir(os.path.join(codex_home, name))] if codex_present else []
    top_files = []
    if codex_present:
        for name in fsutil.listdir(codex_home):
            full = os.path.join(codex_home, name)
            if os.path.isdir(full):
                continue
            st = fsutil.stat(full)
            top_files.append({
                "name": name,
                "bytes": fsutil.file_size(full),
                "mode": fsutil.mode_string(st),
                "modified": fsutil.modified_at(st),
            })

    items = agents + mcp_servers
    comparable = [item for item in items if item.get("purpose_declared")]
    token_map = {index: aicommon.tokens("%s %s" % (item["name"], item["purpose"])) for index, item in enumerate(comparable)}
    for index, item in enumerate(comparable):
        candidates = []
        for other_index, other in enumerate(comparable):
            if other_index == index:
                continue
            score, shared = aicommon.similarity(token_map[index], token_map[other_index])
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

    startup_total = sum((item["context_cost"].get("always_loaded_bytes") or 0) for item in agents if item.get("active"))
    on_demand_total = sum((item["context_cost"].get("on_demand_bytes") or 0) for item in agents)

    inventory = {
        "installation": {
            "codex_directory": fsutil.tilde(codex_home),
            "codex_directory_present": codex_present,
            "subdirectories": subdirectories,
            "files": sorted(top_files, key=lambda item: item["name"]),
            "legacy_config_files": legacy_configs,
            "project_roots_inspected": [fsutil.tilde(root) for root in roots],
        },
        "configuration": {
            "path": fsutil.tilde(config_path),
            "status": config_status,
            "reason": config_reason,
            "model": root_table.get("model"),
            "model_provider": root_table.get("model_provider"),
            "approval": {"key": approval_key, "value": approval_value},
            "sandbox": {"key": sandbox_key, "value": sandbox_value},
            "tables": sorted(name for name in config_tables if name),
            "root_keys": sorted(root_table),
        },
        "agents_md_files": agents,
        "mcp_servers": sorted(mcp_servers, key=lambda item: item["name"]),
        "sessions": sessions,
    }

    context_budget = {
        "session_startup_bytes": startup_total,
        "session_startup_tokens_estimate": startup_total // 4,
        "on_demand_bytes_total": on_demand_total,
        "on_demand_tokens_estimate": on_demand_total // 4,
        "unmeasurable": [
            {"name": server["name"], "kind": server["kind"], "reason": server["context_cost"].get("measurement_note")}
            for server in mcp_servers
        ],
        "method": "always-loaded counts the bytes of every in-scope AGENTS.md, which Codex loads as session instructions; configuration files, session records and MCP schemas have no measurable on-disk prompt cost and are reported as n/a",
    }

    session_total = sum(entry["file_count"] for entry in sessions)
    analysis = {
        "agents_md_found": len(agents),
        "empty_agents_md": [item["path"] for item in agents if item["empty"]],
        "session_file_count": session_total,
        "session_bytes": sum(entry["total_bytes"] for entry in sessions),
        "approval_is_permissive": str(approval_value).lower() in PERMISSIVE_APPROVALS if approval_value is not None else None,
        "sandbox_is_permissive": str(sandbox_value).lower() in PERMISSIVE_SANDBOXES if sandbox_value is not None else None,
    }

    findings = []
    if startup_total:
        findings.append(F.finding(
            "openai_codex",
            "info",
            "AGENTS.md instructions add about %d tokens to every Codex session" % (startup_total // 4),
            "%s across %d in-scope file(s): %s" % (
                fsutil.human_bytes(startup_total),
                len([item for item in agents if item["active"]]),
                ", ".join(item["path"] for item in agents if item["active"]),
            ),
            "Codex merges every AGENTS.md from the working directory up the tree into the session prompt, so the whole body is paid for before any work begins.",
            "Keep AGENTS.md to the rules that change Codex's behaviour and move reference material into files it can open on demand",
            True,
            key="codex-startup-tokens",
        ))
    if analysis["approval_is_permissive"]:
        findings.append(F.finding(
            "openai_codex",
            "warning",
            "Codex approval policy is set to %s" % approval_value,
            "%s = %s in %s" % (approval_key, approval_value, fsutil.tilde(config_path)),
            "A permissive approval policy lets Codex run commands and edit files without asking, so a mistaken or injected instruction applies before it can be reviewed.",
            "Set %s to a policy that prompts before commands run, in %s" % (approval_key, fsutil.tilde(config_path)),
            True,
            key="codex-approval",
        ))
    if analysis["sandbox_is_permissive"]:
        findings.append(F.finding(
            "openai_codex",
            "warning",
            "Codex sandbox is set to %s" % sandbox_value,
            "%s = %s in %s" % (sandbox_key, sandbox_value, fsutil.tilde(config_path)),
            "With the sandbox disabled Codex writes and executes outside the workspace, so a bad edit is not contained to the project it was working on.",
            "Set %s back to a workspace-scoped sandbox in %s" % (sandbox_key, fsutil.tilde(config_path)),
            True,
            key="codex-sandbox",
        ))
    for item in agents:
        if item["empty"]:
            findings.append(F.finding(
                "openai_codex",
                "info",
                "AGENTS.md is empty: %s" % item["path"],
                "%s is %d bytes with no content" % (item["path"], item["file_bytes"]),
                "An empty AGENTS.md reads as configured intent that Codex cannot act on, and hides the fact that no guidance is in force.",
                "Write the rules the file was created for, or delete it",
                True,
                key="codex-empty-%s" % item["path"],
            ))
    if session_total:
        findings.append(F.finding(
            "openai_codex",
            "info",
            "Codex has %d stored session file(s) on disk" % session_total,
            "; ".join("%s: %d files, %s, newest %s" % (
                entry["directory"], entry["file_count"], entry["total_human"], entry["newest_modified"]) for entry in sessions),
            "Session records hold the prompts, file contents and command output of past runs in plain files under the home directory, and they are covered by any backup or sync that includes it.",
            "Review what the session directory retains and prune it if old transcripts are not needed",
            True,
            key="codex-sessions",
        ))

    return {
        "status": "ok",
        "inventory": inventory,
        "context_budget": context_budget,
        "analysis": analysis,
        "findings": findings,
    }
