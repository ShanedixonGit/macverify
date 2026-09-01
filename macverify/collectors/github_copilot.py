import os

from .. import aicommon
from .. import findings as F
from .. import fsutil
from ..context import default_context

INSTRUCTION_RELATIVE = os.path.join(".github", "copilot-instructions.md")

VSCODE_USER_SETTINGS = (
    ("Code", "~/Library/Application Support/Code/User/settings.json"),
    ("Code - Insiders", "~/Library/Application Support/Code - Insiders/User/settings.json"),
)

EXTENSION_ROOTS = (
    ("~/.vscode/extensions", "VS Code"),
    ("~/.vscode-insiders/extensions", "VS Code Insiders"),
)

COPILOT_EXTENSION_PREFIX = "github.copilot"

JETBRAINS_ROOT = "~/Library/Application Support/JetBrains"

JETBRAINS_PLUGIN_NAMES = ("github-copilot-intellij", "copilot-intellij", "github-copilot")

COPILOT_SETTING_PREFIXES = ("github.copilot", "copilot", "chat.", "inlineChat.")

TELEMETRY_KEYS = ("github.copilot.advanced", "telemetry.telemetryLevel")


def _instruction_entry(path, scope, active, active_reason):
    text = fsutil.read_text(path) or ""
    size = len(text.encode("utf-8"))
    body = text.strip()
    first_line = next((line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    return {
        "kind": "copilot_instructions",
        "name": fsutil.tilde(path),
        "scope": scope,
        "scope_detail": fsutil.tilde(os.path.dirname(os.path.dirname(path))),
        "path": fsutil.tilde(path),
        "purpose": first_line[:200] if first_line else "undeclared",
        "purpose_declared": bool(first_line),
        "active": active,
        "active_reason": active_reason,
        "file_bytes": size,
        "empty": not body,
        "heading_outline": aicommon.headings(text),
        "context_cost": aicommon.cost(size if active else 0, 0 if active else size),
        "overlap_candidates": [],
    }


def _copilot_keys(data, prefixes=COPILOT_SETTING_PREFIXES):
    found = {}
    for key in sorted(data or {}):
        lowered = str(key).lower()
        if any(lowered.startswith(prefix.lower()) for prefix in prefixes):
            value = data[key]
            if isinstance(value, (dict, list)):
                found[key] = "%s with %d entries" % (type(value).__name__, len(value))
            else:
                found[key] = value
    return found


def _settings_entry(label, path, scope):
    if not fsutil.exists(path):
        return None
    payload, reason = fsutil.read_json(path)
    if payload is None:
        return {
            "kind": "copilot_settings",
            "name": label,
            "scope": scope,
            "path": fsutil.tilde(path),
            "status": "unavailable",
            "reason": reason,
            "copilot_keys": {},
            "copilot_key_count": 0,
            "purpose": "editor settings file could not be parsed",
            "purpose_declared": False,
            "active": False,
            "active_reason": reason,
            "context_cost": aicommon.no_cost("editor settings are read by the extension, not loaded into a model prompt"),
            "overlap_candidates": [],
        }
    keys = _copilot_keys(payload)
    return {
        "kind": "copilot_settings",
        "name": label,
        "scope": scope,
        "path": fsutil.tilde(path),
        "status": "ok",
        "bytes": fsutil.file_size(path),
        "copilot_keys": keys,
        "copilot_key_count": len(keys),
        "purpose": "%d Copilot-prefixed setting(s)" % len(keys) if keys else "no Copilot-prefixed settings",
        "purpose_declared": bool(keys),
        "active": bool(keys),
        "active_reason": "settings file present and readable",
        "context_cost": aicommon.no_cost("editor settings are read by the extension, not loaded into a model prompt"),
        "overlap_candidates": [],
    }


def _extensions():
    installed = []
    for pattern, label in EXTENSION_ROOTS:
        root = os.path.expanduser(pattern)
        if not fsutil.exists(root):
            continue
        for name in fsutil.listdir(root):
            if not name.lower().startswith(COPILOT_EXTENSION_PREFIX):
                continue
            full = os.path.join(root, name)
            if not os.path.isdir(full):
                continue
            identifier = name
            version = None
            parts = name.rsplit("-", 1)
            if len(parts) == 2 and parts[1][:1].isdigit():
                identifier, version = parts[0], parts[1]
            manifest, _ = fsutil.read_json(os.path.join(full, "package.json"))
            description = (manifest or {}).get("description")
            installed.append({
                "kind": "copilot_extension",
                "name": identifier,
                "scope": "editor",
                "scope_detail": label,
                "path": fsutil.tilde(full),
                "version": (manifest or {}).get("version") or version,
                "display_name": (manifest or {}).get("displayName"),
                "purpose": description if description else "undeclared",
                "purpose_declared": bool(description),
                "active": True,
                "active_reason": "installed in the %s extensions directory" % label,
                "context_cost": aicommon.no_cost("an editor extension has no session-startup prompt cost that can be measured from disk"),
                "overlap_candidates": [],
            })
    return sorted(installed, key=lambda item: (item["name"], item["scope_detail"]))


def _jetbrains():
    root = os.path.expanduser(JETBRAINS_ROOT)
    if not fsutil.exists(root):
        return {"status": "unavailable", "reason": "no JetBrains configuration directory at %s" % fsutil.tilde(root), "products": []}
    products = []
    for product in fsutil.listdir(root):
        product_dir = os.path.join(root, product)
        if not os.path.isdir(product_dir):
            continue
        hits = []
        plugins_dir = os.path.join(product_dir, "plugins")
        for name in fsutil.listdir(plugins_dir):
            if any(marker in name.lower() for marker in JETBRAINS_PLUGIN_NAMES):
                hits.append({"kind": "plugin", "path": fsutil.tilde(os.path.join(plugins_dir, name))})
        options_dir = os.path.join(product_dir, "options")
        for name in fsutil.listdir(options_dir):
            if "copilot" in name.lower():
                path = os.path.join(options_dir, name)
                hits.append({"kind": "options", "path": fsutil.tilde(path), "bytes": fsutil.file_size(path)})
        if hits:
            products.append({"product": product, "path": fsutil.tilde(product_dir), "copilot_artifacts": hits})
    if not products:
        return {"status": "ok", "reason": "JetBrains is installed but no Copilot plugin or configuration was found", "products": []}
    return {"status": "ok", "reason": None, "products": products}


def collect(ctx=None):
    ctx = default_context(ctx)
    home = fsutil.home()
    cwd = os.path.abspath(ctx.cwd)
    roots = aicommon.project_roots(ctx)

    instructions = []
    seen_paths = set()
    for root in roots:
        for directory in aicommon.ancestors(root, home):
            path = os.path.join(directory, INSTRUCTION_RELATIVE)
            if path in seen_paths or not fsutil.exists(path):
                continue
            seen_paths.add(path)
            if directory == cwd:
                scope, active, reason = "project", True, "in the current directory, loaded into every Copilot chat request here"
            elif cwd == directory or cwd.startswith(directory.rstrip(os.sep) + os.sep):
                scope, active, reason = "ancestor", True, "ancestor of the current directory; Copilot loads the nearest instructions file"
            else:
                scope, active, reason = "project", False, "belongs to %s, which is not the current directory" % fsutil.tilde(directory)
            instructions.append(_instruction_entry(path, scope, active, reason))

    settings = []
    for label, pattern in VSCODE_USER_SETTINGS:
        entry = _settings_entry(label, os.path.expanduser(pattern), "user")
        if entry:
            settings.append(entry)
    for root in roots:
        workspace = os.path.join(root, ".vscode", "settings.json")
        entry = _settings_entry("workspace %s" % fsutil.tilde(root), workspace, "workspace")
        if entry:
            settings.append(entry)

    extensions = _extensions()
    jetbrains = _jetbrains()

    editors_present = bool(settings) or bool(extensions)
    if not instructions and not editors_present and jetbrains["status"] == "unavailable":
        return {
            "status": "unavailable",
            "reason": "no GitHub Copilot configuration found: no .github/copilot-instructions.md in the inspected project roots, no VS Code settings or extensions directory, and no JetBrains configuration directory",
            "inventory": {},
            "context_budget": {},
            "analysis": {},
            "findings": [],
        }

    items = instructions + settings + extensions
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

    startup_total = sum((item["context_cost"].get("always_loaded_bytes") or 0) for item in instructions if item.get("active"))
    on_demand_total = sum((item["context_cost"].get("on_demand_bytes") or 0) for item in instructions)
    unmeasurable = [
        {"name": item["name"], "kind": item["kind"], "reason": item["context_cost"].get("measurement_note")}
        for item in settings + extensions
    ]

    telemetry = {}
    for entry in settings:
        for key, value in (entry.get("copilot_keys") or {}).items():
            if key in TELEMETRY_KEYS:
                telemetry.setdefault(entry["path"], {})[key] = value

    empty_instructions = [item for item in instructions if item["empty"]]
    duplicate_dirs = {}
    for item in instructions:
        duplicate_dirs.setdefault(item["scope_detail"], []).append(item)

    inventory = {
        "installation": {
            "vscode_user_settings_present": [entry["name"] for entry in settings if entry["scope"] == "user"],
            "vscode_extension_roots_present": [label for pattern, label in EXTENSION_ROOTS if fsutil.exists(os.path.expanduser(pattern))],
            "copilot_extensions_installed": len(extensions),
            "jetbrains_configuration_present": jetbrains["status"] == "ok",
            "project_roots_inspected": [fsutil.tilde(root) for root in roots],
        },
        "instruction_files": instructions,
        "editor_settings": settings,
        "extensions": extensions,
        "jetbrains": jetbrains,
    }

    context_budget = {
        "session_startup_bytes": startup_total,
        "session_startup_tokens_estimate": startup_total // 4,
        "on_demand_bytes_total": on_demand_total,
        "on_demand_tokens_estimate": on_demand_total // 4,
        "unmeasurable": unmeasurable,
        "method": "always-loaded counts the bytes of every in-scope .github/copilot-instructions.md, which Copilot prepends to each chat request; editor settings and extensions have no equivalent prompt-loading concept and are reported as n/a",
    }

    analysis = {
        "instruction_files_found": len(instructions),
        "empty_instruction_files": [item["path"] for item in empty_instructions],
        "telemetry_related_settings": telemetry,
        "copilot_settings_by_file": {entry["path"]: entry.get("copilot_key_count", 0) for entry in settings},
    }

    findings = []
    if startup_total:
        findings.append(F.finding(
            "github_copilot",
            "info",
            "Copilot instruction files add about %d tokens to every chat request" % (startup_total // 4),
            "%s across %d in-scope file(s): %s" % (
                fsutil.human_bytes(startup_total),
                len([item for item in instructions if item["active"]]),
                ", ".join(item["path"] for item in instructions if item["active"]),
            ),
            "Copilot prepends the nearest instructions file to every chat request, so its whole body is paid for on each turn whether or not it is relevant.",
            "Trim the instructions file to the rules that change Copilot's output, and move situational guidance into the prompt",
            True,
            key="copilot-startup-tokens",
        ))
    for item in empty_instructions:
        findings.append(F.finding(
            "github_copilot",
            "info",
            "Copilot instructions file is empty: %s" % item["path"],
            "%s is %d bytes with no content" % (item["path"], item["file_bytes"]),
            "An empty instructions file reads as configured intent that Copilot cannot act on, and hides the fact that no guidance is in force.",
            "Write the rules the file was created for, or delete it",
            True,
            key="copilot-empty-%s" % item["path"],
        ))
    for directory, group in sorted(duplicate_dirs.items()):
        if len(group) > 1:
            findings.append(F.finding(
                "github_copilot",
                "warning",
                "More than one Copilot instructions file resolves for %s" % directory,
                "; ".join("%s (%s)" % (item["path"], item["scope"]) for item in group),
                "Copilot loads the nearest instructions file, so the others are configuration that looks active but never applies.",
                "Keep one instructions file per repository and delete or merge the rest",
                True,
                key="copilot-duplicate-%s" % directory,
            ))
    if extensions and not instructions:
        findings.append(F.finding(
            "github_copilot",
            "info",
            "Copilot is installed but no instructions file is configured",
            "%d Copilot extension(s) installed (%s); no .github/copilot-instructions.md in any inspected project root" % (
                len(extensions), ", ".join(item["name"] for item in extensions)),
            "Without an instructions file Copilot has no project context beyond the open editor, so it repeats conventions the repository has already settled.",
            "Add .github/copilot-instructions.md stating the project's stack, conventions and things to avoid",
            True,
            key="copilot-no-instructions",
        ))

    return {
        "status": "ok",
        "inventory": inventory,
        "context_budget": context_budget,
        "analysis": analysis,
        "findings": findings,
    }
