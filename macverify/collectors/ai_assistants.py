import os

from .. import aicommon
from .. import findings as F
from .. import fsutil
from ..context import default_context

INSTRUCTION_FILES = (
    ("claude_code", "CLAUDE.md", "CLAUDE.md"),
    ("openai_codex", "AGENTS.md", "AGENTS.md"),
    ("github_copilot", os.path.join(".github", "copilot-instructions.md"), ".github/copilot-instructions.md"),
)

OVERLAP_SCORE = 0.18

OVERLAP_MINIMUM_TERMS = 6

STRONG_OVERLAP_SCORE = 0.4


def _entry(tool, label, path, directory, active, active_reason):
    text = fsutil.read_text(path) or ""
    size = len(text.encode("utf-8"))
    return {
        "tool": tool,
        "label": label,
        "path": fsutil.tilde(path),
        "directory": fsutil.tilde(directory),
        "file_bytes": size,
        "line_count": len(text.splitlines()),
        "empty": not text.strip(),
        "active": active,
        "active_reason": active_reason,
        "heading_outline": aicommon.headings(text, limit=12),
        "context_cost": aicommon.cost(size if active else 0, 0 if active else size),
        "_tokens": aicommon.tokens(text),
        "_text": text,
    }


def collect(ctx=None):
    ctx = default_context(ctx)
    home = fsutil.home()
    cwd = os.path.abspath(ctx.cwd)
    roots = aicommon.project_roots(ctx)

    entries = []
    seen = set()
    for root in roots:
        for directory in aicommon.ancestors(root, home):
            for tool, relative, label in INSTRUCTION_FILES:
                path = os.path.join(directory, relative)
                if path in seen or not fsutil.exists(path):
                    continue
                seen.add(path)
                if directory == cwd:
                    active, reason = True, "in the current directory"
                elif cwd.startswith(directory.rstrip(os.sep) + os.sep):
                    active, reason = True, "ancestor of the current directory"
                else:
                    active, reason = False, "belongs to %s, which is not the current directory" % fsutil.tilde(directory)
                entries.append(_entry(tool, label, path, directory, active, reason))

    if not entries:
        return {
            "status": "unavailable",
            "reason": "no CLAUDE.md, AGENTS.md or .github/copilot-instructions.md found in the inspected project roots or their ancestors",
            "inventory": {},
            "analysis": {},
            "findings": [],
        }

    by_directory = {}
    for entry in entries:
        by_directory.setdefault(entry["directory"], []).append(entry)

    overlaps = []
    for directory in sorted(by_directory):
        group = by_directory[directory]
        if len(group) < 2:
            continue
        for index in range(len(group)):
            for other_index in range(index + 1, len(group)):
                left = group[index]
                right = group[other_index]
                score, shared = aicommon.similarity(left["_tokens"], right["_tokens"])
                union = len(left["_tokens"] | right["_tokens"])
                overlaps.append({
                    "directory": directory,
                    "left": {
                        "tool": left["tool"],
                        "file": left["label"],
                        "path": left["path"],
                        "bytes": left["file_bytes"],
                        "quoted_lines": aicommon.quote_lines(left["_text"], shared) or aicommon.quote_lines(left["_text"], left["_tokens"], limit=1),
                    },
                    "right": {
                        "tool": right["tool"],
                        "file": right["label"],
                        "path": right["path"],
                        "bytes": right["file_bytes"],
                        "quoted_lines": aicommon.quote_lines(right["_text"], shared) or aicommon.quote_lines(right["_text"], right["_tokens"], limit=1),
                    },
                    "score": score,
                    "shared_terms": shared[:16],
                    "shared_term_count": len(shared),
                    "above_reporting_threshold": score >= OVERLAP_SCORE and len(shared) >= OVERLAP_MINIMUM_TERMS,
                    "evidence": "%d of %d combined domain terms are shared (%s vocabulary overlap)" % (
                        len(shared), union, "{:.0%}".format(score)),
                })

    multi_tool_directories = []
    for directory in sorted(by_directory):
        group = by_directory[directory]
        tools = sorted({entry["tool"] for entry in group})
        if len(tools) < 2:
            continue
        pairs = [item for item in overlaps if item["directory"] == directory]
        multi_tool_directories.append({
            "directory": directory,
            "tools": tools,
            "files": [{"tool": entry["tool"], "file": entry["label"], "path": entry["path"], "bytes": entry["file_bytes"], "active": entry["active"], "empty": entry["empty"]} for entry in group],
            "total_bytes": sum(entry["file_bytes"] for entry in group),
            "active_bytes": sum(entry["file_bytes"] for entry in group if entry["active"]),
            "pairwise_similarity": [
                {"files": "%s vs %s" % (item["left"]["file"], item["right"]["file"]), "score": item["score"],
                 "shared_term_count": item["shared_term_count"], "above_reporting_threshold": item["above_reporting_threshold"]}
                for item in sorted(pairs, key=lambda entry: -entry["score"])
            ],
            "highest_score": max([item["score"] for item in pairs] or [0.0]),
        })

    tools_present = sorted({entry["tool"] for entry in entries})
    active_entries = [entry for entry in entries if entry["active"]]
    per_tool = {}
    for entry in entries:
        bucket = per_tool.setdefault(entry["tool"], {"files": 0, "active": 0, "bytes": 0, "active_bytes": 0})
        bucket["files"] += 1
        bucket["bytes"] += entry["file_bytes"]
        if entry["active"]:
            bucket["active"] += 1
            bucket["active_bytes"] += entry["file_bytes"]
    for bucket in per_tool.values():
        bucket["active_tokens_estimate"] = bucket["active_bytes"] // 4

    public = []
    for entry in entries:
        clean = {key: value for key, value in entry.items() if not key.startswith("_")}
        public.append(clean)

    inventory = {
        "tools_with_instruction_files": tools_present,
        "instruction_files": sorted(public, key=lambda item: (item["directory"], item["label"])),
        "directories_with_more_than_one_tool": multi_tool_directories,
        "per_tool": dict(sorted(per_tool.items())),
        "project_roots_inspected": [fsutil.tilde(root) for root in roots],
    }

    analysis = {
        "instruction_file_count": len(entries),
        "active_instruction_file_count": len(active_entries),
        "combined_active_bytes": sum(entry["file_bytes"] for entry in active_entries),
        "combined_active_tokens_estimate": sum(entry["file_bytes"] for entry in active_entries) // 4,
        "instruction_file_overlaps": overlaps,
        "method": "two instruction files in the same directory are compared by the Jaccard overlap of their content vocabularies after stopword removal; a finding is only raised when at least %d domain terms are shared, and every finding carries lines quoted from both files" % OVERLAP_MINIMUM_TERMS,
    }

    findings = []
    for entry in multi_tool_directories:
        pairs = [item for item in overlaps if item["directory"] == entry["directory"]]
        top = max(pairs, key=lambda item: item["score"]) if pairs else None
        crossing = [item for item in pairs if item["above_reporting_threshold"]]
        basis = []
        if top:
            for side in ("left", "right"):
                quotes = top[side]["quoted_lines"]
                if quotes:
                    basis.append('%s says "%s"' % (top[side]["file"], quotes[0]))
        scores = "; ".join("%s %s" % (item["files"], "{:.0%}".format(item["score"])) for item in entry["pairwise_similarity"])
        if crossing:
            severity = "warning" if entry["highest_score"] >= STRONG_OVERLAP_SCORE else "info"
            matters = "The same conventions maintained in two instruction files are loaded separately by each assistant and drift apart, so the two tools end up working to different versions of the same rule."
            action = "Keep the shared rules in one file and have the others point at it, or split them so each file states only what is specific to its assistant"
        else:
            severity = "info"
            matters = "Separate instruction files per assistant are only a problem when they drift; here they describe different things, so the cost is maintaining several files rather than contradicting guidance."
            action = "Decide which file is authoritative for shared conventions, and have the others reference it rather than restate it"
        findings.append(F.finding(
            "ai_assistants",
            severity,
            "%s carries instruction files for %d assistants" % (entry["directory"], len(entry["tools"])),
            "%s. Vocabulary overlap: %s. %s" % (
                ", ".join("%s (%s, %s)" % (item["file"], item["tool"], fsutil.human_bytes(item["bytes"])) for item in entry["files"]),
                scores or "not comparable",
                " ".join(basis) if basis else "no quotable content in either file",
            ),
            matters,
            action,
            True,
            key="multi-tool-%s" % entry["directory"],
        ))

    return {
        "status": "ok",
        "inventory": inventory,
        "analysis": analysis,
        "findings": findings,
    }
