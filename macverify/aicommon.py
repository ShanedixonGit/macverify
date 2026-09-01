import os
import re

from . import fsutil

STOPWORDS = {
    "the", "a", "an", "and", "or", "for", "with", "when", "use", "using", "used", "this", "that", "to", "of", "in",
    "on", "by", "is", "are", "be", "it", "its", "as", "at", "from", "into", "you", "your", "should", "can", "will",
    "any", "all", "not", "but", "if", "then", "than", "also", "via", "per", "up", "out", "over", "before", "after",
    "skill", "skills", "agent", "agents", "command", "commands", "claude", "code", "user", "users", "need", "needs",
    "have", "has", "was", "were", "there", "their", "them", "they", "what", "which", "who", "how", "why", "more",
}

NOT_APPLICABLE = "n/a"

MAX_ANCESTOR_DEPTH = 12


def tokens(text):
    words = re.findall(r"[a-z][a-z0-9_-]{2,}", (text or "").lower())
    return {word for word in words if word not in STOPWORDS}


def similarity(left, right):
    if not left or not right:
        return 0.0, []
    shared = left & right
    union = left | right
    if not union:
        return 0.0, []
    return round(len(shared) / float(len(union)), 3), sorted(shared)


def cost(always_bytes, on_demand_bytes):
    return {
        "always_loaded_bytes": always_bytes,
        "always_loaded_tokens_estimate": always_bytes // 4,
        "on_demand_bytes": on_demand_bytes,
        "on_demand_tokens_estimate": on_demand_bytes // 4,
    }


def no_cost(reason):
    return {
        "always_loaded_bytes": None,
        "always_loaded_tokens_estimate": NOT_APPLICABLE,
        "on_demand_bytes": None,
        "on_demand_tokens_estimate": NOT_APPLICABLE,
        "measurement_note": reason,
    }


def headings(body, limit=40):
    outline = []
    for line in (body or "").splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*$", line)
        if match:
            outline.append({"level": len(match.group(1)), "text": match.group(2)[:120]})
        if len(outline) >= limit:
            break
    return outline


def ancestors(start, home, include_home=True):
    chain = []
    current = os.path.abspath(start)
    while True:
        chain.append(current)
        parent = os.path.dirname(current)
        if parent == current or len(chain) >= MAX_ANCESTOR_DEPTH:
            break
        if current == home:
            break
        current = parent
    if include_home and home not in chain and fsutil.exists(home):
        chain.append(home)
    return chain


def project_roots(ctx):
    roots = []
    for root in [ctx.cwd] + list(ctx.projects):
        absolute = os.path.abspath(os.path.expanduser(root))
        if absolute not in roots:
            roots.append(absolute)
    return roots


def search_roots(ctx):
    home = fsutil.home()
    seen = []
    for root in project_roots(ctx):
        for candidate in ancestors(root, home):
            if candidate not in seen:
                seen.append(candidate)
    return seen


def quote_lines(text, terms, limit=2, width=160):
    if not text or not terms:
        return []
    wanted = set(terms)
    picked = []
    for line in text.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if len(stripped) < 20:
            continue
        if tokens(stripped) & wanted:
            picked.append(stripped[:width])
        if len(picked) >= limit:
            break
    return picked
