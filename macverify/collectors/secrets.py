import os
import re

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

MASK = "*" * 12
MAX_FILE_BYTES = 512 * 1024
MAX_CONFIG_FILES = 2500

VALUE_DETECTORS = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), "critical"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "critical"),
    ("slack_token", re.compile(r"\bxox[abporsu]-[A-Za-z0-9-]{10,}"), "critical"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "critical"),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"), "critical"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), "critical"),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical"),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "critical"),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    ("credentials_in_url", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@\"']+:[^/\s@\"']+@"), "critical"),
    ("json_web_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "warning"),
)

NAME_HINT = re.compile(
    r"(?i)(?:^|[_.-])(?:secret|token|passwd|password|pwd|apikey|api_key|access_key|secret_key|private_key|credential|credentials|auth|authorization|bearer|client_secret|session_key|signing_key|encryption_key|dsn)(?:$|[_.-])"
)

PLACEHOLDER = re.compile(
    r"^(?:|0|1|true|false|none|null|nil|yes|no|xxx+|changeme|placeholder|your[-_ ]?\w*|<[^>]*>|\.\.\.|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|~?/[^\s]*|\./[^\s]*|\$\(.*\)|`.*`)$",
    re.IGNORECASE,
)

ASSIGNMENT = re.compile(r"^\s*(?:export\s+|set\s+-[gxul]+\s+|setenv\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.+?)\s*$")

SHELL_PROFILES = (
    "~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin", "~/.zlogout",
    "~/.bash_profile", "~/.bashrc", "~/.bash_login", "~/.profile",
    "~/.config/fish/config.fish", "~/.kshrc", "~/.cshrc",
)

DIRECT_FILES = (
    "~/.env", "~/.env.local", "~/.envrc", "~/.netrc", "~/.authinfo",
    "~/.aws/credentials", "~/.aws/config",
    "~/.gitconfig", "~/.config/git/config", "~/.git-credentials",
)

SENSITIVE_MODE_FILES = ("~/.netrc", "~/.aws/credentials", "~/.git-credentials", "~/.env", "~/.authinfo")

SKIP_CONFIG_DIRS = {"node_modules", "Cache", "caches", "Caches", "logs", "log", "tmp", "blobs", "storage", "History", "GPUCache"}

TEXT_SUFFIXES = ("", ".env", ".conf", ".cfg", ".config", ".ini", ".json", ".yaml", ".yml", ".toml", ".txt", ".sh", ".bash", ".zsh", ".fish", ".properties", ".netrc", ".credentials", ".rc", ".secret", ".token", ".md")


def mask(value):
    if value is None:
        return None
    text = str(value)
    prefix = text[:4]
    return "%s%s" % (prefix, MASK)


def classify(name, value):
    text = value if value is not None else ""
    for detector, pattern, severity in VALUE_DETECTORS:
        match = pattern.search(text)
        if match:
            return detector, severity, mask(match.group(0))
    if name and NAME_HINT.search(name):
        stripped = text.strip().strip("\"'")
        if not stripped or PLACEHOLDER.match(stripped) or len(stripped) < 8:
            return None
        return "name_hint", "warning", mask(stripped)
    return None


def redact(name, value):
    verdict = classify(name, value)
    if verdict is None:
        return value
    return verdict[2]


def _scan_text(path, text, limit_lines=20000):
    hits = []
    for index, line in enumerate(text.splitlines(), start=1):
        if index > limit_lines:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        name = None
        value = stripped
        assignment = ASSIGNMENT.match(line)
        if assignment:
            name = assignment.group(1)
            value = assignment.group(2)
        verdict = classify(name, value)
        if verdict is None and name is None:
            verdict = classify(None, stripped)
        if verdict is None:
            continue
        detector, severity, masked = verdict
        hits.append({
            "path": fsutil.tilde(path),
            "line": index,
            "name": name or "(inline value)",
            "detector": detector,
            "severity": severity,
            "masked_prefix": masked,
        })
    return hits


def _scan_file(path):
    if not fsutil.exists(path):
        return []
    size = fsutil.file_size(path)
    if size is None or size > MAX_FILE_BYTES:
        return []
    text = fsutil.read_text(path, MAX_FILE_BYTES)
    if text is None:
        return []
    return _scan_text(path, text)


def _config_files(root):
    collected = []
    stack = [(root, 0)]
    seen = 0
    while stack:
        current, depth = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except (OSError, ValueError):
            continue
        for entry in entries:
            seen += 1
            if seen > MAX_CONFIG_FILES * 4 or len(collected) >= MAX_CONFIG_FILES:
                return sorted(collected)
            if entry.name in SKIP_CONFIG_DIRS:
                continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < 3:
                        stack.append((entry.path, depth + 1))
                    continue
                suffix = os.path.splitext(entry.name)[1].lower()
                if suffix not in TEXT_SUFFIXES:
                    continue
                info = entry.stat(follow_symlinks=False)
                if info.st_size > MAX_FILE_BYTES:
                    continue
                collected.append(entry.path)
            except (OSError, ValueError):
                continue
    return sorted(collected)


def _git_remotes(roots):
    remotes = []
    for root in roots:
        config_path = os.path.join(root, ".git", "config")
        text = fsutil.read_text(config_path)
        if text is None:
            continue
        current = None
        for index, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            section = re.match(r'^\[remote\s+"([^"]+)"\]', stripped)
            if section:
                current = section.group(1)
                continue
            if stripped.startswith("[") and not section:
                current = None
                continue
            url = re.match(r"^url\s*=\s*(.+)$", stripped)
            if url and current:
                raw = url.group(1).strip()
                verdict = classify("url", raw)
                remotes.append({
                    "repository": fsutil.tilde(root),
                    "remote": current,
                    "path": fsutil.tilde(config_path),
                    "line": index,
                    "embedded_credentials": verdict is not None and verdict[0] == "credentials_in_url",
                    "url": mask(raw) if verdict and verdict[0] == "credentials_in_url" else raw,
                })
    return sorted(remotes, key=lambda item: (item["repository"], item["remote"]))


def collect(ctx=None):
    ctx = default_context(ctx)
    home = fsutil.home()
    hits = []
    scanned = []
    skipped = []

    targets = []
    for pattern in SHELL_PROFILES + DIRECT_FILES:
        targets.append(os.path.expanduser(pattern))
    aws_dir = os.path.expanduser("~/.aws")
    if fsutil.exists(aws_dir):
        for entry in fsutil.listdir(aws_dir):
            targets.append(os.path.join(aws_dir, entry))
    config_root = os.path.expanduser("~/.config")
    config_files = _config_files(config_root) if fsutil.exists(config_root) else []
    targets.extend(config_files)

    seen_paths = set()
    for path in targets:
        real = os.path.abspath(path)
        if real in seen_paths:
            continue
        seen_paths.add(real)
        if not fsutil.exists(real):
            continue
        st = fsutil.stat(real)
        if st is None or not os.path.isfile(real):
            continue
        scanned.append(fsutil.tilde(real))
        try:
            hits.extend(_scan_file(real))
        except Exception as exc:
            skipped.append({"path": fsutil.tilde(real), "reason": exc.__class__.__name__})

    roots = [ctx.cwd] + list(ctx.projects)
    remotes = _git_remotes(sorted(set(roots)))

    permissions = []
    for pattern in SENSITIVE_MODE_FILES:
        path = os.path.expanduser(pattern)
        st = fsutil.stat(path)
        if st is None:
            continue
        mode = fsutil.mode_string(st)
        permissions.append({"path": fsutil.tilde(path), "mode": mode, "group_or_world_readable": bool(st.st_mode & 0o077)})

    hits = sorted(hits, key=lambda item: (item["path"], item["line"], item["name"]))
    by_detector = {}
    for hit in hits:
        by_detector[hit["detector"]] = by_detector.get(hit["detector"], 0) + 1

    result = {
        "status": "ok",
        "policy": "names, paths, line numbers and detector labels only; no secret value is read into the report, logged or transmitted",
        "files_scanned": len(scanned),
        "config_files_scanned": len(config_files),
        "scanned_paths": sorted(scanned)[:400],
        "match_count": len(hits),
        "matches_by_detector": dict(sorted(by_detector.items())),
        "matches": hits,
        "git_remotes": remotes,
        "sensitive_file_permissions": sorted(permissions, key=lambda item: item["path"]),
        "skipped": skipped,
    }

    findings = []
    for hit in hits:
        findings.append(F.finding(
            "secrets",
            hit["severity"],
            "Credential-shaped value in %s" % os.path.basename(hit["path"]),
            "%s:%s name=%s detector=%s prefix=%s" % (hit["path"], hit["line"], hit["name"], hit["detector"], hit["masked_prefix"]),
            "A credential stored in a plain file is readable by every process running as this user and is easy to leak through backups, screen shares and shell history.",
            "Move the value into the login keychain or a secrets manager and reference it at runtime; then rotate it",
            False,
            key="%s:%s:%s" % (hit["path"], hit["line"], hit["detector"]),
        ))

    for remote in remotes:
        if remote["embedded_credentials"]:
            findings.append(F.finding(
                "secrets",
                "critical",
                "Git remote URL contains embedded credentials",
                "%s remote %s at %s:%s (url masked: %s)" % (remote["repository"], remote["remote"], remote["path"], remote["line"], remote["url"]),
                "Credentials in a remote URL are written to disk in plain text and are echoed by common git commands and CI logs.",
                "git remote set-url %s <url-without-credentials>   # then use a credential helper" % remote["remote"],
                False,
                key="remote:%s:%s" % (remote["repository"], remote["remote"]),
            ))

    for entry in permissions:
        if entry["group_or_world_readable"]:
            findings.append(F.finding(
                "secrets",
                "warning",
                "Credential file is readable beyond its owner: %s" % entry["path"],
                "mode %s" % entry["mode"],
                "Group and world readable credential files are exposed to any other account or sandboxed process on the machine.",
                "chmod 600 %s" % entry["path"],
                True,
                key="mode:%s" % entry["path"],
            ))

    result["findings"] = findings
    return result
