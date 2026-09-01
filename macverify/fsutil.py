import os
import plistlib
import stat as statmod

MAX_TEXT_BYTES = 1024 * 1024


def home():
    return os.path.expanduser("~")


def expand(path):
    return os.path.expanduser(os.path.expandvars(path))


def tilde(path):
    try:
        real = os.path.abspath(path)
    except (OSError, ValueError):
        return str(path)
    base = home()
    if real == base:
        return "~"
    if real.startswith(base + os.sep):
        return "~" + real[len(base):]
    return real


def exists(path):
    try:
        return os.path.exists(path)
    except (OSError, ValueError):
        return False


def read_text(path, limit=MAX_TEXT_BYTES):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(limit)
    except (OSError, ValueError):
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def read_json(path):
    import json

    text = read_text(path)
    if text is None:
        return None, "unreadable: %s" % tilde(path)
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, "invalid json in %s: %s" % (tilde(path), exc.__class__.__name__)


def read_plist(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except (OSError, ValueError):
        return None, "unreadable plist: %s" % tilde(path)
    for candidate in (raw, raw.lstrip(b"\xef\xbb\xbf \t\r\n")):
        try:
            return plistlib.loads(candidate), None
        except Exception:
            continue
    from . import shell

    converted = shell.run(["plutil", "-convert", "xml1", "-o", "-", path], timeout=5)
    if converted["ok"] and converted["stdout"].strip():
        try:
            return plistlib.loads(converted["stdout"].encode("utf-8", "replace")), None
        except Exception:
            pass
    return None, "unparseable plist: %s" % tilde(path)


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except (OSError, ValueError):
        return []


def stat(path, follow=False):
    try:
        return os.stat(path) if follow else os.lstat(path)
    except (OSError, ValueError):
        return None


def mode_string(st):
    if st is None:
        return None
    return oct(statmod.S_IMODE(st.st_mode))[2:].rjust(4, "0")


def is_world_writable(path):
    st = stat(path, follow=True)
    if st is None:
        return False
    if statmod.S_ISDIR(st.st_mode) and st.st_mode & statmod.S_ISVTX:
        return False
    return bool(st.st_mode & statmod.S_IWOTH)


def iso_time(value):
    import datetime

    if value is None:
        return None
    try:
        moment = datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
    except (ValueError, OSError, OverflowError, TypeError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def created_at(st):
    if st is None:
        return None
    return iso_time(getattr(st, "st_birthtime", None) or st.st_ctime)


def modified_at(st):
    if st is None:
        return None
    return iso_time(st.st_mtime)


def file_size(path):
    st = stat(path, follow=True)
    return int(st.st_size) if st else None


def dir_size(path, max_entries=200000, same_device=True):
    root_stat = stat(path, follow=True)
    if root_stat is None:
        return None
    device = root_stat.st_dev
    total = 0
    seen = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    seen += 1
                    if seen > max_entries:
                        return total
                    try:
                        if entry.is_symlink():
                            continue
                        info = entry.stat(follow_symlinks=False)
                        if same_device and info.st_dev != device:
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += int(info.st_size)
                    except (OSError, ValueError):
                        continue
        except (OSError, ValueError):
            continue
    return total


def human_bytes(value):
    if value is None:
        return None
    try:
        size = float(value)
    except (TypeError, ValueError):
        return None
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(size) < 1024.0 or unit == "PB":
            if unit == "B":
                return "%d B" % int(size)
            return "%.1f %s" % (size, unit)
        size /= 1024.0
    return None


def walk_files(root, pattern_fn, max_depth=4, max_entries=60000, skip_names=()):
    results = []
    seen = 0
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as scanner:
                entries = sorted(scanner, key=lambda item: item.name)
        except (OSError, ValueError):
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return sorted(results)
            if entry.name in skip_names or entry.name.startswith("."):
                if entry.name not in (".claude", ".claude-plugin"):
                    continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth:
                        stack.append((entry.path, depth + 1))
                elif pattern_fn(entry.name):
                    results.append(entry.path)
            except (OSError, ValueError):
                continue
    return sorted(results)
