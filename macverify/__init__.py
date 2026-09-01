import os
import re

DISTRIBUTION = "macverify"

UNKNOWN_VERSION = "0+unknown"


def _installed_version():
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:
        return None
    try:
        return version(DISTRIBUTION)
    except PackageNotFoundError:
        return None
    except Exception:
        return None


def _source_version():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pyproject.toml")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r'^\s*version\s*=\s*["\']([^"\']+)["\']\s*$', line)
                if match:
                    return match.group(1)
    except (OSError, ValueError):
        return None
    return None


def _resolve_version():
    return _installed_version() or _source_version() or UNKNOWN_VERSION


__version__ = _resolve_version()
