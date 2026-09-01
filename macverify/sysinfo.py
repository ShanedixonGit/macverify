import getpass
import os
import platform
import socket

from . import fsutil, shell

_CACHE = {}


def _sysctl(name):
    value = shell.stdout_of(["sysctl", "-n", name], timeout=4)
    return value.strip() if value else None


def architecture():
    if "arch" in _CACHE:
        return _CACHE["arch"]
    machine = platform.machine()
    is_arm_hardware = _sysctl("hw.optional.arm64") == "1"
    translated = _sysctl("sysctl.proc_translated") == "1"
    if is_arm_hardware:
        native = "arm64"
    elif machine == "arm64":
        native = "arm64"
    else:
        native = "x86_64"
    info = {
        "interpreter_arch": machine,
        "native_arch": native,
        "apple_silicon": native == "arm64",
        "running_under_rosetta": translated,
    }
    _CACHE["arch"] = info
    return info


def macos_version():
    if "macos" in _CACHE:
        return _CACHE["macos"]
    release = platform.mac_ver()[0] or None
    build = shell.stdout_of(["sw_vers", "-buildVersion"], timeout=4)
    name = shell.stdout_of(["sw_vers", "-productName"], timeout=4)
    parts = (release or "").split(".")
    info = {
        "product": (name or "macOS").strip(),
        "version": release,
        "major": int(parts[0]) if parts and parts[0].isdigit() else None,
        "build": build.strip() if build else None,
    }
    _CACHE["macos"] = info
    return info


def homebrew():
    if "brew" in _CACHE:
        return _CACHE["brew"]
    binary = shell.which("brew")
    if not binary:
        for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew", os.path.expanduser("~/.linuxbrew/bin/brew")):
            if fsutil.exists(candidate):
                binary = candidate
                break
    if not binary:
        info = {"present": False, "prefix": None, "binary": None, "reason": "brew not found on PATH or in default prefixes"}
        _CACHE["brew"] = info
        return info
    prefix = shell.stdout_of([binary, "--prefix"], timeout=10)
    prefix = prefix.strip() if prefix else os.path.dirname(os.path.dirname(binary))
    cellar = os.path.join(prefix, "Cellar")
    info = {
        "present": True,
        "binary": binary,
        "prefix": prefix,
        "cellar": cellar if fsutil.exists(cellar) else None,
        "layout": "apple_silicon_default" if prefix == "/opt/homebrew" else ("intel_default" if prefix == "/usr/local" else "custom"),
    }
    _CACHE["brew"] = info
    return info


def login_shell():
    if "shell" in _CACHE:
        return _CACHE["shell"]
    env_shell = os.environ.get("SHELL") or None
    directory_shell = None
    try:
        user = getpass.getuser()
    except Exception:
        user = None
    if user:
        output = shell.stdout_of(["dscacheutil", "-q", "user", "-a", "name", user], timeout=5)
        for line in (output or "").splitlines():
            if line.startswith("shell:"):
                directory_shell = line.split(":", 1)[1].strip() or None
    path = directory_shell or env_shell
    family = os.path.basename(path) if path else None
    if family and family not in ("zsh", "bash", "fish", "sh", "ksh", "tcsh", "csh", "dash"):
        family = family.lower()
    info = {
        "path": path,
        "family": family,
        "from_environment": env_shell,
        "from_directory_service": directory_shell,
    }
    _CACHE["shell"] = info
    return info


def hostname():
    try:
        return socket.gethostname()
    except Exception:
        return None


def snapshot():
    return {
        "architecture": architecture(),
        "macos": macos_version(),
        "homebrew": homebrew(),
        "shell": login_shell(),
        "hostname": hostname(),
        "python": {
            "version": platform.python_version(),
            "executable": os.sys.executable,
        },
    }
