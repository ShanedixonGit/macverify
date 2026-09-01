import os
import re

from .. import findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context

VERSION_PATTERN = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[._+-][0-9A-Za-z.]+)?)")

SIMPLE_TOOLS = (
    ("git", ["git", "--version"], "git"),
    ("go", ["go", "version"], "go"),
    ("java", ["java", "-version"], "openjdk"),
    ("ruby", ["ruby", "--version"], "ruby"),
    ("php", ["php", "--version"], "php"),
    ("deno", ["deno", "--version"], "deno"),
    ("bun", ["bun", "--version"], "oven-sh/bun/bun"),
    ("rustc", ["rustc", "--version"], None),
    ("cargo", ["cargo", "--version"], None),
    ("rustup", ["rustup", "--version"], None),
    ("node", ["node", "--version"], "node"),
    ("npm", ["npm", "--version"], "npm"),
    ("pnpm", ["pnpm", "--version"], "pnpm"),
    ("yarn", ["yarn", "--version"], "yarn"),
    ("docker", ["docker", "--version"], None),
    ("podman", ["podman", "--version"], "podman"),
    ("colima", ["colima", "version"], "colima"),
    ("orb", ["orb", "version"], None),
    ("swift", ["swift", "--version"], None),
    ("perl", ["perl", "--version"], "perl"),
)

NODE_MANAGER_DIRS = (
    ("nvm", "~/.nvm/versions/node"),
    ("fnm", "~/.local/share/fnm/node-versions"),
    ("fnm", "~/Library/Application Support/fnm/node-versions"),
    ("volta", "~/.volta/tools/image/node"),
    ("asdf", "~/.asdf/installs/nodejs"),
    ("n", "~/n/n/versions/node"),
)

PYTHON_SEARCH_GLOBS = (
    "~/.pyenv/versions/*/bin/python3",
    "/Library/Frameworks/Python.framework/Versions/*/bin/python3",
    "~/.asdf/installs/python/*/bin/python3",
)


def _brew_env():
    return {"HOMEBREW_OFFLINE": "1"}


def _first_version(text):
    if not text:
        return None
    match = VERSION_PATTERN.search(text)
    return match.group(1) if match else None


def _install_method(path):
    if not path:
        return "unknown"
    home = fsutil.home()
    brew = sysinfo.homebrew()
    prefix = brew.get("prefix")
    resolved = os.path.realpath(path)
    for probe in (path, resolved):
        if "/.pyenv/" in probe:
            return "pyenv"
        if "/.nvm/" in probe:
            return "nvm"
        if "/fnm/" in probe or "/.fnm/" in probe:
            return "fnm"
        if "/.volta/" in probe:
            return "volta"
        if "/.asdf/" in probe:
            return "asdf"
        if "/.rustup/" in probe or "/.cargo/" in probe:
            return "rustup"
        if "/.bun/" in probe:
            return "bun_installer"
        if "/.deno/" in probe:
            return "deno_installer"
        if prefix and (probe.startswith(prefix + "/Cellar/") or probe.startswith(prefix + "/opt/") or probe.startswith(prefix + "/bin/")):
            return "homebrew"
        if probe.startswith("/Applications/") or probe.startswith(os.path.join(home, "Applications")):
            return "application_bundle"
        if probe.startswith("/Library/Frameworks/"):
            return "vendor_installer"
        if probe.startswith("/System/") or probe.startswith("/usr/bin/") or probe.startswith("/usr/sbin/") or probe.startswith("/usr/libexec/"):
            return "apple_system"
        if probe.startswith("/opt/") and not (prefix and probe.startswith(prefix)):
            return "manual_opt"
    if resolved.startswith(home):
        return "user_local"
    return "unknown"


def _upgrade_command(method, name, brew_name=None, version=None):
    token = brew_name or name
    if method == "homebrew":
        return "brew upgrade %s" % token
    if method == "pyenv":
        return "pyenv install --list | tail -n 20   # then: pyenv install <version> && pyenv global <version>"
    if method == "nvm":
        return "nvm install --lts && nvm alias default 'lts/*'"
    if method == "fnm":
        return "fnm install --lts && fnm default <version>"
    if method == "volta":
        return "volta install %s@latest" % ("node" if name in ("node", "npm") else name)
    if method == "asdf":
        return "asdf install %s latest && asdf global %s latest" % (name, name)
    if method == "rustup":
        return "rustup update"
    if method == "apple_system":
        return "Apple-managed component: update via System Settings > General > Software Update"
    if method == "application_bundle":
        return "Update from within the application, or: brew upgrade --cask %s" % token
    if method == "bun_installer":
        return "bun upgrade"
    if method == "deno_installer":
        return "deno upgrade"
    if method == "vendor_installer":
        return "Reinstall the current release from the vendor installer package"
    return "No upgrade path determined offline for %s" % name


def _brew_outdated(ctx):
    brew = sysinfo.homebrew()
    if not brew.get("present"):
        return {}, {}, brew.get("reason", "homebrew not installed")
    payload, reason = shell.json_of([brew["binary"], "outdated", "--json=v2"], timeout=ctx.slow(4), env=_brew_env())
    if payload is None:
        return {}, {}, reason
    formulae = {}
    casks = {}
    for item in payload.get("formulae") or []:
        formulae[item.get("name")] = {
            "installed": (item.get("installed_versions") or [None])[0],
            "latest": item.get("current_version"),
            "pinned": bool(item.get("pinned")),
        }
    for item in payload.get("casks") or []:
        casks[item.get("name")] = {
            "installed": (item.get("installed_versions") or [None])[0],
            "latest": item.get("current_version"),
        }
    return formulae, casks, None


def _probe(argv, timeout):
    res = shell.run(argv, timeout=timeout)
    if res["skipped_reason"]:
        return None, res["skipped_reason"]
    text = (res["stdout"] + "\n" + res["stderr"]).strip()
    if not res["ok"] and not text:
        return None, shell.failure_reason(res)
    return text, None


def _path_dirs():
    seen = []
    for entry in (os.environ.get("PATH") or "").split(os.pathsep):
        if entry and entry not in seen:
            seen.append(entry)
    return seen


def _glob(pattern):
    import glob as globmod

    try:
        return sorted(globmod.glob(os.path.expanduser(pattern)))
    except (OSError, ValueError):
        return []


def _python_interpreters(ctx):
    candidates = []
    name_pattern = re.compile(r"^python(2|3)?(\.\d+)?$")
    for directory in _path_dirs():
        for entry in fsutil.listdir(directory):
            if name_pattern.match(entry):
                candidates.append(os.path.join(directory, entry))
    for pattern in PYTHON_SEARCH_GLOBS:
        candidates.extend(_glob(pattern))
    brew = sysinfo.homebrew()
    if brew.get("prefix"):
        candidates.extend(_glob(os.path.join(brew["prefix"], "opt", "python@*", "bin", "python3")))
    for extra in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if fsutil.exists(extra):
            candidates.append(extra)

    interpreters = []
    seen_real = {}
    for path in sorted(set(candidates)):
        if not fsutil.exists(path):
            continue
        real = os.path.realpath(path)
        if real in seen_real:
            seen_real[real]["aliases"].append(fsutil.tilde(path))
            seen_real[real]["aliases"] = sorted(set(seen_real[real]["aliases"]))
            continue
        text, reason = _probe([path, "--version"], ctx.timeout)
        entry = {
            "path": fsutil.tilde(path),
            "real_path": fsutil.tilde(real),
            "version": _first_version(text) if text else None,
            "install_method": _install_method(real),
            "aliases": [],
            "on_path": os.path.dirname(path) in _path_dirs(),
        }
        if text is None:
            entry["status"] = "unavailable"
            entry["reason"] = reason
        entry["upgrade_command"] = _upgrade_command(entry["install_method"], "python", brew_name="python@%s" % ".".join((entry["version"] or "0.0").split(".")[:2]))
        interpreters.append(entry)
        seen_real[real] = entry
    return sorted(interpreters, key=lambda item: (item["path"]))


def _pip_mapping(ctx):
    mapping = []
    name_pattern = re.compile(r"^pip(2|3)?(\.\d+)?$")
    seen = set()
    for directory in _path_dirs():
        for entry in fsutil.listdir(directory):
            if not name_pattern.match(entry):
                continue
            path = os.path.join(directory, entry)
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            text, reason = _probe([path, "--version"], ctx.timeout)
            record = {"pip": fsutil.tilde(path), "version": None, "python": None, "site_packages": None}
            if text is None:
                record["status"] = "unavailable"
                record["reason"] = reason
                mapping.append(record)
                continue
            record["version"] = _first_version(text)
            match = re.search(r"from (\S+) \(python (\d+\.\d+)\)", text)
            if match:
                record["site_packages"] = fsutil.tilde(match.group(1))
                record["python"] = match.group(2)
                root = match.group(1)
                marker = "/lib/python"
                if marker in root:
                    record["python_prefix"] = fsutil.tilde(root.split(marker)[0])
            mapping.append(record)
    return sorted(mapping, key=lambda item: item["pip"])


def _node_managers(ctx):
    managers = []
    for name, pattern in NODE_MANAGER_DIRS:
        directory = os.path.expanduser(pattern)
        if not fsutil.exists(directory):
            continue
        versions = [entry for entry in fsutil.listdir(directory) if not entry.startswith(".")]
        managers.append({
            "manager": name,
            "versions_dir": fsutil.tilde(directory),
            "installed_versions": versions,
            "version_count": len(versions),
        })
    nvm_script = os.path.expanduser("~/.nvm/nvm.sh")
    if fsutil.exists(nvm_script) and not any(item["manager"] == "nvm" for item in managers):
        managers.append({"manager": "nvm", "versions_dir": None, "installed_versions": [], "version_count": 0, "note": "nvm.sh present with no installed versions"})
    for binary in ("fnm", "volta", "asdf", "nvs"):
        path = shell.which(binary)
        if path and not any(item["manager"] == binary for item in managers):
            managers.append({"manager": binary, "binary": fsutil.tilde(path), "installed_versions": [], "version_count": 0})
    return sorted(managers, key=lambda item: (item["manager"], item.get("versions_dir") or ""))


def _rust(ctx):
    info = {}
    if shell.which("rustup"):
        text, reason = _probe(["rustup", "toolchain", "list"], ctx.timeout)
        info["toolchains"] = sorted(line.strip() for line in (text or "").splitlines() if line.strip()) if text else []
        if text is None:
            info["toolchains_status"] = shell.unavailable(reason)
        target, _ = _probe(["rustup", "show", "active-toolchain"], ctx.timeout)
        info["active_toolchain"] = target.strip().splitlines()[0] if target else None
    else:
        info = shell.unavailable("rustup not installed")
    return info


def _xcode(ctx):
    info = {}
    developer_dir, reason = _probe(["xcode-select", "-p"], ctx.timeout)
    info["developer_dir"] = developer_dir.strip() if developer_dir else None
    if developer_dir is None:
        info["developer_dir_status"] = shell.unavailable(reason)
    clt = shell.run(["pkgutil", "--pkg-info=com.apple.pkg.CLTools_Executables"], timeout=ctx.timeout)
    if clt["ok"]:
        version = None
        for line in clt["stdout"].splitlines():
            if line.startswith("version:"):
                version = line.split(":", 1)[1].strip()
        info["command_line_tools"] = {"installed": True, "version": version, "upgrade_command": "Apple-managed: System Settings > General > Software Update (or: xcode-select --install after removal)"}
    else:
        info["command_line_tools"] = {"installed": False, "reason": shell.failure_reason(clt), "upgrade_command": "xcode-select --install"}
    app_plist = "/Applications/Xcode.app/Contents/version.plist"
    if fsutil.exists(app_plist):
        payload, plist_reason = fsutil.read_plist(app_plist)
        if payload:
            info["xcode_app"] = {
                "installed": True,
                "version": payload.get("CFBundleShortVersionString"),
                "build": payload.get("ProductBuildVersion"),
                "path": "/Applications/Xcode.app",
                "upgrade_command": "Update Xcode from the App Store",
            }
        else:
            info["xcode_app"] = shell.unavailable(plist_reason)
    else:
        info["xcode_app"] = {"installed": False, "reason": "/Applications/Xcode.app not present"}
    sdk = shell.run(["xcrun", "--show-sdk-version"], timeout=ctx.timeout)
    info["sdk_version"] = sdk["stdout"].strip() if sdk["ok"] else None
    return info


def _container_runtimes(ctx, tools):
    present = [name for name in ("docker", "podman", "colima", "orb") if tools.get(name, {}).get("present")]
    orbstack = fsutil.exists("/Applications/OrbStack.app")
    docker_desktop = fsutil.exists("/Applications/Docker.app")
    return {
        "cli_present": present,
        "orbstack_app": orbstack,
        "docker_desktop_app": docker_desktop,
        "note": "runtime state is reported by the containers collector",
    }


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {"status": "ok", "findings": []}
    items = []

    brew_formulae, brew_casks, brew_reason = _brew_outdated(ctx)
    brew = sysinfo.homebrew()
    result["homebrew"] = dict(brew)
    if brew.get("present"):
        version_text, version_reason = _probe([brew["binary"], "--version"], ctx.slow(2))
        result["homebrew"]["version"] = _first_version(version_text) if version_text else None
        result["homebrew"]["outdated_metadata"] = "local" if brew_reason is None else "unavailable"
        if brew_reason:
            result["homebrew"]["outdated_reason"] = brew_reason
    else:
        result["homebrew"]["upgrade_command"] = 'Install from https://brew.sh (not performed by this audit)'

    tools = {}
    for name, argv, brew_name in SIMPLE_TOOLS:
        path = shell.which(argv[0])
        if not path:
            tools[name] = {"present": False, "status": "unavailable", "reason": "%s not found on PATH" % argv[0]}
            continue
        text, reason = _probe(argv, ctx.timeout)
        real = os.path.realpath(path)
        method = _install_method(real)
        entry = {
            "present": True,
            "path": fsutil.tilde(path),
            "real_path": fsutil.tilde(real),
            "version": _first_version(text) if text else None,
            "install_method": method,
            "latest_known": None,
            "latest_source": None,
            "upgrade_command": _upgrade_command(method, name, brew_name=brew_name),
        }
        if text is None:
            entry["status"] = "unavailable"
            entry["reason"] = reason
        if brew_name and brew_name in brew_formulae:
            entry["latest_known"] = brew_formulae[brew_name]["latest"]
            entry["latest_source"] = "local homebrew metadata"
            entry["outdated"] = True
        elif brew_name and brew_name in brew_casks:
            entry["latest_known"] = brew_casks[brew_name]["latest"]
            entry["latest_source"] = "local homebrew metadata"
            entry["outdated"] = True
            entry["upgrade_command"] = "brew upgrade --cask %s" % brew_name
        else:
            entry["outdated"] = False if brew_reason is None else None
        tools[name] = entry
        items.append((name, entry))

    result["tools"] = tools
    result["python"] = {
        "interpreters": _python_interpreters(ctx),
        "pip_mapping": _pip_mapping(ctx),
        "active_python3": fsutil.tilde(shell.which("python3")) if shell.which("python3") else None,
        "pyenv": {
            "present": bool(shell.which("pyenv")),
            "root": fsutil.tilde(os.path.expanduser("~/.pyenv")) if fsutil.exists(os.path.expanduser("~/.pyenv")) else None,
            "versions": [entry for entry in fsutil.listdir(os.path.expanduser("~/.pyenv/versions"))] if fsutil.exists(os.path.expanduser("~/.pyenv/versions")) else [],
        },
    }
    result["node"] = {"managers": _node_managers(ctx), "active_node": tools.get("node", {}).get("version")}
    result["rust"] = _rust(ctx)
    result["xcode"] = _xcode(ctx)
    result["containers_cli"] = _container_runtimes(ctx, tools)

    findings = []
    for name, entry in items:
        if entry.get("outdated") and entry.get("latest_known"):
            findings.append(F.finding(
                "toolchain",
                "info",
                "%s is behind the version in local Homebrew metadata" % name,
                "installed %s, local metadata reports %s" % (entry.get("version"), entry["latest_known"]),
                "Running an older release means known upstream fixes present in the already-downloaded metadata are not applied.",
                entry["upgrade_command"],
                True,
                key=name,
            ))

    interpreters = result["python"]["interpreters"]
    if len(interpreters) > 3:
        findings.append(F.finding(
            "toolchain",
            "info",
            "Multiple Python interpreters installed",
            "%d distinct interpreters: %s" % (len(interpreters), ", ".join(item["path"] for item in interpreters[:8])),
            "Several interpreters make it ambiguous which one pip installs into and which one a script will use.",
            "pyenv versions && which -a python3 python",
            True,
            key="python-interpreter-count",
        ))

    managers_with_versions = [item for item in result["node"]["managers"] if item.get("version_count")]
    if len(managers_with_versions) > 1:
        findings.append(F.finding(
            "toolchain",
            "warning",
            "More than one Node version manager holds installed runtimes",
            ", ".join("%s (%d versions)" % (item["manager"], item["version_count"]) for item in managers_with_versions),
            "Competing Node managers fight over PATH order, so the node in a shell depends on which shim was sourced last.",
            "Pick one manager, then remove the others' shims from your shell profile",
            True,
            key="node-manager-conflict",
        ))

    if not result["xcode"]["command_line_tools"].get("installed"):
        findings.append(F.finding(
            "toolchain",
            "warning",
            "Xcode Command Line Tools are not installed",
            result["xcode"]["command_line_tools"].get("reason", "pkgutil reports no CLTools_Executables package"),
            "Most native build steps, Homebrew formulae and git itself depend on the CLT headers and toolchain.",
            "xcode-select --install",
            True,
            key="clt-missing",
        ))

    arch = sysinfo.architecture()
    if arch.get("running_under_rosetta"):
        findings.append(F.finding(
            "toolchain",
            "warning",
            "The audit interpreter is running under Rosetta 2",
            "interpreter arch %s on native %s hardware" % (arch["interpreter_arch"], arch["native_arch"]),
            "Tools launched from a translated process inherit the x86_64 environment, which silently installs the wrong architecture builds.",
            "arch -arm64 /bin/zsh --login   # then re-run the audit",
            True,
            key="rosetta",
        ))

    result["findings"] = findings
    return result
