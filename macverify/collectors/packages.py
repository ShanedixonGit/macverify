import os
import re

from .. import findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context

BREW_ENV = {"HOMEBREW_OFFLINE": "1"}

NETWORK_NOTE = "requires a network request to the registry; this audit is offline-only"


def _du_kb(path, timeout):
    if not fsutil.exists(path):
        return None
    res = shell.run(["du", "-sk", path], timeout=timeout)
    if not res["stdout"].strip():
        return None
    head = res["stdout"].strip().splitlines()[0].split("\t")[0].strip()
    try:
        return int(head) * 1024
    except ValueError:
        return None


def _homebrew(ctx):
    brew = sysinfo.homebrew()
    if not brew.get("present"):
        return shell.unavailable(brew.get("reason", "homebrew not installed"))
    binary = brew["binary"]
    prefix = brew["prefix"]
    data = {"status": "ok", "prefix": prefix, "binary": fsutil.tilde(binary)}

    outdated, reason = shell.json_of([binary, "outdated", "--json=v2"], timeout=ctx.slow(4), env=BREW_ENV)
    if outdated is None:
        data["outdated"] = shell.unavailable(reason)
    else:
        data["outdated"] = {
            "formulae": sorted(
                [{"name": item.get("name"), "installed": (item.get("installed_versions") or [None])[0], "latest": item.get("current_version"), "pinned": bool(item.get("pinned"))} for item in outdated.get("formulae") or []],
                key=lambda item: item["name"] or "",
            ),
            "casks": sorted(
                [{"name": item.get("name"), "installed": (item.get("installed_versions") or [None])[0], "latest": item.get("current_version")} for item in outdated.get("casks") or []],
                key=lambda item: item["name"] or "",
            ),
        }
        data["outdated"]["formula_count"] = len(data["outdated"]["formulae"])
        data["outdated"]["cask_count"] = len(data["outdated"]["casks"])

    installed, installed_reason = shell.json_of([binary, "info", "--json=v2", "--installed"], timeout=ctx.slow(6), env=BREW_ENV)
    if installed is None:
        data["installed"] = shell.unavailable(installed_reason)
        formula_names = []
    else:
        deprecated = []
        disabled = []
        unlinked = []
        pinned = []
        formula_names = []
        for item in installed.get("formulae") or []:
            name = item.get("name")
            formula_names.append(name)
            if item.get("deprecated"):
                deprecated.append({"name": name, "reason": item.get("deprecation_reason"), "date": item.get("deprecation_date")})
            if item.get("disabled"):
                disabled.append({"name": name, "reason": item.get("disable_reason"), "date": item.get("disable_date")})
            if item.get("pinned"):
                pinned.append(name)
            if item.get("installed") and not item.get("linked_keg"):
                unlinked.append({"name": name, "versions": sorted(entry.get("version") for entry in item.get("installed") or [] if entry.get("version"))})
        data["installed"] = {
            "formula_count": len(formula_names),
            "cask_count": len(installed.get("casks") or []),
            "formulae": sorted(name for name in formula_names if name),
            "casks": sorted(item.get("token") or item.get("full_token") or "" for item in installed.get("casks") or []),
            "deprecated": sorted(deprecated, key=lambda item: item["name"] or ""),
            "disabled": sorted(disabled, key=lambda item: item["name"] or ""),
            "unlinked_kegs": sorted(unlinked, key=lambda item: item["name"] or ""),
            "pinned": sorted(pinned),
        }

    taps = shell.stdout_of([binary, "tap"], timeout=ctx.slow(2), env=BREW_ENV)
    data["taps"] = sorted(line.strip() for line in (taps or "").splitlines() if line.strip()) if taps is not None else shell.unavailable("brew tap produced no readable output")

    doctor = shell.run([binary, "doctor"], timeout=ctx.slow(5), env=BREW_ENV)
    if doctor["skipped_reason"]:
        data["doctor"] = shell.unavailable(doctor["skipped_reason"])
    else:
        text = (doctor["stdout"] + doctor["stderr"]).strip()
        warnings = [line.strip() for line in text.splitlines() if line.strip().startswith("Warning:")]
        data["doctor"] = {
            "clean": doctor["ok"] and "ready to brew" in text.lower(),
            "warning_count": len(warnings),
            "warnings": warnings,
            "output": text[:8000],
        }

    footprint = {}
    for label, path in (("cellar", os.path.join(prefix, "Cellar")), ("caskroom", os.path.join(prefix, "Caskroom"))):
        size = _du_kb(path, ctx.slow(5))
        footprint[label] = {"path": path, "bytes": size, "human": fsutil.human_bytes(size)}
    cache = shell.stdout_of([binary, "--cache"], timeout=ctx.slow(2), env=BREW_ENV)
    cache_path = cache.strip() if cache else None
    cache_size = _du_kb(cache_path, ctx.slow(5)) if cache_path else None
    footprint["download_cache"] = {"path": fsutil.tilde(cache_path) if cache_path else None, "bytes": cache_size, "human": fsutil.human_bytes(cache_size)}
    total = sum(entry["bytes"] or 0 for entry in footprint.values())
    footprint["total_bytes"] = total
    footprint["total_human"] = fsutil.human_bytes(total)
    data["disk_footprint"] = footprint
    return data


def _npm(ctx):
    if not shell.which("npm"):
        return shell.unavailable("npm not found on PATH")
    payload, reason = shell.json_of(["npm", "ls", "-g", "--depth=0", "--json"], timeout=ctx.slow(3), allow_nonzero=True)
    if payload is None:
        return shell.unavailable(reason)
    packages = []
    for name, meta in sorted((payload.get("dependencies") or {}).items()):
        packages.append({"name": name, "version": (meta or {}).get("version"), "upgrade_command": "npm install -g %s@latest" % name})
    return {
        "status": "ok",
        "prefix": fsutil.tilde((payload.get("path") or "")) or None,
        "package_count": len(packages),
        "packages": packages,
        "outdated": {"status": "unavailable", "reason": NETWORK_NOTE, "manual_command": "npm outdated -g --depth=0"},
    }


def _pip(ctx):
    interpreter = shell.which("python3") or shell.which("python")
    if not interpreter:
        return shell.unavailable("no python interpreter found on PATH")
    payload, reason = shell.json_of([interpreter, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"], timeout=ctx.slow(3))
    result = {"interpreter": fsutil.tilde(interpreter)}
    if payload is None:
        result["packages"] = shell.unavailable(reason)
    else:
        result["package_count"] = len(payload)
        result["packages"] = sorted(({"name": item.get("name"), "version": item.get("version")} for item in payload), key=lambda item: (item["name"] or "").lower())
    result["outdated"] = {"status": "unavailable", "reason": NETWORK_NOTE, "manual_command": "python3 -m pip list --outdated"}
    result["in_virtualenv"] = bool(os.environ.get("VIRTUAL_ENV"))
    return result


def _pipx(ctx):
    if not shell.which("pipx"):
        return shell.unavailable("pipx not found on PATH")
    payload, reason = shell.json_of(["pipx", "list", "--json"], timeout=ctx.slow(3))
    if payload is None:
        return shell.unavailable(reason)
    venvs = []
    for name, meta in sorted((payload.get("venvs") or {}).items()):
        metadata = (meta or {}).get("metadata") or {}
        main = metadata.get("main_package") or {}
        venvs.append({
            "name": name,
            "version": main.get("package_version"),
            "python": main.get("python_version"),
            "apps": sorted(main.get("apps") or []),
            "upgrade_command": "pipx upgrade %s" % name,
        })
    return {"status": "ok", "package_count": len(venvs), "packages": venvs}


def _cargo(ctx):
    if not shell.which("cargo"):
        return shell.unavailable("cargo not found on PATH")
    text = shell.stdout_of(["cargo", "install", "--list"], timeout=ctx.slow(3))
    if text is None:
        return shell.unavailable("cargo install --list produced no readable output")
    packages = []
    for line in text.splitlines():
        match = re.match(r"^(\S+)\s+v(\S+?):\s*$", line.strip())
        if match:
            packages.append({"name": match.group(1), "version": match.group(2), "upgrade_command": "cargo install %s --force" % match.group(1)})
    return {"status": "ok", "package_count": len(packages), "packages": sorted(packages, key=lambda item: item["name"])}


def _gem(ctx):
    if not shell.which("gem"):
        return shell.unavailable("gem not found on PATH")
    text = shell.stdout_of(["gem", "list", "--local", "--no-versions"], timeout=ctx.slow(3))
    if text is None:
        return shell.unavailable("gem list produced no readable output")
    names = sorted(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("*"))
    return {"status": "ok", "package_count": len(names), "packages": names[:400], "truncated": len(names) > 400}


def _names(entry, key="packages"):
    payload = entry.get(key) if isinstance(entry, dict) else None
    if not isinstance(payload, list):
        return set()
    out = set()
    for item in payload:
        if isinstance(item, dict) and item.get("name"):
            out.add(str(item["name"]).lower())
        elif isinstance(item, str):
            out.add(item.lower())
    return out


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {"status": "ok", "findings": []}
    result["homebrew"] = _homebrew(ctx)
    result["npm_global"] = _npm(ctx)
    result["pip"] = _pip(ctx)
    result["pipx"] = _pipx(ctx)
    result["cargo"] = _cargo(ctx)
    result["gem"] = _gem(ctx)

    findings = []
    brew = result["homebrew"]
    if isinstance(brew.get("outdated"), dict) and brew["outdated"].get("formula_count") is not None:
        count = brew["outdated"]["formula_count"] + brew["outdated"]["cask_count"]
        if count:
            severity = "warning" if count >= 25 else "info"
            findings.append(F.finding(
                "packages",
                severity,
                "%d Homebrew packages are outdated in local metadata" % count,
                "%d formulae, %d casks" % (brew["outdated"]["formula_count"], brew["outdated"]["cask_count"]),
                "Outdated formulae accumulate old dependency trees, which grows disk use and delays security fixes already downloaded in the tap metadata.",
                "brew upgrade",
                True,
                key="brew-outdated",
            ))
    installed = brew.get("installed") if isinstance(brew, dict) else None
    if isinstance(installed, dict):
        for item in installed.get("disabled") or []:
            findings.append(F.finding(
                "packages",
                "warning",
                "Disabled Homebrew formula still installed: %s" % item["name"],
                "disabled %s: %s" % (item.get("date") or "date unknown", item.get("reason") or "no reason recorded"),
                "A disabled formula receives no further updates from Homebrew, so it will drift permanently out of date.",
                "brew uninstall %s   # confirm no dependents first: brew uses --installed %s" % (item["name"], item["name"]),
                False,
                key="brew-disabled-%s" % item["name"],
            ))
        for item in installed.get("deprecated") or []:
            findings.append(F.finding(
                "packages",
                "info",
                "Deprecated Homebrew formula installed: %s" % item["name"],
                "deprecated %s: %s" % (item.get("date") or "date unknown", item.get("reason") or "no reason recorded"),
                "Deprecated formulae are scheduled for removal, so they will stop receiving updates on a known date.",
                "brew info %s" % item["name"],
                True,
                key="brew-deprecated-%s" % item["name"],
            ))
        for item in installed.get("unlinked_kegs") or []:
            findings.append(F.finding(
                "packages",
                "info",
                "Unlinked Homebrew keg: %s" % item["name"],
                "installed versions %s with no linked keg" % (", ".join(item.get("versions") or []) or "unknown"),
                "An unlinked keg occupies disk space while providing nothing on PATH, and usually indicates an interrupted upgrade.",
                "brew link %s   # or: brew uninstall %s" % (item["name"], item["name"]),
                True,
                key="brew-unlinked-%s" % item["name"],
            ))
    doctor = brew.get("doctor") if isinstance(brew, dict) else None
    if isinstance(doctor, dict) and doctor.get("warning_count"):
        findings.append(F.finding(
            "packages",
            "info",
            "brew doctor reports %d warnings" % doctor["warning_count"],
            "; ".join(doctor.get("warnings") or [])[:400],
            "brew doctor warnings are the usual first cause of failed builds and linking errors later on.",
            "brew doctor",
            True,
            key="brew-doctor",
        ))

    duplicates = {}
    sources = {
        "homebrew": set(installed.get("formulae") or []) if isinstance(installed, dict) else set(),
        "npm_global": _names(result["npm_global"]),
        "pipx": _names(result["pipx"]),
        "cargo": _names(result["cargo"]),
    }
    sources["homebrew"] = {name.lower() for name in sources["homebrew"]}
    for manager, names in sources.items():
        for name in names:
            duplicates.setdefault(name, set()).add(manager)
    overlapping = sorted((name, sorted(managers)) for name, managers in duplicates.items() if len(managers) > 1)
    result["cross_manager_duplicates"] = [{"name": name, "managers": managers} for name, managers in overlapping]
    for name, managers in overlapping:
        findings.append(F.finding(
            "packages",
            "warning",
            "%s is installed by more than one package manager" % name,
            "provided by: %s" % ", ".join(managers),
            "Two managers owning the same command means PATH order decides which version runs, and upgrades applied to one are invisible to the other.",
            "which -a %s   # then remove the copy you do not intend to keep" % name,
            True,
            key="duplicate-%s" % name,
        ))

    result["findings"] = findings
    return result
