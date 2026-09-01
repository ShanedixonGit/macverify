"""Decide, before anything is collected, what this particular Mac can answer.

macverify runs on machines it has never seen: Intel and Apple silicon, macOS 11
through the current release, admin and standard accounts, with or without
Homebrew, Xcode or a container engine. Rather than let each collector discover
that on its own and report a confusing `unavailable`, this module states up
front which checks this host can support and why the rest will be short.
"""

import getpass
import os
import platform
import sys

from . import fsutil, sysinfo

MINIMUM_PYTHON = (3, 8)
MINIMUM_MACOS_MAJOR = 11
TESTED_MACOS_MAJOR = 26

XPROTECT_PATHS = (
    ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", 10.15),
    ("/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist", None),
)


def _macos_release():
    macos = sysinfo.macos_version()
    version = macos.get("version") or ""
    parts = [part for part in version.split(".") if part.isdigit()]
    major = int(parts[0]) if parts else None
    minor = int(parts[1]) if len(parts) > 1 else 0
    return macos, major, minor


def xprotect_info_plist():
    """The XProtect bundle moved in Catalina; find whichever one this host has."""
    for path, _ in XPROTECT_PATHS:
        if fsutil.exists(path):
            return path
    return None


def gatekeeper_reenable_command(major):
    """`spctl --master-enable` was withdrawn; on newer macOS only the GUI works."""
    if major is not None and major >= 15:
        return "System Settings > Privacy & Security > Security > Allow applications from"
    return "sudo spctl --master-enable"


def _account_kind():
    try:
        user = getpass.getuser()
    except Exception:
        return {"user": None, "admin": None, "root": os.geteuid() == 0}
    groups = []
    try:
        import grp

        for entry in grp.getgrall():
            if user in entry.gr_mem:
                groups.append(entry.gr_name)
    except Exception:
        groups = []
    return {
        "user": user,
        "admin": "admin" in groups if groups else None,
        "root": os.geteuid() == 0,
        "groups": sorted(groups)[:24],
    }


def _capability_notes(major, arch, account):
    """Per-domain expectations, so a short report is explained rather than blamed."""
    notes = []
    if major is not None and major >= 13:
        notes.append({
            "domain": "security",
            "expect": "supported",
            "detail": "sharing services are read from the launchd override database; the Sharing pane moved to System Settings > General on macOS 13 and later",
        })
    elif major is not None:
        notes.append({
            "domain": "security",
            "expect": "supported",
            "detail": "on macOS %d the same settings live in System Preferences > Sharing" % major,
        })
    if major is not None and major >= 15:
        notes.append({
            "domain": "security",
            "expect": "partial",
            "detail": "spctl --master-enable was removed in macOS 15, so the Gatekeeper fix is offered as a Settings path instead of a command",
        })
    if xprotect_info_plist() is None:
        notes.append({
            "domain": "security",
            "expect": "partial",
            "detail": "no XProtect bundle found at either the Catalina-and-later or the legacy path; malware definition versions will be absent",
        })
    if arch.get("apple_silicon"):
        notes.append({
            "domain": "security",
            "expect": "partial",
            "detail": "boot policy on Apple silicon is readable only through bputil under root, which this audit refuses to invoke; it is reported as requiring privileges",
        })
    else:
        notes.append({
            "domain": "security",
            "expect": "partial",
            "detail": "secure boot state is read from the T2 controller; Macs without a T2 report it as not applicable",
        })
    if arch.get("running_under_rosetta"):
        notes.append({
            "domain": "toolchain",
            "expect": "degraded",
            "detail": "the interpreter is translated by Rosetta, so PATH probes see the x86_64 view of this machine; re-run under a native shell for accurate results",
        })
    if account.get("root"):
        notes.append({
            "domain": "all",
            "expect": "unusual",
            "detail": "running as root reads files a normal session cannot, so the report will not reflect what your own account can see",
        })
    if account.get("admin") is False:
        notes.append({
            "domain": "permissions",
            "expect": "partial",
            "detail": "a standard (non-admin) account cannot read the system TCC database, so only user-scope privacy grants are enumerated",
        })
    if not sysinfo.homebrew().get("present"):
        notes.append({
            "domain": "packages",
            "expect": "partial",
            "detail": "Homebrew is not installed, so formula, cask and outdated-package checks are skipped rather than failed",
        })
    return notes


def preflight():
    """Return whether this host is supported, and what to expect if it is."""
    system = platform.system()
    python_version = tuple(sys.version_info[:3])
    macos, major, minor = _macos_release()
    arch = sysinfo.architecture()
    account = _account_kind()

    report = {
        "supported": True,
        "reason": None,
        "platform": system,
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "minimum_supported": ".".join(str(part) for part in MINIMUM_PYTHON),
        },
        "macos": {
            "version": macos.get("version"),
            "major": major,
            "minor": minor,
            "build": macos.get("build"),
            "minimum_supported": MINIMUM_MACOS_MAJOR,
            "newer_than_tested": bool(major and major > TESTED_MACOS_MAJOR),
        },
        "architecture": arch,
        "account": account,
        "warnings": [],
        "capability_notes": [],
    }

    if system != "Darwin":
        report["supported"] = False
        report["reason"] = "macverify reads macOS-specific state (launchd, TCC, XProtect, APFS) and has nothing to report on %s" % system
        return report

    if python_version < MINIMUM_PYTHON:
        report["supported"] = False
        report["reason"] = "Python %s is required; this interpreter is %s" % (
            report["python"]["minimum_supported"], platform.python_version())
        return report

    if major is not None and major < MINIMUM_MACOS_MAJOR:
        report["warnings"].append(
            "macOS %s predates the oldest release this rule set was written against (macOS %d); "
            "checks that reference newer paths will report as unavailable rather than fail"
            % (macos.get("version"), MINIMUM_MACOS_MAJOR))
    if report["macos"]["newer_than_tested"]:
        report["warnings"].append(
            "macOS %s is newer than the last release these rules were verified against; "
            "any check Apple has since moved will report as unavailable rather than guess"
            % macos.get("version"))
    if arch.get("running_under_rosetta"):
        report["warnings"].append(
            "this interpreter is running under Rosetta 2 on Apple silicon; re-run with a native "
            "python3 for an accurate toolchain view")
    if account.get("root"):
        report["warnings"].append(
            "running as root; macverify needs no elevation and the report will describe root's view "
            "of the machine rather than your own")

    report["capability_notes"] = _capability_notes(major, arch, account)
    return report
