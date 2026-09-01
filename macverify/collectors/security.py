import os

from .. import compat, findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context

# Apple moved these bundles out of /System into /Library/Apple in Catalina, and
# retired MRT in Ventura. Each label carries both locations so the collector
# reports a version on any release rather than a false "not installed".
XPROTECT_BUNDLES = (
    ("xprotect_definitions", (
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    )),
    ("xprotect_remediator", (
        "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
    )),
    ("mrt", (
        "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist",
        "/System/Library/CoreServices/MRT.app/Contents/Info.plist",
    )),
)

REMOTE_SERVICES = {
    "com.openssh.sshd": "remote login (ssh)",
    "com.apple.screensharing": "screen sharing",
    "com.apple.RemoteDesktop.agent": "remote management (ARD)",
    "com.apple.smbd": "file sharing (smb)",
    "com.apple.AppleFileServer": "file sharing (afp)",
}


def _simple(argv, ctx, privileged_hint=None):
    res = shell.run(argv, timeout=ctx.slow(2))
    if res["skipped_reason"]:
        return shell.unavailable(res["skipped_reason"])
    text = (res["stdout"] + res["stderr"]).strip()
    lowered = text.lower()
    if "requires root" in lowered or "must be run as root" in lowered or "administrator" in lowered:
        return shell.requires_privileges(text[:200], {"privileged_command_not_run": " ".join(argv)})
    if not res["ok"] and not text:
        return shell.unavailable(shell.failure_reason(res))
    return {"status": "ok", "output": text[:400]}


def _sip(ctx):
    info = _simple(["csrutil", "status"], ctx)
    if isinstance(info, dict) and info.get("status") == "ok":
        info["enabled"] = "enabled" in info["output"].lower() and "disabled" not in info["output"].lower()
    return info


def _filevault(ctx):
    info = _simple(["fdesetup", "status"], ctx)
    if isinstance(info, dict) and info.get("status") == "ok":
        info["enabled"] = "filevault is on" in info["output"].lower()
    return info


def _gatekeeper(ctx):
    info = _simple(["spctl", "--status"], ctx)
    if isinstance(info, dict) and info.get("status") == "ok":
        info["assessments_enabled"] = "assessments enabled" in info["output"].lower()
    return info


def _malware_definitions():
    versions = {}
    for label, candidates in XPROTECT_BUNDLES:
        path = next((candidate for candidate in candidates if fsutil.exists(candidate)), None)
        if path is None:
            bundle = os.path.basename(os.path.dirname(os.path.dirname(candidates[0])))
            versions[label] = {
                "installed": False,
                "searched": list(candidates),
                "reason": "%s is not present at either the current or the legacy path on this macOS release" % bundle,
            }
            continue
        payload, reason = fsutil.read_plist(path)
        if payload is None:
            versions[label] = shell.unavailable(reason)
            continue
        versions[label] = {
            "installed": True,
            "path": path,
            "version": payload.get("CFBundleShortVersionString"),
            "build": payload.get("CFBundleVersion"),
            "modified": fsutil.modified_at(fsutil.stat(path)),
        }
    return versions


def _software_updates():
    payload, reason = fsutil.read_plist("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    if payload is None:
        return shell.unavailable("%s; a live check would require a network request, which this audit does not make" % reason)
    recommended = payload.get("RecommendedUpdates") or []
    entries = []
    for item in recommended:
        if isinstance(item, dict):
            entries.append({"identifier": item.get("Identifier"), "display_name": item.get("Display Name"), "version": item.get("Display Version")})
    return {
        "status": "ok",
        "source": "local SoftwareUpdate preference cache; no network check was made",
        "pending_count": payload.get("LastRecommendedUpdatesAvailable", len(entries)),
        "pending_updates": entries,
        "last_check": fsutil.iso_time(payload.get("LastSuccessfulDate").timestamp()) if hasattr(payload.get("LastSuccessfulDate"), "timestamp") else str(payload.get("LastSuccessfulDate")) if payload.get("LastSuccessfulDate") else None,
        "automatic_check_enabled": payload.get("AutomaticCheckEnabled"),
        "automatic_download_enabled": payload.get("AutomaticDownload"),
        "critical_updates_install": payload.get("CriticalUpdateInstall"),
    }


def _secure_boot(ctx):
    arch = sysinfo.architecture()
    if arch.get("apple_silicon"):
        return shell.requires_privileges(
            "on Apple silicon the boot policy is readable only through bputil, which requires root",
            {"privileged_command_not_run": "sudo bputil -d", "manual_check": "Startup Security Utility in Recovery"},
        )
    payload, reason = shell.json_of(["system_profiler", "-json", "SPiBridgeDataType"], timeout=ctx.slow(3))
    if payload is None:
        return shell.unavailable("%s; this Mac may have no T2 controller" % reason)
    items = payload.get("SPiBridgeDataType") or []
    if not items:
        return {"status": "ok", "secure_boot": "not applicable", "reason": "no Apple T2 controller reported on this Mac"}
    entry = items[0]
    return {
        "status": "ok",
        "model": entry.get("ibridge_model_identifier"),
        "secure_boot": entry.get("ibridge_secure_boot"),
        "external_boot": entry.get("ibridge_boot_external"),
    }


def _guest_account():
    payload, reason = fsutil.read_plist("/Library/Preferences/com.apple.loginwindow.plist")
    if payload is None:
        return shell.unavailable(reason)
    return {
        "status": "ok",
        "guest_enabled": bool(payload.get("GuestEnabled")),
        "hide_admin_users": payload.get("HideAdminUsers"),
        "show_full_name": payload.get("SHOWFULLNAME"),
    }


def _remote_access():
    disabled, reason = fsutil.read_plist("/var/db/com.apple.xpc.launchd/disabled.plist")
    services = {}
    if disabled is None:
        for label, description in sorted(REMOTE_SERVICES.items()):
            services[label] = {"description": description, "state": "unknown", "reason": reason}
    else:
        for label, description in sorted(REMOTE_SERVICES.items()):
            if label in disabled:
                services[label] = {"description": description, "state": "disabled" if disabled[label] else "enabled"}
            else:
                services[label] = {"description": description, "state": "not_configured", "note": "no explicit override recorded; the launchd default applies"}
    ard, ard_reason = fsutil.read_plist("/Library/Preferences/com.apple.RemoteManagement.plist")
    remote_management = {"configured": bool(ard)} if ard is not None else shell.unavailable(ard_reason)
    if ard:
        remote_management.update({key: ard.get(key) for key in sorted(ard) if key.startswith("ARD")})
    return {
        "status": "ok",
        "source": "/var/db/com.apple.xpc.launchd/disabled.plist",
        "services": services,
        "remote_management": remote_management,
        "note": "authoritative service state needs launchctl print-disabled system, which requires root",
    }


def _sudoers():
    path = "/etc/sudoers"
    readable = os.access(path, os.R_OK)
    if not readable:
        return shell.requires_privileges(
            "/etc/sudoers and /etc/sudoers.d are readable only by root, so NOPASSWD entries cannot be enumerated without elevation",
            {"privileged_command_not_run": "sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d"},
        )
    text = fsutil.read_text(path) or ""
    hits = [number for number, line in enumerate(text.splitlines(), start=1) if "NOPASSWD" in line and not line.strip().startswith("#")]
    return {"status": "ok", "nopasswd_entry_count": len(hits), "lines": hits, "note": "presence only; rule contents are not reported"}


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {
        "status": "ok",
        "sip": _sip(ctx),
        "filevault": _filevault(ctx),
        "gatekeeper": _gatekeeper(ctx),
        "malware_definitions": _malware_definitions(),
        "software_updates": _software_updates(),
        "secure_boot": _secure_boot(ctx),
        "guest_account": _guest_account(),
        "remote_access": _remote_access(),
        "sudoers": _sudoers(),
    }

    findings = []
    sip = result["sip"]
    if isinstance(sip, dict) and sip.get("enabled") is False:
        findings.append(F.finding(
            "security",
            "critical",
            "System Integrity Protection is disabled",
            sip.get("output", "")[:200],
            "With SIP off, any process running as root can modify system binaries and persist below the level any user-space tool can detect.",
            "Re-enable from Recovery: csrutil enable",
            True,
            key="sip",
        ))
    filevault = result["filevault"]
    if isinstance(filevault, dict) and filevault.get("enabled") is False:
        findings.append(F.finding(
            "security",
            "critical",
            "FileVault is off",
            filevault.get("output", "")[:200],
            "Without full disk encryption, anyone with physical access to the machine can read every file including credential stores.",
            "System Settings > Privacy & Security > FileVault > Turn On",
            True,
            key="filevault",
        ))
    gatekeeper = result["gatekeeper"]
    if isinstance(gatekeeper, dict) and gatekeeper.get("assessments_enabled") is False:
        findings.append(F.finding(
            "security",
            "critical",
            "Gatekeeper assessments are disabled",
            gatekeeper.get("output", "")[:200],
            "Unsigned and unnotarised applications will launch without any check, which removes the main barrier against trojanised downloads.",
            compat.gatekeeper_reenable_command((sysinfo.macos_version() or {}).get("major")),
            True,
            key="gatekeeper",
        ))

    updates = result["software_updates"]
    if isinstance(updates, dict) and updates.get("status") == "ok":
        pending = updates.get("pending_count") or 0
        if pending:
            findings.append(F.finding(
                "security",
                "warning",
                "%s software updates are pending in the local cache" % pending,
                "; ".join(str(item.get("display_name")) for item in updates.get("pending_updates") or [])[:300] or "no per-update detail cached",
                "Pending Apple updates usually include XProtect and kernel level security fixes that only apply after installation and restart.",
                "softwareupdate -l   # this audit did not check online",
                True,
                key="pending-updates",
            ))

    guest = result["guest_account"]
    if isinstance(guest, dict) and guest.get("guest_enabled"):
        findings.append(F.finding(
            "security",
            "warning",
            "Guest account is enabled",
            "GuestEnabled is true in the login window preferences",
            "A guest session gives an unauthenticated local user a working desktop and network access from this machine.",
            "System Settings > Users & Groups > Guest User > off",
            True,
            key="guest",
        ))

    remote = result["remote_access"]
    if isinstance(remote, dict) and remote.get("services"):
        for label, entry in sorted(remote["services"].items()):
            if entry.get("state") == "enabled":
                findings.append(F.finding(
                    "security",
                    "warning",
                    "Remote access service enabled: %s" % entry["description"],
                    "%s is explicitly enabled in the launchd override database" % label,
                    "Each enabled remote access service is an authenticated network entry point into this machine that stays open on every network you join.",
                    "System Settings > General > Sharing",
                    True,
                    key="remote-%s" % label,
                ))

    result["findings"] = findings
    return result
