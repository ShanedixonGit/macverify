import os
import sqlite3

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

SERVICES = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic keyboard and mouse events",
    "kTCCServiceDeveloperTool": "Developer Tools",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceCamera": "Camera",
}

HIGH_RISK = ("kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility", "kTCCServiceScreenCapture", "kTCCServiceListenEvent", "kTCCServicePostEvent")

# Applications that commonly hold one of the high-risk grants. The list is an
# annotation, not a filter: every installed bundle is enumerated so the audit
# works on a Mac whose tools nobody anticipated.
NOTABLE_APPS = (
    "Terminal.app", "iTerm.app", "Warp.app", "Ghostty.app", "Alacritty.app", "kitty.app", "WezTerm.app", "Hyper.app",
    "Visual Studio Code.app", "Cursor.app", "Zed.app", "Sublime Text.app", "Xcode.app", "Nova.app",
    "IntelliJ IDEA.app", "PyCharm.app", "PyCharm CE.app", "DataGrip.app", "WebStorm.app", "RustRover.app",
    "Docker.app", "OrbStack.app", "UTM.app", "VMware Fusion.app", "Parallels Desktop.app",
    "Hammerspoon.app", "Karabiner-Elements.app", "Raycast.app", "Alfred 5.app", "BetterTouchTool.app",
    "Keyboard Maestro.app", "Rectangle.app", "CleanShot X.app", "Loom.app", "zoom.us.app", "Slack.app",
    "Claude.app", "ChatGPT.app", "Obsidian.app", "1Password.app", "Bartender 5.app",
)

APP_DIRS = ("/Applications", "/Applications/Utilities", "/System/Applications", "~/Applications")


def _open_db(path):
    if not fsutil.exists(path):
        return None, "database not present at %s" % fsutil.tilde(path)
    if not os.access(path, os.R_OK):
        return None, "not readable without Full Disk Access"
    try:
        connection = sqlite3.connect("file:%s?mode=ro&immutable=1" % path, uri=True, timeout=2)
    except sqlite3.Error as exc:
        return None, "sqlite open failed: %s" % exc.__class__.__name__
    return connection, None


def _read_tcc(path):
    connection, reason = _open_db(path)
    if connection is None:
        return shell.requires_privileges(reason, {"database": fsutil.tilde(path)})
    grants = []
    try:
        cursor = connection.execute("SELECT service, client, client_type, auth_value FROM access")
        rows = cursor.fetchall()
        value_key = "auth_value"
    except sqlite3.Error:
        try:
            cursor = connection.execute("SELECT service, client, client_type, allowed FROM access")
            rows = cursor.fetchall()
            value_key = "allowed"
        except sqlite3.Error as exc:
            connection.close()
            return shell.unavailable("TCC schema not readable: %s" % exc.__class__.__name__)
    for service, client, client_type, value in rows:
        if service not in SERVICES:
            continue
        allowed = value in (2, 1) if value_key == "auth_value" else bool(value)
        grants.append({
            "service": service,
            "permission": SERVICES[service],
            "client": client,
            "client_type": "bundle_id" if client_type == 0 else "executable_path",
            "granted": allowed,
        })
    connection.close()
    return {"status": "ok", "database": fsutil.tilde(path), "grant_count": len(grants), "grants": sorted(grants, key=lambda item: (item["permission"], item["client"] or ""))}


def _installed_applications(limit=400):
    """Every .app bundle in the standard locations, on any Mac, in one pass."""
    notable = set(NOTABLE_APPS)
    found = {}
    truncated = False
    for directory in APP_DIRS:
        base = os.path.expanduser(directory)
        if not fsutil.exists(base):
            continue
        for name in fsutil.listdir(base):
            if not name.endswith(".app"):
                continue
            if len(found) >= limit:
                truncated = True
                break
            found.setdefault(name, {
                "application": name,
                "path": fsutil.tilde(os.path.join(base, name)),
                "commonly_privileged": name in notable,
            })
    apps = sorted(found.values(), key=lambda entry: entry["application"])
    return apps, truncated


def collect(ctx=None):
    ctx = default_context(ctx)
    user_db = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
    result = {
        "status": "ok",
        "note": "TCC databases are protected by Full Disk Access; this audit reads them only if already permitted and never elevates",
        "user_database": _read_tcc(user_db),
        "system_database": _read_tcc(system_db),
    }
    applications, truncated = _installed_applications()
    result["installed_applications"] = {
        "count": len(applications),
        "truncated": truncated,
        "source": "directory listing of %s" % ", ".join(APP_DIRS),
        "applications": applications,
    }
    candidates = [item for item in applications if item["commonly_privileged"]]

    readable = [entry for entry in (result["user_database"], result["system_database"]) if isinstance(entry, dict) and entry.get("status") == "ok"]
    if not readable:
        result["manual_check"] = {
            "reason": "no TCC database was readable from this process",
            "where": "System Settings > Privacy & Security > Full Disk Access / Accessibility / Screen Recording / Input Monitoring",
            "applications_worth_checking": [item["application"] for item in candidates] or [item["application"] for item in applications[:40]],
        }
        result["status"] = "requires_privileges"

    findings = []
    for entry in readable:
        for grant in entry["grants"]:
            if grant["granted"] and grant["service"] in HIGH_RISK:
                findings.append(F.finding(
                    "permissions",
                    "warning",
                    "%s granted to %s" % (grant["permission"], grant["client"]),
                    "%s in %s" % (grant["client_type"], entry["database"]),
                    "This class of grant lets the application read every file or observe and synthesise input for every other application, so it inherits the trust of everything it runs.",
                    "System Settings > Privacy & Security > %s" % grant["permission"],
                    True,
                    key="%s-%s" % (grant["service"], grant["client"]),
                ))
    if not readable:
        findings.append(F.finding(
            "permissions",
            "info",
            "Privacy permissions could not be enumerated",
            "TCC databases are unreadable without Full Disk Access for this process",
            "Without the TCC tables there is no programmatic view of which tools hold Full Disk Access, Accessibility or Screen Recording.",
            "Review the listed applications manually in System Settings > Privacy & Security",
            True,
            key="tcc-unreadable",
        ))

    result["findings"] = findings
    return result
