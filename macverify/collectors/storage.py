import os
import re

from .. import findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context

SKIP_FILESYSTEMS = ("devfs", "map", "/dev/disk-auto")

RECLAIMABLE_PATHS = (
    ("user_caches", "~/Library/Caches"),
    ("xcode_derived_data", "~/Library/Developer/Xcode/DerivedData"),
    ("xcode_archives", "~/Library/Developer/Xcode/Archives"),
    ("xcode_device_support", "~/Library/Developer/Xcode/iOS DeviceSupport"),
    ("core_simulator", "~/Library/Developer/CoreSimulator"),
    ("docker_desktop_data", "~/Library/Containers/com.docker.docker/Data"),
    ("orbstack_data", "~/.orbstack/data"),
    ("colima_data", "~/.colima"),
    ("podman_machine", "~/.local/share/containers"),
    ("pip_cache", "~/Library/Caches/pip"),
    ("npm_cache", "~/.npm/_cacache"),
    ("yarn_cache", "~/Library/Caches/Yarn"),
    ("cargo_registry", "~/.cargo/registry"),
    ("go_module_cache", "~/go/pkg/mod"),
    ("gradle_cache", "~/.gradle/caches"),
    ("trash", "~/.Trash"),
)


def _df(ctx):
    res = shell.run(["df", "-k"], timeout=ctx.timeout)
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    volumes = []
    for line in res["stdout"].splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        filesystem, blocks, used, available, capacity = parts[0], parts[1], parts[2], parts[3], parts[4]
        mount = parts[8]
        if filesystem in SKIP_FILESYSTEMS or filesystem.startswith("map "):
            continue
        try:
            total_bytes = int(blocks) * 1024
            used_bytes = int(used) * 1024
            free_bytes = int(available) * 1024
        except ValueError:
            continue
        network = bool(re.match(r"^(//|\w+@|.+:/)", filesystem)) or filesystem.startswith("afp") or filesystem.startswith("smb")
        volumes.append({
            "filesystem": filesystem,
            "mount_point": mount,
            "total_bytes": total_bytes,
            "total_human": fsutil.human_bytes(total_bytes),
            "used_bytes": used_bytes,
            "used_human": fsutil.human_bytes(used_bytes),
            "free_bytes": free_bytes,
            "free_human": fsutil.human_bytes(free_bytes),
            "capacity_used": capacity,
            "free_percent": round(100.0 * free_bytes / total_bytes, 1) if total_bytes else None,
            "network_mount": network,
        })
    return sorted(volumes, key=lambda item: item["mount_point"])


def _snapshots(ctx):
    res = shell.run(["tmutil", "listlocalsnapshots", "/"], timeout=ctx.slow(2))
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    names = [line.strip() for line in res["stdout"].splitlines() if line.strip() and "com.apple" in line]
    detail = shell.run(["diskutil", "apfs", "listSnapshots", "/"], timeout=ctx.slow(2))
    reclaimable = None
    if detail["ok"]:
        total = 0
        found = False
        for match in re.finditer(r"Purgeable Size:\s+[\d.]+ \w+ \((\d+) Bytes\)", detail["stdout"]):
            total += int(match.group(1))
            found = True
        reclaimable = total if found else None
    return {
        "status": "ok",
        "count": len(names),
        "snapshots": names,
        "reclaimable_bytes": reclaimable,
        "reclaimable_human": fsutil.human_bytes(reclaimable),
        "reclaimable_status": None if reclaimable is not None else shell.requires_privileges(
            "per-snapshot purgeable size is reported by diskutil only for privileged callers on this system",
            {"privileged_command_not_run": "sudo diskutil apfs listSnapshots /"},
        ),
    }


def _du_multi(paths, timeout):
    existing = [path for path in paths if fsutil.exists(path)]
    if not existing:
        return {}, None
    res = shell.run(["du", "-sk"] + existing, timeout=timeout)
    if not res["stdout"].strip():
        return {}, res["skipped_reason"] or shell.failure_reason(res)
    sizes = {}
    for line in res["stdout"].splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        try:
            sizes[parts[1].strip()] = int(parts[0].strip()) * 1024
        except ValueError:
            continue
    return sizes, None


def _home_tree(ctx):
    home = fsutil.home()
    res = shell.run(["du", "-kx", "-d", "2", home], timeout=ctx.slow(5))
    if not res["stdout"].strip():
        return shell.unavailable(res["skipped_reason"] or shell.failure_reason(res)), []
    entries = []
    for line in res["stdout"].splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0].strip()) * 1024
        except ValueError:
            continue
        path = parts[1].strip()
        if path == home:
            continue
        entries.append({"path": fsutil.tilde(path), "bytes": size, "human": fsutil.human_bytes(size), "depth": path[len(home):].count(os.sep)})
    ranked = sorted(entries, key=lambda item: (-item["bytes"], item["path"]))[:20]
    return {"status": "ok", "scanned_root": "~", "max_depth": 2, "skipped": "other filesystems, network mounts and unreadable directories", "entry_count": len(entries)}, ranked


def _node_modules(ctx):
    home = fsutil.home()
    res = shell.run(["find", home, "-maxdepth", "6", "-type", "d", "-name", "node_modules", "-prune", "-print"], timeout=ctx.slow(4))
    if not res["stdout"].strip():
        return {"status": "ok" if res["rc"] == 0 else "unavailable", "reason": None if res["rc"] == 0 else (res["skipped_reason"] or shell.failure_reason(res)), "count": 0, "total_bytes": 0, "total_human": "0 B", "largest": []}
    paths = sorted(line for line in res["stdout"].splitlines() if line.strip())
    capped = paths[:300]
    sizes, reason = _du_multi(capped, ctx.slow(5))
    total = sum(sizes.values())
    largest = sorted(({"path": fsutil.tilde(path), "bytes": size, "human": fsutil.human_bytes(size)} for path, size in sizes.items()), key=lambda item: (-item["bytes"], item["path"]))[:10]
    return {
        "status": "ok",
        "count": len(paths),
        "sized_count": len(sizes),
        "truncated": len(paths) > len(capped),
        "total_bytes": total,
        "total_human": fsutil.human_bytes(total),
        "largest": largest,
        "size_reason": reason,
    }


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {"status": "ok", "findings": []}
    result["volumes"] = _df(ctx)
    result["apfs_snapshots"] = _snapshots(ctx)

    scan_meta, ranked = _home_tree(ctx)
    result["home_scan"] = scan_meta
    result["largest_home_directories"] = ranked

    brew = sysinfo.homebrew()
    reclaimable_targets = [(label, os.path.expanduser(path)) for label, path in RECLAIMABLE_PATHS]
    if brew.get("present"):
        cache = shell.stdout_of([brew["binary"], "--cache"], timeout=ctx.slow(2), env={"HOMEBREW_OFFLINE": "1"})
        if cache and cache.strip():
            reclaimable_targets.append(("homebrew_cache", cache.strip()))
    sizes, reason = _du_multi([path for _, path in reclaimable_targets], ctx.slow(6))
    reclaimables = []
    for label, path in reclaimable_targets:
        size = sizes.get(path)
        reclaimables.append({
            "label": label,
            "path": fsutil.tilde(path),
            "exists": fsutil.exists(path),
            "bytes": size,
            "human": fsutil.human_bytes(size),
        })
    node_modules = _node_modules(ctx)
    result["node_modules"] = node_modules

    reclaimable_total = sum(item["bytes"] or 0 for item in reclaimables) + (node_modules.get("total_bytes") or 0)
    snapshot_reclaim = result["apfs_snapshots"].get("reclaimable_bytes") if isinstance(result["apfs_snapshots"], dict) else None
    if snapshot_reclaim:
        reclaimable_total += snapshot_reclaim
    result["reclaimable"] = {
        "categories": sorted(reclaimables, key=lambda item: (-(item["bytes"] or 0), item["label"])),
        "node_modules_bytes": node_modules.get("total_bytes"),
        "snapshot_bytes": snapshot_reclaim,
        "total_bytes": reclaimable_total,
        "total_human": fsutil.human_bytes(reclaimable_total),
        "measurement_reason": reason,
        "note": "sizes are measured only; nothing was deleted",
    }

    findings = []
    volumes = result["volumes"] if isinstance(result["volumes"], list) else []
    for volume in volumes:
        if volume["network_mount"] or not volume["total_bytes"]:
            continue
        free_percent = volume["free_percent"]
        if free_percent is None:
            continue
        if free_percent < 5:
            severity = "critical"
        elif free_percent < 10:
            severity = "warning"
        else:
            continue
        findings.append(F.finding(
            "storage",
            severity,
            "Volume %s is %.1f%% free" % (volume["mount_point"], free_percent),
            "%s free of %s on %s" % (volume["free_human"], volume["total_human"], volume["filesystem"]),
            "Below roughly ten percent free, APFS cannot keep purgeable space available and the system starts refusing writes and updates.",
            "Review the reclaimable totals in this report before deleting anything",
            True,
            key="volume-%s" % volume["mount_point"],
        ))

    if reclaimable_total > 20 * 1024 ** 3:
        biggest = ", ".join("%s %s" % (item["label"], item["human"]) for item in result["reclaimable"]["categories"][:4] if item["bytes"])
        findings.append(F.finding(
            "storage",
            "warning",
            "About %s of caches and build artefacts are reclaimable" % fsutil.human_bytes(reclaimable_total),
            "largest: %s; node_modules %s across %s directories" % (biggest, node_modules.get("total_human"), node_modules.get("count")),
            "Developer caches grow without bound and are the usual cause of a full startup volume on a working machine.",
            "rm -rf ~/Library/Developer/Xcode/DerivedData   # regenerated on next build",
            True,
            key="reclaimable-total",
        ))
    elif reclaimable_total > 5 * 1024 ** 3:
        findings.append(F.finding(
            "storage",
            "info",
            "About %s of caches and build artefacts are reclaimable" % fsutil.human_bytes(reclaimable_total),
            "node_modules %s across %s directories" % (node_modules.get("total_human"), node_modules.get("count")),
            "These directories are all regenerable, so they are the cheapest space to recover when the volume fills.",
            "du -sh ~/Library/Caches ~/Library/Developer/Xcode/DerivedData",
            True,
            key="reclaimable-total",
        ))

    snapshots = result["apfs_snapshots"]
    if isinstance(snapshots, dict) and snapshots.get("count", 0) > 5:
        findings.append(F.finding(
            "storage",
            "info",
            "%d local APFS snapshots are retained" % snapshots["count"],
            "oldest: %s" % (snapshots["snapshots"][0] if snapshots.get("snapshots") else "unknown"),
            "Local Time Machine snapshots hold on to deleted file blocks, so freeing space has no effect until they expire.",
            "tmutil listlocalsnapshots /   # macOS thins these automatically under space pressure",
            True,
            key="snapshots",
        ))

    result["findings"] = findings
    return result
