import json

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context


def _ndjson(text):
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, list):
            rows.extend(item for item in parsed if isinstance(item, dict))
        elif isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _engine(binary, ctx):
    if not shell.which(binary):
        return shell.unavailable("%s not found on PATH" % binary)
    probe = shell.run([binary, "info", "--format", "{{json .}}"], timeout=ctx.slow(2))
    if not probe["ok"]:
        return shell.unavailable("%s CLI is installed but its daemon did not respond: %s" % (binary, shell.failure_reason(probe)))
    info = {}
    try:
        info = json.loads(probe["stdout"]) or {}
    except ValueError:
        info = {}

    containers = _ndjson(shell.stdout_of([binary, "ps", "-a", "--format", "{{json .}}"], timeout=ctx.slow(2)))
    dangling_images = _ndjson(shell.stdout_of([binary, "images", "--filter", "dangling=true", "--format", "{{json .}}"], timeout=ctx.slow(2)))
    all_images = _ndjson(shell.stdout_of([binary, "images", "--format", "{{json .}}"], timeout=ctx.slow(2)))
    volumes = _ndjson(shell.stdout_of([binary, "volume", "ls", "--format", "{{json .}}"], timeout=ctx.slow(2)))
    dangling_volumes = _ndjson(shell.stdout_of([binary, "volume", "ls", "--filter", "dangling=true", "--format", "{{json .}}"], timeout=ctx.slow(2)))
    networks = _ndjson(shell.stdout_of([binary, "network", "ls", "--format", "{{json .}}"], timeout=ctx.slow(2)))

    running = [item for item in containers if str(item.get("State", item.get("Status", ""))).lower().startswith("running") or str(item.get("Status", "")).lower().startswith("up")]
    stopped = [item for item in containers if item not in running]

    df_res = shell.run([binary, "system", "df"], timeout=ctx.slow(3))
    df_rows = []
    if df_res["ok"]:
        for line in df_res["stdout"].splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                df_rows.append({"type": " ".join(parts[:-4]), "total": parts[-4], "active": parts[-3], "size": parts[-2], "reclaimable": parts[-1]})

    default_networks = {"bridge", "host", "none", "podman"}
    orphaned_networks = [item for item in networks if (item.get("Name") or "") not in default_networks and not (item.get("Name") or "").startswith("orbstack")]

    return {
        "status": "ok",
        "engine": binary,
        "server_version": info.get("ServerVersion") or (info.get("version") or {}).get("Version"),
        "storage_driver": info.get("Driver"),
        "root_dir": info.get("DockerRootDir") or (info.get("store") or {}).get("graphRoot"),
        "containers": {
            "total": len(containers),
            "running": [{"name": item.get("Names") or item.get("Name"), "image": item.get("Image"), "status": item.get("Status")} for item in running],
            "stopped": [{"name": item.get("Names") or item.get("Name"), "image": item.get("Image"), "status": item.get("Status")} for item in stopped],
        },
        "images": {"total": len(all_images), "dangling": len(dangling_images), "dangling_ids": sorted(str(item.get("ID") or item.get("Id") or "")[:19] for item in dangling_images)},
        "volumes": {"total": len(volumes), "unused": len(dangling_volumes), "unused_names": sorted(str(item.get("Name") or "") for item in dangling_volumes)},
        "networks": {"total": len(networks), "non_default": sorted(str(item.get("Name") or "") for item in orphaned_networks)},
        "disk_usage": df_rows or shell.unavailable(shell.failure_reason(df_res)),
        "prune_policy": "this audit never prunes; the commands below are printed for you to run deliberately",
    }


def _colima(ctx):
    if not shell.which("colima"):
        return shell.unavailable("colima not found on PATH")
    res = shell.run(["colima", "status"], timeout=ctx.slow(2))
    text = (res["stdout"] + res["stderr"]).strip()
    return {
        "status": "ok" if res["ok"] else "unavailable",
        "reason": None if res["ok"] else shell.failure_reason(res),
        "output": text[:1000],
        "profiles_dir": fsutil.tilde("~/.colima") if fsutil.exists(fsutil.expand("~/.colima")) else None,
    }


def _orbstack(ctx):
    app = fsutil.exists("/Applications/OrbStack.app")
    binary = shell.which("orbctl") or shell.which("orb")
    if not app and not binary:
        return shell.unavailable("OrbStack is not installed")
    res = shell.run([binary or "orb", "status"], timeout=ctx.slow(2)) if binary else None
    data = {"status": "ok", "app_installed": app, "cli": fsutil.tilde(binary) if binary else None}
    if res is not None:
        data["state"] = (res["stdout"] + res["stderr"]).strip()[:400] if not res["skipped_reason"] else None
        data["reachable"] = res["ok"]
    data_dir = fsutil.expand("~/.orbstack/data")
    data["data_dir"] = fsutil.tilde(data_dir) if fsutil.exists(data_dir) else None
    return data


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {"status": "ok", "findings": []}
    result["docker"] = _engine("docker", ctx)
    result["podman"] = _engine("podman", ctx)
    result["colima"] = _colima(ctx)
    result["orbstack"] = _orbstack(ctx)

    findings = []
    for engine_key in ("docker", "podman"):
        engine = result[engine_key]
        if not isinstance(engine, dict) or engine.get("status") != "ok":
            continue
        stopped = engine["containers"]["stopped"]
        if len(stopped) >= 5:
            findings.append(F.finding(
                "containers",
                "info",
                "%d stopped %s containers are retained" % (len(stopped), engine_key),
                ", ".join(str(item["name"]) for item in stopped[:8]),
                "Stopped containers keep their writable layer on disk, which is invisible in Finder and grows with every throwaway run.",
                "%s container prune   # removes stopped containers only" % engine_key,
                False,
                key="%s-stopped" % engine_key,
            ))
        if engine["images"]["dangling"]:
            findings.append(F.finding(
                "containers",
                "info",
                "%d dangling %s images" % (engine["images"]["dangling"], engine_key),
                "untagged image layers left behind by rebuilds",
                "Dangling layers are unreferenced by any tag and can never be used again, but still occupy the container disk image.",
                "%s image prune" % engine_key,
                False,
                key="%s-dangling" % engine_key,
            ))
        if engine["volumes"]["unused"]:
            findings.append(F.finding(
                "containers",
                "warning",
                "%d unused %s volumes" % (engine["volumes"]["unused"], engine_key),
                ", ".join(engine["volumes"]["unused_names"][:8]),
                "Unused volumes often hold database state from deleted stacks; they consume space and may contain data you have forgotten about.",
                "%s volume ls -f dangling=true   # inspect before: %s volume prune" % (engine_key, engine_key),
                False,
                key="%s-volumes" % engine_key,
            ))

    result["findings"] = findings
    return result
