import re

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

FIREWALL_BINARY = "/usr/libexec/ApplicationFirewall/socketfilterfw"

DEFAULT_HOSTS = {
    ("127.0.0.1", "localhost"),
    ("255.255.255.255", "broadcasthost"),
    ("::1", "localhost"),
    ("fe80::1%lo0", "localhost"),
}

SENSITIVE_PORTS = {
    22: "ssh", 23: "telnet", 25: "smtp", 445: "smb", 548: "afp", 631: "cups",
    1433: "mssql", 2375: "docker api (plaintext)", 2376: "docker api (tls)",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc / screen sharing",
    5984: "couchdb", 6379: "redis", 8020: "hdfs", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def _parse_address(node):
    text = node.strip()
    if text.startswith("["):
        match = re.match(r"^\[([^\]]*)\]:(\d+|\*)$", text)
        if match:
            return match.group(1), match.group(2)
    if text.count(":") > 1:
        host, _, port = text.rpartition(":")
        return host, port
    host, _, port = text.rpartition(":")
    return host or "*", port


def _exposure(host):
    if host in ("*", "0.0.0.0", "::", ""):
        return "all_interfaces"
    if host in ("127.0.0.1", "::1") or host.startswith("127."):
        return "loopback"
    return "specific_interface"


def _listeners(ctx):
    res = shell.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "cnpLt"], timeout=ctx.slow(2))
    if res["skipped_reason"]:
        return shell.unavailable(res["skipped_reason"]), []
    if not res["stdout"].strip():
        return shell.unavailable(shell.failure_reason(res)), []
    merged = {}
    order = []
    current = {}
    for line in res["stdout"].splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            current = {"pid": value, "process": None, "user": None, "family": None}
        elif tag == "c":
            current["process"] = value
        elif tag == "L":
            current["user"] = value
        elif tag == "t":
            current["family"] = value
        elif tag == "n":
            host, port = _parse_address(value)
            key = (current.get("process"), current.get("pid"), value)
            if key not in merged:
                merged[key] = {
                    "process": current.get("process"),
                    "pid": current.get("pid"),
                    "user": current.get("user"),
                    "protocol": "TCP",
                    "families": [],
                    "address": value,
                    "host": host,
                    "port": int(port) if str(port).isdigit() else port,
                    "exposure": _exposure(host),
                }
                order.append(key)
            family = current.get("family")
            if family and family not in merged[key]["families"]:
                merged[key]["families"].append(family)
    grouped = {"loopback": [], "all_interfaces": [], "specific_interface": []}
    for key in order:
        entry = merged[key]
        entry["families"] = sorted(entry["families"])
        grouped[entry["exposure"]].append(entry)
    for bucket in grouped:
        grouped[bucket] = sorted(grouped[bucket], key=lambda item: (item["port"] if isinstance(item["port"], int) else 0, item["process"] or ""))
    summary = {
        "status": "ok",
        "scope_note": "lsof without elevated privileges reports sockets owned by this user only; listeners owned by other users are not visible",
        "counts": {key: len(value) for key, value in grouped.items()},
        "by_exposure": grouped,
    }
    return summary, grouped["all_interfaces"]


def _firewall(ctx):
    if not fsutil.exists(FIREWALL_BINARY):
        return shell.unavailable("socketfilterfw is not present on this system")
    data = {}
    for key, flag in (("global_state", "--getglobalstate"), ("block_all", "--getblockall"), ("stealth_mode", "--getstealthmode"), ("allow_signed", "--getallowsigned")):
        res = shell.run([FIREWALL_BINARY, flag], timeout=ctx.timeout)
        if res["ok"]:
            data[key] = res["stdout"].strip().splitlines()[0] if res["stdout"].strip() else None
        else:
            data[key] = shell.requires_privileges(shell.failure_reason(res))
    listing = shell.run([FIREWALL_BINARY, "--listapps"], timeout=ctx.slow(2))
    if listing["ok"]:
        apps = []
        current = None
        for line in listing["stdout"].splitlines():
            stripped = line.strip()
            match = re.match(r"^\d+\s*:\s*(.+)$", stripped)
            if match:
                current = {"application": match.group(1), "permission": None}
                apps.append(current)
            elif current is not None and stripped.startswith("("):
                current["permission"] = stripped.strip("()")
        data["allowed_apps"] = {"count": len(apps), "apps": apps}
    else:
        data["allowed_apps"] = shell.requires_privileges(shell.failure_reason(listing))
    plist, plist_reason = fsutil.read_plist("/Library/Preferences/com.apple.alf.plist")
    if plist:
        data["preference_global_state"] = plist.get("globalstate")
        data["preference_stealth"] = plist.get("stealthenabled")
    else:
        data["preference_file"] = shell.unavailable(plist_reason)
    enabled = str(data.get("global_state") or "")
    data["enabled"] = ("enabled" in enabled.lower()) or (data.get("preference_global_state") in (1, 2))
    return data


def _hosts():
    text = fsutil.read_text("/etc/hosts")
    if text is None:
        return shell.unavailable("/etc/hosts is not readable")
    custom = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        address = parts[0]
        for name in parts[1:]:
            if (address, name) in DEFAULT_HOSTS:
                continue
            custom.append({"line": number, "address": address, "hostname": name})
    return {"status": "ok", "custom_entry_count": len(custom), "custom_entries": custom}


def _vpn_and_proxy(ctx):
    data = {}
    connections = shell.run(["scutil", "--nc", "list"], timeout=ctx.timeout)
    if connections["ok"]:
        rows = []
        for line in connections["stdout"].splitlines():
            match = re.match(r"^\s*(\*|\s)\s*\((\w+)\)\s+(\S+)\s+(\S+)\s+---\s+(.*)$", line)
            if match:
                rows.append({"enabled": match.group(1) == "*", "state": match.group(2), "identifier": match.group(3), "type": match.group(4), "name": match.group(5).strip()})
        data["vpn_configurations"] = {"count": len(rows), "configurations": rows, "active": [item for item in rows if item["state"].lower() == "connected"]}
    else:
        data["vpn_configurations"] = shell.unavailable(shell.failure_reason(connections))

    proxy = shell.run(["scutil", "--proxy"], timeout=ctx.timeout)
    if proxy["ok"]:
        values = {}
        for line in proxy["stdout"].splitlines():
            match = re.match(r"^\s*([A-Za-z0-9]+)\s*:\s*(.+?)\s*$", line)
            if match and not match.group(2).startswith("<"):
                values[match.group(1)] = match.group(2)
        data["system_proxy"] = {
            "values": values,
            "http_enabled": values.get("HTTPEnable") == "1",
            "https_enabled": values.get("HTTPSEnable") == "1",
            "socks_enabled": values.get("SOCKSEnable") == "1",
            "auto_config_enabled": values.get("ProxyAutoConfigEnable") == "1",
        }
    else:
        data["system_proxy"] = shell.unavailable(shell.failure_reason(proxy))

    services = shell.run(["networksetup", "-listallnetworkservices"], timeout=ctx.slow(2))
    if services["ok"]:
        names = [line.strip() for line in services["stdout"].splitlines()[1:] if line.strip() and not line.startswith("*")]
        per_service = []
        for name in names[:12]:
            entry = {"service": name}
            for label, flag in (("web_proxy", "-getwebproxy"), ("secure_web_proxy", "-getsecurewebproxy"), ("socks_proxy", "-getsocksfirewallproxy")):
                res = shell.run(["networksetup", flag, name], timeout=ctx.timeout)
                if res["ok"]:
                    parsed = {}
                    for line in res["stdout"].splitlines():
                        if ":" in line:
                            key, _, value = line.partition(":")
                            parsed[key.strip().lower().replace(" ", "_")] = value.strip()
                    entry[label] = parsed
            per_service.append(entry)
        data["network_services"] = {"count": len(names), "services": names, "proxy_settings": per_service}
    else:
        data["network_services"] = shell.unavailable(shell.failure_reason(services))
    return data


def _dns(ctx):
    res = shell.run(["scutil", "--dns"], timeout=ctx.timeout)
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    resolvers = []
    current = None
    for line in res["stdout"].splitlines():
        stripped = line.strip()
        if stripped.startswith("resolver #"):
            current = {"resolver": stripped, "nameservers": [], "domain": None}
            resolvers.append(current)
        elif current is not None:
            match = re.match(r"^nameserver\[\d+\]\s*:\s*(\S+)$", stripped)
            if match:
                current["nameservers"].append(match.group(1))
            domain = re.match(r"^domain\s*:\s*(\S+)$", stripped)
            if domain:
                current["domain"] = domain.group(1)
    unique = sorted({server for item in resolvers for server in item["nameservers"]})
    return {"status": "ok", "resolver_count": len(resolvers), "resolvers": resolvers[:12], "unique_nameservers": unique}


def collect(ctx=None):
    ctx = default_context(ctx)
    listeners, exposed = _listeners(ctx)
    result = {
        "status": "ok",
        "listening_sockets": listeners,
        "firewall": _firewall(ctx),
        "hosts_file": _hosts(),
        "dns": _dns(ctx),
    }
    result.update(_vpn_and_proxy(ctx))

    findings = []
    for entry in exposed:
        port = entry.get("port")
        service = SENSITIVE_PORTS.get(port)
        severity = "critical" if service else "warning"
        findings.append(F.finding(
            "network",
            severity,
            "%s listens on all interfaces at port %s" % (entry.get("process") or "unknown process", port),
            "%s bound to %s (pid %s%s)" % (entry.get("process"), entry.get("address"), entry.get("pid"), ", known service: %s" % service if service else ""),
            "A socket bound to 0.0.0.0 accepts connections from any host that can reach this machine, including untrusted networks such as cafe and conference wifi.",
            "Bind the service to 127.0.0.1 instead, or enable the application firewall for incoming connections",
            True,
            key="listener-%s-%s" % (entry.get("process"), port),
        ))

    firewall = result["firewall"]
    if isinstance(firewall, dict) and firewall.get("enabled") is False:
        findings.append(F.finding(
            "network",
            "warning",
            "Application firewall is disabled",
            str(firewall.get("global_state") or firewall.get("preference_global_state")),
            "With the application firewall off, every listening service on this machine is reachable from the local network without prompting.",
            "System Settings > Network > Firewall (or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on)",
            True,
            key="firewall-off",
        ))

    hosts = result["hosts_file"]
    if isinstance(hosts, dict) and hosts.get("custom_entry_count"):
        findings.append(F.finding(
            "network",
            "info",
            "%d non-default entries in /etc/hosts" % hosts["custom_entry_count"],
            "; ".join("%s -> %s" % (item["hostname"], item["address"]) for item in hosts["custom_entries"][:10]),
            "Host file overrides silently redirect names for every application, and are a common cause of confusing certificate and connectivity errors months later.",
            "cat /etc/hosts",
            True,
            key="hosts-custom",
        ))

    proxy = result.get("system_proxy")
    if isinstance(proxy, dict) and (proxy.get("http_enabled") or proxy.get("https_enabled") or proxy.get("socks_enabled")):
        findings.append(F.finding(
            "network",
            "info",
            "A system proxy is configured and enabled",
            "http=%s https=%s socks=%s" % (proxy.get("http_enabled"), proxy.get("https_enabled"), proxy.get("socks_enabled")),
            "All proxied traffic is visible to whatever terminates the proxy, which matters if it was left over from a debugging session.",
            "scutil --proxy",
            True,
            key="proxy-enabled",
        ))

    result["findings"] = findings
    return result
