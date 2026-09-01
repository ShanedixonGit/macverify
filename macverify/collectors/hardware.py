import re

from .. import findings as F
from .. import fsutil, shell, sysinfo
from ..context import default_context

THERMAL_KEYS = ("CPU_Scheduler_Limit", "CPU_Available_CPUs", "CPU_Speed_Limit")


def _sysctl_map(names, timeout):
    values = {}
    for name in names:
        text = shell.stdout_of(["sysctl", "-n", name], timeout=timeout)
        values[name] = text.strip() if text else None
    return values


def _hardware_profile(ctx):
    payload, reason = shell.json_of(["system_profiler", "-json", "SPHardwareDataType"], timeout=ctx.slow(3))
    if payload is None:
        return shell.unavailable(reason)
    items = payload.get("SPHardwareDataType") or []
    if not items:
        return shell.unavailable("system_profiler returned no hardware entries")
    entry = items[0]
    return {
        "model_name": entry.get("machine_name"),
        "model_identifier": entry.get("machine_model"),
        "chip": entry.get("chip_type") or entry.get("cpu_type"),
        "cores": entry.get("number_processors"),
        "memory": entry.get("physical_memory"),
        "serial_present": bool(entry.get("serial_number")),
        "boot_rom": entry.get("boot_rom_version"),
        "os_loader": entry.get("os_loader_version"),
    }


def _memory(ctx):
    sysctls = _sysctl_map(["hw.memsize", "hw.pagesize", "vm.swapusage"], ctx.timeout)
    total = int(sysctls["hw.memsize"]) if (sysctls["hw.memsize"] or "").isdigit() else None
    vm_text = shell.stdout_of(["vm_stat"], timeout=ctx.timeout)
    pages = {}
    page_size = int(sysctls["hw.pagesize"]) if (sysctls["hw.pagesize"] or "").isdigit() else 4096
    if vm_text:
        header = re.search(r"page size of (\d+) bytes", vm_text)
        if header:
            page_size = int(header.group(1))
        for line in vm_text.splitlines()[1:]:
            match = re.match(r'^"?([^":]+)"?:\s+(\d+)\.', line.strip())
            if match:
                pages[match.group(1).strip()] = int(match.group(2))
    def size_of(key):
        return pages[key] * page_size if key in pages else None

    wired = size_of("Pages wired down")
    active = size_of("Pages active")
    inactive = size_of("Pages inactive")
    free = size_of("Pages free")
    speculative = size_of("Pages speculative")
    compressed = size_of("Pages occupied by compressor")
    used = None
    if None not in (wired, active, compressed):
        used = wired + active + compressed
    available = total - used if (total and used) else None
    pressure_percent = round(100.0 * used / total, 1) if (total and used) else None

    swap = {"raw": sysctls["vm.swapusage"]}
    if sysctls["vm.swapusage"]:
        for key in ("total", "used", "free"):
            match = re.search(r"%s = ([\d.]+)([KMG])" % key, sysctls["vm.swapusage"])
            if match:
                scale = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[match.group(2)]
                swap[key + "_bytes"] = int(float(match.group(1)) * scale)
                swap[key + "_human"] = fsutil.human_bytes(swap[key + "_bytes"])
        swap["encrypted"] = "(encrypted)" in sysctls["vm.swapusage"]

    free_percent = None
    quick = shell.run(["memory_pressure", "-Q"], timeout=ctx.timeout)
    if quick["ok"]:
        match = re.search(r"free percentage:\s*(\d+)%", quick["stdout"])
        if match:
            free_percent = int(match.group(1))

    return {
        "total_bytes": total,
        "total_human": fsutil.human_bytes(total),
        "used_bytes": used,
        "used_human": fsutil.human_bytes(used),
        "available_bytes": available,
        "available_human": fsutil.human_bytes(available),
        "page_size": page_size,
        "breakdown": {
            "wired": fsutil.human_bytes(wired),
            "active": fsutil.human_bytes(active),
            "inactive": fsutil.human_bytes(inactive),
            "speculative": fsutil.human_bytes(speculative),
            "compressed": fsutil.human_bytes(compressed),
            "free": fsutil.human_bytes(free),
        },
        "memory_pressure_percent": pressure_percent,
        "system_free_percent": free_percent,
        "swap": swap,
    }


def _uptime(ctx):
    boot = shell.stdout_of(["sysctl", "-n", "kern.boottime"], timeout=ctx.timeout)
    seconds = None
    if boot:
        match = re.search(r"sec\s*=\s*(\d+)", boot)
        if match:
            import time

            seconds = int(time.time()) - int(match.group(1))
    text = shell.stdout_of(["uptime"], timeout=ctx.timeout)
    return {
        "boot_time_utc": fsutil.iso_time(int(boot and re.search(r"sec\s*=\s*(\d+)", boot).group(1)) if boot and re.search(r"sec\s*=\s*(\d+)", boot) else None),
        "uptime_seconds": seconds,
        "uptime_days": round(seconds / 86400.0, 1) if seconds else None,
        "load_summary": text.strip() if text else None,
    }


def _power(ctx):
    payload, reason = shell.json_of(["system_profiler", "-json", "SPPowerDataType"], timeout=ctx.slow(3))
    result = {}
    if payload is None:
        result["profile"] = shell.unavailable(reason)
    else:
        battery = None
        ac = None
        for entry in payload.get("SPPowerDataType") or []:
            name = entry.get("_name")
            if name == "spbattery_information":
                battery = entry
            elif name == "sppower_ac_charger_information":
                ac = entry
        if battery:
            health = battery.get("sppower_battery_health_info") or {}
            charge = battery.get("sppower_battery_charge_info") or {}
            result["battery"] = {
                "present": True,
                "cycle_count": health.get("sppower_battery_cycle_count"),
                "condition": health.get("sppower_battery_health"),
                "maximum_capacity_percent": health.get("sppower_battery_health_maximum_capacity"),
                "fully_charged": charge.get("sppower_battery_fully_charged"),
                "charging": charge.get("sppower_battery_is_charging"),
                "state_of_charge_percent": charge.get("sppower_battery_state_of_charge"),
            }
        else:
            result["battery"] = {"present": False, "reason": "no internal battery reported"}
        if ac:
            result["ac_charger"] = {"connected": ac.get("sppower_battery_charger_connected"), "wattage": ac.get("sppower_ac_charger_watts")}
    source = shell.stdout_of(["pmset", "-g", "ps"], timeout=ctx.timeout)
    if source:
        first = source.strip().splitlines()[0]
        result["power_source"] = first.replace("Now drawing from ", "").strip("'")
        result["power_source_raw"] = source.strip()[:400]
    else:
        result["power_source"] = None
    return result


def _thermal(ctx):
    res = shell.run(["pmset", "-g", "therm"], timeout=ctx.timeout)
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    values = {}
    for line in res["stdout"].splitlines():
        match = re.match(r"\s*(\w+)\s*=\s*(\d+)", line)
        if match:
            values[match.group(1)] = int(match.group(2))
    nominal = all(values.get(key, 100) >= 100 for key in ("CPU_Speed_Limit",) if key in values)
    return {
        "values": values,
        "nominal": nominal if values else None,
        "raw": res["stdout"].strip()[:600],
    }


def _cpu_temperature(ctx):
    for binary, argv in (("osx-cpu-temp", ["osx-cpu-temp"]), ("istats", ["istats", "cpu", "temp"]), ("smctemp", ["smctemp", "-c"])):
        if shell.which(binary):
            text = shell.stdout_of(argv, timeout=ctx.timeout)
            if text:
                return {"status": "ok", "source": binary, "reading": text.strip().splitlines()[0][:120]}
    return shell.requires_privileges(
        "CPU die temperature is exposed by powermetrics and the SMC, both of which need root on macOS; no unprivileged sensor tool is installed",
        {"unprivileged_alternatives": ["brew install osx-cpu-temp", "brew install smctemp"], "privileged_command_not_run": "sudo powermetrics --samplers smc -n 1"},
    )


def collect(ctx=None):
    ctx = default_context(ctx)
    arch = sysinfo.architecture()
    sysctls = _sysctl_map(
        ["machdep.cpu.brand_string", "hw.model", "hw.ncpu", "hw.physicalcpu", "hw.logicalcpu", "hw.perflevel0.physicalcpu", "hw.perflevel1.physicalcpu"],
        ctx.timeout,
    )
    result = {
        "status": "ok",
        "architecture": arch,
        "macos": sysinfo.macos_version(),
        "profile": _hardware_profile(ctx),
        "cpu": {
            "brand": sysctls["machdep.cpu.brand_string"],
            "model": sysctls["hw.model"],
            "logical_cores": sysctls["hw.logicalcpu"] or sysctls["hw.ncpu"],
            "physical_cores": sysctls["hw.physicalcpu"],
            "performance_cores": sysctls["hw.perflevel0.physicalcpu"],
            "efficiency_cores": sysctls["hw.perflevel1.physicalcpu"],
        },
        "memory": _memory(ctx),
        "uptime": _uptime(ctx),
        "power": _power(ctx),
        "thermal_pressure": _thermal(ctx),
        "cpu_temperature": _cpu_temperature(ctx),
    }

    findings = []
    memory = result["memory"]
    pressure = memory.get("memory_pressure_percent")
    if pressure is not None and pressure >= 85:
        findings.append(F.finding(
            "hardware",
            "warning",
            "Memory pressure is high at %.1f%%" % pressure,
            "wired + active + compressed is %s of %s" % (memory.get("used_human"), memory.get("total_human")),
            "Sustained high memory pressure pushes the system into compression and swap, which shows up as general interface stalling.",
            "Close the largest resident processes, or reduce the number of running containers and simulators",
            True,
            key="memory-pressure",
        ))
    swap_used = (memory.get("swap") or {}).get("used_bytes")
    if swap_used and swap_used > 4 * 1024 ** 3:
        findings.append(F.finding(
            "hardware",
            "warning",
            "Swap usage exceeds 4 GB",
            "swap in use: %s" % (memory.get("swap") or {}).get("used_human"),
            "Heavy swap use means the working set no longer fits in RAM, and it writes continuously to the internal SSD.",
            "Restart long-lived memory-heavy processes, or reduce concurrent workloads",
            True,
            key="swap-usage",
        ))

    battery = (result["power"] or {}).get("battery") or {}
    if battery.get("present"):
        condition = str(battery.get("condition") or "")
        if condition and condition.lower() not in ("normal", "good"):
            findings.append(F.finding(
                "hardware",
                "warning",
                "Battery condition reported as %s" % condition,
                "cycle count %s, maximum capacity %s" % (battery.get("cycle_count"), battery.get("maximum_capacity_percent")),
                "A degraded battery reduces peak power delivery, which on portables leads to throttling under load even on mains power.",
                "Have the battery checked; no software change applies",
                True,
                key="battery-condition",
            ))
        capacity = battery.get("maximum_capacity_percent")
        capacity_value = None
        if isinstance(capacity, str):
            digits = re.search(r"(\d+)", capacity)
            capacity_value = int(digits.group(1)) if digits else None
        elif isinstance(capacity, (int, float)):
            capacity_value = int(capacity)
        if capacity_value is not None and capacity_value < 80:
            findings.append(F.finding(
                "hardware",
                "info",
                "Battery maximum capacity is %d%% of design" % capacity_value,
                "cycle count %s" % battery.get("cycle_count"),
                "Below 80 percent of design capacity Apple considers the battery consumed, and runtime on battery drops noticeably.",
                "Plan a battery replacement; no software change applies",
                True,
                key="battery-capacity",
            ))

    thermal = result["thermal_pressure"]
    if isinstance(thermal, dict) and thermal.get("values"):
        limit = thermal["values"].get("CPU_Speed_Limit")
        if limit is not None and limit < 100:
            findings.append(F.finding(
                "hardware",
                "warning",
                "CPU is thermally or power limited to %d%%" % limit,
                thermal.get("raw", "")[:200],
                "The scheduler is capping CPU speed right now, so builds and test runs take longer than the hardware allows.",
                "Check ventilation and background load; pmset -g therm reports the live limit",
                True,
                key="thermal-limit",
            ))

    uptime_days = (result["uptime"] or {}).get("uptime_days")
    if uptime_days and uptime_days > 30:
        findings.append(F.finding(
            "hardware",
            "info",
            "System has been up for %.1f days" % uptime_days,
            "boot time %s" % (result["uptime"] or {}).get("boot_time_utc"),
            "Pending security updates and kernel extension changes only take effect after a restart.",
            "Restart at a convenient point to apply queued system updates",
            True,
            key="uptime",
        ))

    result["findings"] = findings
    return result
