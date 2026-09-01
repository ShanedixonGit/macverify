from . import i18n, scope as scope_mod
from .findings import SEVERITY_ORDER

HEADINGS = {
    "en": {
        "title": "Remediation commands",
        "intro": "Every command below is printed for review. macverify executed none of them, and it changed nothing on this machine.",
        "generated": "Generated",
        "host": "Host",
        "nothing": "No findings were recorded for this domain.",
        "why": "Why",
        "reversible": "Reversible",
        "not_reversible": "Not trivially reversible",
        "evidence": "Evidence",
        "none_recorded": "No remediation commands were produced. Nothing in this audit required one.",
        "no_command": "No command applies; this finding needs a decision rather than a command.",
        "summary": "Summary",
        "quick": "Quick fixes",
        "quick_intro": "Deduplicated commands, grouped by what running them would change. None of them was executed.",
        "tier_inspect": "Look first (read-only)",
        "tier_apply": "Safe to apply (reversible)",
        "tier_careful": "Read before running (deletes data, needs elevation, or is not trivially undone)",
        "manual": "Steps with no command",
        "addresses": "Addresses",
        "by_domain": "Findings by area",
        "scope": "Scope",
    },
    "es": {
        "title": "Comandos de remediacion",
        "intro": "Todos los comandos siguientes se muestran para revision. macverify no ejecuto ninguno y no modifico nada en este equipo.",
        "generated": "Generado",
        "host": "Equipo",
        "nothing": "No se registraron hallazgos en este dominio.",
        "why": "Motivo",
        "reversible": "Reversible",
        "not_reversible": "No es facilmente reversible",
        "evidence": "Evidencia",
        "none_recorded": "No se generaron comandos de remediacion. Nada en esta auditoria lo requirio.",
        "no_command": "No aplica ningun comando; este hallazgo requiere una decision, no un comando.",
        "summary": "Resumen",
        "quick": "Soluciones rapidas",
        "quick_intro": "Comandos sin duplicados, agrupados por lo que cambiaria al ejecutarlos. Ninguno fue ejecutado.",
        "tier_inspect": "Mire primero (solo lectura)",
        "tier_apply": "Seguro de aplicar (reversible)",
        "tier_careful": "Lea antes de ejecutar (borra datos, requiere privilegios o no se deshace facilmente)",
        "manual": "Pasos sin comando",
        "addresses": "Resuelve",
        "by_domain": "Hallazgos por area",
        "scope": "Alcance",
    },
}


def render(dataset, lang="en"):
    labels = i18n.labels(lang)
    words = HEADINGS.get(lang, HEADINGS["en"])
    system = dataset.get("system") or {}
    findings = dataset.get("findings") or []
    tally = (dataset.get("summary") or {}).get("finding_counts") or {}

    lines = [
        "# %s" % words["title"],
        "",
        words["intro"],
        "",
        "- %s: %s" % (words["generated"], dataset.get("generated_at")),
        "- %s: %s" % (words["host"], system.get("hostname")),
        "- %s: %d %s, %d %s, %d %s" % (
            words["summary"],
            tally.get("critical", 0), labels["critical"].lower(),
            tally.get("warning", 0), labels["warning"].lower(),
            tally.get("info", 0), labels["info"].lower(),
        ),
        "",
    ]

    lines.extend(_quick_fix_lines(dataset, words))
    lines.extend(_scope_lines(lang, words))

    if not findings:
        lines.append(words["none_recorded"])
        return "\n".join(lines) + "\n"

    lines.append("## %s" % words["by_domain"])
    lines.append("")

    by_domain = {}
    for item in findings:
        by_domain.setdefault(item.get("domain", "unknown"), []).append(item)

    for domain in dataset.get("run", {}).get("domains", []):
        items = by_domain.get(domain)
        if not items:
            continue
        lines.append("## %s" % i18n.domain_label(lang, domain))
        lines.append("")
        for item in sorted(items, key=lambda entry: (SEVERITY_ORDER.get(entry.get("severity"), 3), entry.get("title", ""))):
            severity = item.get("severity", "info")
            lines.append("### [%s] %s" % (labels.get(severity, severity).upper(), item.get("title", "")))
            lines.append("")
            lines.append("%s: %s" % (words["why"], item.get("why_it_matters", "")))
            lines.append("")
            lines.append("%s: `%s`" % (words["evidence"], str(item.get("evidence", "")).replace("`", "'")))
            lines.append("")
            action = item.get("suggested_action")
            if action:
                lines.append("```sh")
                lines.append(str(action))
                lines.append("```")
            else:
                lines.append(words["no_command"])
            lines.append("")
            lines.append("%s: %s" % (words["reversible"], labels["yes"] if item.get("reversible") else words["not_reversible"]))
            lines.append("")
            lines.append("`%s`" % item.get("id", ""))
            lines.append("")
    return "\n".join(lines) + "\n"


def _quick_fix_lines(dataset, words):
    plan = dataset.get("quick_fixes") or {}
    commands = plan.get("commands") or []
    manual = plan.get("manual_steps") or []
    if not commands and not manual:
        return []
    lines = ["## %s" % words["quick"], "", words["quick_intro"], ""]
    for tier, heading in (("inspect", "tier_inspect"), ("apply", "tier_apply"), ("careful", "tier_careful")):
        items = [entry for entry in commands if entry["tier"] == tier]
        if not items:
            continue
        lines.append("### %s" % words[heading])
        lines.append("")
        lines.append("```sh")
        for entry in items:
            for title in entry["titles"][:3]:
                lines.append("# %s" % title)
            if entry.get("note"):
                lines.append("# %s" % entry["note"])
            lines.append(entry["command"])
            lines.append("")
        while lines and lines[-1] == "":
            lines.pop()
        lines.append("```")
        lines.append("")
    if manual:
        lines.append("### %s" % words["manual"])
        lines.append("")
        for entry in manual:
            lines.append("- %s" % entry["manual_step"])
            lines.append("  - %s: %s" % (words["addresses"], "; ".join(entry["titles"][:3])))
        lines.append("")
    return lines


def _scope_lines(lang, words):
    text = scope_mod.scope(lang)
    lines = ["## %s" % words["scope"], "", text["summary"], ""]
    lines.append("### %s" % text["not_heading"])
    lines.append("")
    for item in text["not"]:
        lines.append("- %s" % item)
    lines.append("")
    lines.append("### %s" % text["av_heading"])
    lines.append("")
    lines.append(text["av_intro"])
    lines.append("")
    for tool in text["av_tools"]:
        lines.append("- **%s** - %s" % (tool["name"], tool["finds"]))
        lines.append("  - %s" % tool["how"])
    lines.append("")
    lines.append(text["av_builtin"])
    lines.append("")
    lines.append(text["av_order"])
    lines.append("")
    return lines
