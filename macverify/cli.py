import argparse
import datetime
import json
import os
import sys

from . import __version__, compat, findings as findings_mod, quickfix, registry, report_html, report_md, runner, scope as scope_mod, sysinfo
from .context import Context

REPORT_DIR = os.path.join(os.path.expanduser("~"), ".macverify", "reports")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="macverify",
        description="Read-only inventory of a macOS user space and its AI assistant configuration. Nothing is modified, elevated, or sent over the network.",
    )
    parser.add_argument("--version", action="version", version="macverify %s" % __version__, help="print the installed version and exit")
    parser.add_argument("--only", action="append", metavar="DOMAIN", help="run only this domain (repeatable)")
    parser.add_argument("--skip", action="append", metavar="DOMAIN", help="skip this domain (repeatable)")
    parser.add_argument("--json-only", action="store_true", help="write the JSON dataset only")
    parser.add_argument("--html-only", action="store_true", help="write the HTML report only")
    parser.add_argument("--out", metavar="DIR", default=REPORT_DIR, help="output directory (default: ~/.macverify/reports)")
    parser.add_argument("--timeout", type=float, default=8.0, metavar="S", help="per-command timeout in seconds (default: 8)")
    parser.add_argument("--lang", choices=("en", "es"), default="en", help="report label language (default: en)")
    parser.add_argument("--project", action="append", metavar="PATH", help="extra project root to inspect for AI assistant config (repeatable)")
    parser.add_argument("--verbose", action="store_true", help="print per-domain progress to stderr")
    parser.add_argument("--list-domains", action="store_true", help="list domain names and exit")
    parser.add_argument("--quick-fixes", action="store_true", help="print the quick-fix plan to stdout as well as writing the reports")
    parser.add_argument("--check", action="store_true", help="report what this machine can be audited for, then exit without collecting")
    return parser


def _log(enabled, message):
    if enabled:
        sys.stderr.write("[macverify] %s\n" % message)
        sys.stderr.flush()


def _collect_findings(results):
    collected = []
    for domain in sorted(results):
        for item in results[domain].get("findings") or []:
            if isinstance(item, dict) and item.get("id"):
                collected.append(item)
    return findings_mod.sort_findings(collected)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_domains:
        for domain in registry.DOMAINS:
            sys.stdout.write("%s\n" % domain)
        return 0

    host = compat.preflight()
    if args.check:
        _print_check(host)
        return 0 if host["supported"] else 1
    if not host["supported"]:
        sys.stderr.write("macverify cannot run here: %s\n" % host["reason"])
        return 1
    for warning in host["warnings"]:
        _log(True, warning)

    domains, unknown = registry.resolve(args.only, args.skip)
    for name in unknown:
        _log(True, "unknown domain ignored: %s" % name)
    if not domains:
        _log(True, "no domains selected")
        return 0

    projects = [os.path.abspath(os.path.expanduser(path)) for path in (args.project or [])]
    ctx = Context(timeout=max(1.0, args.timeout), projects=projects, verbose=args.verbose, lang=args.lang)

    started = datetime.datetime.now(datetime.timezone.utc)
    _log(args.verbose, "running %d domains with a %.0fs per-command timeout" % (len(domains), ctx.timeout))
    results = runner.run_all(domains, ctx)
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()

    for domain in domains:
        _log(args.verbose, "%-12s %s" % (domain, results[domain].get("status")))

    all_findings = _collect_findings(results)
    tally = findings_mod.counts(all_findings)
    plan = quickfix.build(all_findings)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")

    dataset = {
        "schema_version": 1,
        "tool": {"name": "macverify", "version": __version__, "mode": "read-only"},
        "generated_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "system": sysinfo.snapshot(),
        "compatibility": host,
        "scope": {
            "reads": scope_mod.scope(args.lang)["does"],
            "cannot_detect": scope_mod.scope(args.lang)["not"],
            "recommended_scanners": scope_mod.scope(args.lang)["av_tools"],
        },
        "run": {
            "domains": list(domains),
            "per_command_timeout_seconds": ctx.timeout,
            "language": args.lang,
            "extra_projects": projects,
            "statuses": {domain: results[domain].get("status") for domain in domains},
        },
        "summary": {
            "finding_counts": tally,
            "total_findings": len(all_findings),
            "domains_ok": sorted(d for d in domains if results[d].get("status") == "ok"),
            "domains_degraded": sorted(d for d in domains if results[d].get("status") not in ("ok",)),
        },
        "findings": all_findings,
        "quick_fixes": plan,
        "domains": {domain: results[domain] for domain in domains},
    }

    out_dir = os.path.abspath(os.path.expanduser(args.out))
    try:
        newly_created = not os.path.isdir(out_dir)
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        if newly_created or out_dir == os.path.abspath(REPORT_DIR):
            os.chmod(out_dir, 0o700)
        if out_dir == os.path.abspath(REPORT_DIR):
            os.chmod(os.path.dirname(out_dir), 0o700)
    except OSError as exc:
        sys.stderr.write("cannot create output directory %s: %s\n" % (out_dir, exc))
        return 0

    written = []
    if not args.html_only:
        json_path = os.path.join(out_dir, "audit_%s.json" % stamp)
        _write(json_path, json.dumps(dataset, indent=2, ensure_ascii=False, default=str) + "\n")
        written.append(json_path)

    if not args.json_only:
        html_path = os.path.join(out_dir, "audit_%s.html" % stamp)
        _write(html_path, report_html.render(dataset, args.lang))
        written.append(html_path)

        md_path = os.path.join(out_dir, "remediation.md")
        _write(md_path, report_md.render(dataset, args.lang))
        written.append(md_path)

    assistants = {name: results[name] for name in registry.AI_ASSISTANT_DOMAINS if name in results}
    if assistants and not args.html_only:
        assistant_path = os.path.join(out_dir, "ai_assistant_findings.json")
        payload = {
            "generated_at": dataset["generated_at"],
            "tool": dataset["tool"],
            "domains": assistants,
            "statuses": {name: assistants[name].get("status") for name in sorted(assistants)},
            "findings": [item for item in all_findings if item.get("domain") in registry.AI_ASSISTANT_DOMAINS],
        }
        _write(assistant_path, json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")
        written.append(assistant_path)

    if args.quick_fixes:
        _print_quick_fixes(plan)

    sys.stdout.write("macverify %s  read-only  offline\n" % __version__)
    sys.stdout.write("domains: %d ok, %d degraded  findings: %d critical, %d warning, %d info  (%.1fs)\n" % (
        len(dataset["summary"]["domains_ok"]),
        len(dataset["summary"]["domains_degraded"]),
        tally["critical"],
        tally["warning"],
        tally["info"],
        elapsed,
    ))
    sys.stdout.write("quick fixes: %d commands (%d read-only, %d reversible, %d need care), %d manual steps\n" % (
        plan["counts"]["commands"], plan["counts"]["inspect"], plan["counts"]["apply"],
        plan["counts"]["careful"], plan["counts"]["manual_steps"]))
    sys.stdout.write("this audit reads configuration only; it cannot detect malware. Run an anti-malware scan as well - see the Quick fixes tab.\n")
    for path in written:
        sys.stdout.write("wrote %s\n" % path)
    return 0


def _print_check(host):
    sys.stdout.write("platform      %s\n" % host["platform"])
    sys.stdout.write("macOS         %s (build %s)\n" % (host["macos"]["version"], host["macos"]["build"]))
    sys.stdout.write("architecture  %s%s\n" % (
        host["architecture"].get("native_arch"),
        " (interpreter translated by Rosetta)" if host["architecture"].get("running_under_rosetta") else ""))
    sys.stdout.write("python        %s\n" % host["python"]["version"])
    sys.stdout.write("account       %s%s\n" % (
        host["account"].get("user"),
        " (admin)" if host["account"].get("admin") else " (standard)" if host["account"].get("admin") is False else ""))
    sys.stdout.write("supported     %s\n" % ("yes" if host["supported"] else "no: %s" % host["reason"]))
    for warning in host["warnings"]:
        sys.stdout.write("warning       %s\n" % warning)
    for note in host["capability_notes"]:
        sys.stdout.write("%-13s %s: %s\n" % (note["expect"], note["domain"], note["detail"]))


def _print_quick_fixes(plan):
    headings = (
        ("inspect", "look first, read-only"),
        ("apply", "safe to apply, reversible"),
        ("careful", "read before running"),
    )
    for tier, heading in headings:
        items = quickfix.by_tier(plan, tier)
        if not items:
            continue
        sys.stdout.write("\n# %s\n" % heading)
        for entry in items:
            sys.stdout.write("# %s\n" % "; ".join(entry["titles"][:2]))
            sys.stdout.write("%s\n" % entry["command"])
    if plan["manual_steps"]:
        sys.stdout.write("\n# steps with no command\n")
        for entry in plan["manual_steps"]:
            sys.stdout.write("# %s -> %s\n" % ("; ".join(entry["titles"][:2]), entry["manual_step"]))
    sys.stdout.write("\n")


def _write(path, text):
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = None
                handle.write(text)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        os.chmod(path, 0o600)
    except OSError as exc:
        sys.stderr.write("cannot write %s: %s\n" % (path, exc))
