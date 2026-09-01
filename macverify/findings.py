import hashlib
import re

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _slug(text):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", str(text).lower())).strip("-")[:48]


def finding(domain, severity, title, evidence, why_it_matters, suggested_action=None, reversible=True, key=None):
    if severity not in SEVERITY_ORDER:
        severity = "info"
    basis = "|".join([str(domain), str(title), str(key if key is not None else evidence)])
    digest = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:8]
    return {
        "id": "%s-%s-%s" % (_slug(domain), _slug(title), digest),
        "domain": domain,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "why_it_matters": why_it_matters,
        "suggested_action": suggested_action,
        "reversible": bool(reversible),
    }


def sort_findings(items):
    return sorted(items, key=lambda item: (SEVERITY_ORDER.get(item.get("severity"), 3), item.get("domain", ""), item.get("title", ""), item.get("id", "")))


def counts(items):
    tally = {"critical": 0, "warning": 0, "info": 0}
    for item in items:
        key = item.get("severity", "info")
        if key in tally:
            tally[key] += 1
    return tally
