import concurrent.futures
import traceback

from . import registry
from .context import Context


def _execute(domain, ctx):
    try:
        module = registry.load(domain)
    except Exception as exc:
        return {"status": "unavailable", "reason": "collector import failed: %s: %s" % (exc.__class__.__name__, exc), "findings": []}
    try:
        payload = module.collect(ctx)
    except Exception as exc:
        return {
            "status": "error",
            "reason": "%s: %s" % (exc.__class__.__name__, exc),
            "trace_summary": traceback.format_exc(limit=3).strip().splitlines()[-1][:300],
            "findings": [],
        }
    if not isinstance(payload, dict):
        return {"status": "error", "reason": "collector returned %s" % type(payload).__name__, "findings": []}
    payload.setdefault("status", "ok")
    payload.setdefault("findings", [])
    return payload


def run_all(domains, ctx=None, global_timeout=None):
    ctx = ctx or Context()
    if global_timeout is None:
        global_timeout = max(120, ctx.timeout * 20)
    results = {}
    workers = max(1, min(len(domains), 13))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_execute, domain, ctx): domain for domain in domains}
        done, pending = concurrent.futures.wait(futures, timeout=global_timeout)
        for future in done:
            domain = futures[future]
            try:
                results[domain] = future.result()
            except Exception as exc:
                results[domain] = {"status": "error", "reason": "%s: %s" % (exc.__class__.__name__, exc), "findings": []}
        for future in pending:
            domain = futures[future]
            future.cancel()
            results[domain] = {
                "status": "unavailable",
                "reason": "collector exceeded global timeout of %ss" % global_timeout,
                "findings": [],
            }
    return {domain: results.get(domain, {"status": "unavailable", "reason": "not executed", "findings": []}) for domain in domains}
