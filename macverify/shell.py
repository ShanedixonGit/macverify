import os
import shlex
import shutil
import subprocess

DEFAULT_TIMEOUT = 8

BLOCKED_BINARIES = {"sudo", "su", "doas", "sudoedit", "security", "systemsetup"}

BASE_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "NO_COLOR": "1",
    "CLICOLOR": "0",
    "TERM": "dumb",
    "HOMEBREW_NO_AUTO_UPDATE": "1",
    "HOMEBREW_NO_ANALYTICS": "1",
    "HOMEBREW_NO_ENV_HINTS": "1",
    "HOMEBREW_NO_INSTALL_CLEANUP": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PIP_NO_INPUT": "1",
    "PYTHONWARNINGS": "ignore",
    "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    "NPM_CONFIG_FUND": "false",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/usr/bin/false",
    "SSH_ASKPASS": "/usr/bin/false",
    "DISPLAY": "",
}


def build_env(extra=None):
    env = dict(os.environ)
    env.update(BASE_ENV)
    if extra:
        env.update(extra)
    return env


def unavailable(reason):
    return {"status": "unavailable", "reason": reason}


def requires_privileges(reason, extra=None):
    payload = {"status": "requires_privileges", "reason": reason}
    if extra:
        payload.update(extra)
    return payload


def which(name):
    try:
        return shutil.which(name)
    except (OSError, TypeError):
        return None


def run(cmd, timeout=DEFAULT_TIMEOUT, env=None, cwd=None):
    if isinstance(cmd, str):
        try:
            argv = shlex.split(cmd)
        except ValueError:
            argv = []
    else:
        argv = [str(part) for part in cmd]
    result = {
        "cmd": " ".join(shlex.quote(part) for part in argv),
        "ok": False,
        "stdout": "",
        "stderr": "",
        "rc": None,
        "skipped_reason": None,
    }
    if not argv:
        result["skipped_reason"] = "empty command"
        return result
    if os.path.basename(argv[0]) in BLOCKED_BINARIES:
        result["skipped_reason"] = "privileged command refused by audit policy"
        return result
    binary = argv[0] if os.path.sep in argv[0] else which(argv[0])
    if not binary or not os.path.exists(binary):
        result["skipped_reason"] = "binary not found: %s" % argv[0]
        return result
    try:
        proc = subprocess.run(
            [binary] + argv[1:],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=build_env(env),
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        result["skipped_reason"] = "timeout after %ss" % timeout
        return result
    except (OSError, ValueError, MemoryError) as exc:
        result["skipped_reason"] = "exec failed: %s" % exc.__class__.__name__
        return result
    except Exception as exc:
        result["skipped_reason"] = "exec failed: %s" % exc.__class__.__name__
        return result
    result["rc"] = proc.returncode
    result["stdout"] = proc.stdout.decode("utf-8", "replace")
    result["stderr"] = proc.stderr.decode("utf-8", "replace")
    result["ok"] = proc.returncode == 0
    return result


def stdout_of(cmd, timeout=DEFAULT_TIMEOUT, allow_nonzero=False, env=None, cwd=None):
    res = run(cmd, timeout=timeout, env=env, cwd=cwd)
    if res["skipped_reason"]:
        return None
    if res["ok"] or (allow_nonzero and res["stdout"].strip()):
        return res["stdout"]
    return None


def failure_reason(res):
    if res["skipped_reason"]:
        return res["skipped_reason"]
    detail = (res["stderr"] or res["stdout"]).strip().splitlines()
    head = detail[0][:200] if detail else "no output"
    return "exit %s: %s" % (res["rc"], head)


def json_of(cmd, timeout=DEFAULT_TIMEOUT, allow_nonzero=False, env=None, cwd=None):
    import json

    res = run(cmd, timeout=timeout, env=env, cwd=cwd)
    if not res["ok"] and not (allow_nonzero and res["stdout"].strip()):
        return None, failure_reason(res)
    try:
        return json.loads(res["stdout"]), None
    except (ValueError, TypeError):
        return None, "unparseable output from: %s" % res["cmd"]
