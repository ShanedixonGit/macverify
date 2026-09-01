import os
import re
import stat as statmod
import time

from .. import findings as F
from .. import fsutil, shell
from ..context import default_context

NON_KEY_NAMES = {"config", "known_hosts", "known_hosts.old", "authorized_keys", "authorized_keys2", "environment", "rc", "agent.env", "allowed_signers", ".DS_Store"}
TWO_YEARS = 2 * 365 * 24 * 3600
WEAK_RSA_BITS = 3072


def _key_info(path, ctx):
    res = shell.run(["ssh-keygen", "-l", "-f", path], timeout=ctx.timeout)
    if not res["ok"]:
        return None, shell.failure_reason(res)
    line = res["stdout"].strip().splitlines()[0] if res["stdout"].strip() else ""
    match = re.match(r"^(\d+)\s+(\S+)\s+(.*)\s+\(([^)]+)\)\s*$", line)
    if not match:
        return None, "unparseable ssh-keygen output"
    comment = match.group(3).strip()
    return {
        "bits": int(match.group(1)),
        "fingerprint_algorithm": match.group(2).split(":")[0],
        "comment": None if comment in ("no comment", "") else comment,
        "algorithm": match.group(4).strip(),
    }, None


def _passphrase_state(path, ctx):
    res = shell.run(["ssh-keygen", "-y", "-P", "", "-f", path], timeout=ctx.timeout)
    if res["skipped_reason"]:
        return "unknown", res["skipped_reason"]
    if res["ok"]:
        return "no_passphrase", None
    stderr = (res["stderr"] or "").lower()
    if "incorrect passphrase" in stderr or "load failed" in stderr and "passphrase" in stderr:
        return "passphrase_protected", None
    if "invalid format" in stderr or "is not a public key file" in stderr:
        return "not_a_private_key", None
    return "unknown", stderr.strip().splitlines()[0][:160] if stderr.strip() else None


def _ssh_keys(ctx):
    ssh_dir = os.path.expanduser("~/.ssh")
    if not fsutil.exists(ssh_dir):
        return shell.unavailable("~/.ssh does not exist")
    dir_stat = fsutil.stat(ssh_dir)
    keys = []
    now = time.time()
    for name in fsutil.listdir(ssh_dir):
        if name in NON_KEY_NAMES or name.endswith(".pub") or name.startswith("known_hosts"):
            continue
        path = os.path.join(ssh_dir, name)
        st = fsutil.stat(path)
        if st is None or not statmod.S_ISREG(st.st_mode):
            continue
        info, reason = _key_info(path, ctx)
        public_path = path + ".pub"
        if info is None and fsutil.exists(public_path):
            info, reason = _key_info(public_path, ctx)
        entry = {
            "filename": name,
            "path": fsutil.tilde(path),
            "has_public_half": fsutil.exists(public_path),
            "mode": fsutil.mode_string(st),
            "size_bytes": int(st.st_size),
            "created": fsutil.created_at(st),
            "modified": fsutil.modified_at(st),
            "age_days": int((now - st.st_mtime) / 86400),
            "permissive_mode": bool(st.st_mode & 0o077),
        }
        if info is None:
            entry["status"] = "unavailable"
            entry["reason"] = reason
            keys.append(entry)
            continue
        entry.update(info)
        state, state_reason = _passphrase_state(path, ctx)
        entry["passphrase"] = state
        if state_reason:
            entry["passphrase_detail"] = state_reason
        keys.append(entry)
    config_path = os.path.join(ssh_dir, "config")
    hosts = []
    if fsutil.exists(config_path):
        text = fsutil.read_text(config_path) or ""
        current = None
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            match = re.match(r"^(?i)host\s+(.+)$", stripped)
            if match:
                current = {"pattern": match.group(1).strip(), "line": number, "options": []}
                hosts.append(current)
            elif current is not None and stripped and not stripped.startswith("#"):
                key = stripped.split()[0]
                if key.lower() in ("hostname", "user", "port", "identityfile", "proxyjump", "proxycommand", "forwardagent", "identitiesonly", "addkeystoagent", "usekeychain"):
                    current["options"].append(stripped[:160])
    known_hosts_path = os.path.join(ssh_dir, "known_hosts")
    known_hosts_count = 0
    if fsutil.exists(known_hosts_path):
        text = fsutil.read_text(known_hosts_path) or ""
        known_hosts_count = len([line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")])
    return {
        "status": "ok",
        "directory": fsutil.tilde(ssh_dir),
        "directory_mode": fsutil.mode_string(dir_stat),
        "key_count": len(keys),
        "keys": sorted(keys, key=lambda item: item["filename"]),
        "config_hosts": hosts,
        "config_host_count": len(hosts),
        "known_hosts_entries": known_hosts_count,
        "authorized_keys_present": fsutil.exists(os.path.join(ssh_dir, "authorized_keys")),
    }


def _gpg(ctx):
    if not shell.which("gpg"):
        return shell.unavailable("gpg not found on PATH")
    res = shell.run(["gpg", "--list-keys", "--with-colons", "--batch", "--no-tty"], timeout=ctx.slow(2))
    if not res["ok"]:
        return shell.unavailable(shell.failure_reason(res))
    keys = []
    current = None
    for line in res["stdout"].splitlines():
        fields = line.split(":")
        if not fields:
            continue
        if fields[0] == "pub":
            current = {
                "key_id": fields[4] if len(fields) > 4 else None,
                "algorithm_id": fields[3] if len(fields) > 3 else None,
                "bits": int(fields[2]) if len(fields) > 2 and fields[2].isdigit() else None,
                "created": fsutil.iso_time(fields[5]) if len(fields) > 5 and fields[5].isdigit() else None,
                "expires": fsutil.iso_time(fields[6]) if len(fields) > 6 and fields[6].isdigit() else None,
                "validity": fields[1] if len(fields) > 1 else None,
                "uids": [],
            }
            keys.append(current)
        elif fields[0] == "uid" and current is not None and len(fields) > 9:
            current["uids"].append(fields[9])
    secret = shell.run(["gpg", "--list-secret-keys", "--with-colons", "--batch", "--no-tty"], timeout=ctx.slow(2))
    secret_ids = []
    if secret["ok"]:
        for line in secret["stdout"].splitlines():
            fields = line.split(":")
            if fields and fields[0] == "sec" and len(fields) > 4:
                secret_ids.append(fields[4])
    return {"status": "ok", "public_key_count": len(keys), "keys": keys, "secret_key_ids": sorted(secret_ids)}


def _agents(ctx):
    ssh_socket = os.environ.get("SSH_AUTH_SOCK")
    agent = {"ssh_auth_sock_set": bool(ssh_socket), "socket_exists": fsutil.exists(ssh_socket) if ssh_socket else False}
    res = shell.run(["ssh-add", "-l"], timeout=ctx.timeout)
    if res["skipped_reason"]:
        agent["identities"] = shell.unavailable(res["skipped_reason"])
    elif res["rc"] == 0:
        lines = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
        agent["identities"] = {"count": len(lines), "summaries": [" ".join(line.split()[:2] + line.split()[-1:]) for line in lines]}
    elif res["rc"] == 1:
        agent["identities"] = {"count": 0, "note": "agent is running with no identities loaded"}
    else:
        agent["identities"] = shell.unavailable("no ssh agent is reachable from this session")
    gpg_agent = {"present": False}
    if shell.which("gpgconf"):
        socket_path = shell.stdout_of(["gpgconf", "--list-dirs", "agent-socket"], timeout=ctx.timeout)
        if socket_path:
            socket_path = socket_path.strip()
            gpg_agent = {"present": fsutil.exists(socket_path), "socket": fsutil.tilde(socket_path), "note": "socket presence only; no agent was started by this audit"}
    return {"ssh_agent": agent, "gpg_agent": gpg_agent}


def collect(ctx=None):
    ctx = default_context(ctx)
    result = {"status": "ok", "ssh": _ssh_keys(ctx), "gpg": _gpg(ctx)}
    result.update(_agents(ctx))

    findings = []
    ssh = result["ssh"]
    if isinstance(ssh, dict) and ssh.get("status") == "ok":
        for key in ssh["keys"]:
            algorithm = (key.get("algorithm") or "").upper()
            label = key["filename"]
            if algorithm == "DSA":
                findings.append(F.finding(
                    "identity",
                    "critical",
                    "DSA SSH key present: %s" % label,
                    "%s, %s bits" % (key["path"], key.get("bits")),
                    "DSA is capped at 1024 bits, is disabled by default in current OpenSSH, and is considered broken for new connections.",
                    "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519   # then replace the key on each server and delete the old one",
                    False,
                    key="dsa-%s" % label,
                ))
            if algorithm == "RSA" and key.get("bits") and key["bits"] < WEAK_RSA_BITS:
                findings.append(F.finding(
                    "identity",
                    "warning",
                    "RSA key below 3072 bits: %s" % label,
                    "%s, %s bits" % (key["path"], key["bits"]),
                    "RSA keys under 3072 bits fall below the current minimum strength recommendation and some servers already refuse them.",
                    "ssh-keygen -t ed25519 -f ~/.ssh/%s_ed25519" % os.path.splitext(label)[0],
                    False,
                    key="weak-rsa-%s" % label,
                ))
            if key.get("permissive_mode"):
                findings.append(F.finding(
                    "identity",
                    "critical",
                    "SSH key file has permissive mode: %s" % label,
                    "%s mode %s" % (key["path"], key.get("mode")),
                    "OpenSSH refuses to use group or world readable private keys, and any other local account can copy the key before that check happens.",
                    "chmod 600 %s" % key["path"],
                    True,
                    key="mode-%s" % label,
                ))
            if key.get("passphrase") == "no_passphrase":
                findings.append(F.finding(
                    "identity",
                    "warning",
                    "SSH private key has no passphrase: %s" % label,
                    "%s (%s %s bits)" % (key["path"], key.get("algorithm"), key.get("bits")),
                    "An unprotected private key is usable immediately by anything that can read the file, including a backup or a malicious dependency.",
                    "ssh-keygen -p -f %s   # adds a passphrase in place" % key["path"],
                    True,
                    key="nopass-%s" % label,
                ))
            if key.get("age_days") and key["age_days"] > TWO_YEARS / 86400:
                findings.append(F.finding(
                    "identity",
                    "info",
                    "SSH key not rotated in %d days: %s" % (key["age_days"], label),
                    "%s last modified %s" % (key["path"], key.get("modified")),
                    "Long-lived keys accumulate copies across machines and servers, so a single old leak stays valid indefinitely.",
                    "Generate a replacement key and remove the old public key from every authorized_keys it was added to",
                    False,
                    key="age-%s" % label,
                ))
        if ssh.get("directory_mode") and ssh["directory_mode"] not in ("0700", "0500"):
            findings.append(F.finding(
                "identity",
                "warning",
                "~/.ssh directory mode is %s" % ssh["directory_mode"],
                "expected 0700",
                "A group or world accessible .ssh directory lets another local account enumerate and in some cases replace your keys and known hosts.",
                "chmod 700 ~/.ssh",
                True,
                key="ssh-dir-mode",
            ))

    gpg = result["gpg"]
    if isinstance(gpg, dict) and gpg.get("status") == "ok":
        for key in gpg["keys"]:
            if key.get("expires") and key["expires"] < time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()):
                findings.append(F.finding(
                    "identity",
                    "info",
                    "Expired GPG key in keyring: %s" % key["key_id"],
                    "expired %s, uids: %s" % (key["expires"], "; ".join(key.get("uids") or [])[:120]),
                    "An expired signing key silently fails verification for anyone checking your commits or releases.",
                    "gpg --edit-key %s expire" % key["key_id"],
                    True,
                    key="gpg-expired-%s" % key["key_id"],
                ))

    result["findings"] = findings
    return result
