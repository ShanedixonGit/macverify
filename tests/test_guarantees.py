import ast
import os
import unittest

PACKAGE_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "macverify")

NETWORK_MODULES = {
    "urllib", "urllib.request", "urllib.parse", "urllib.error", "requests", "httpx", "http",
    "http.client", "ftplib", "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc",
    "socketserver", "asyncio", "ssl", "webbrowser",
}

FORBIDDEN_MODULES = {"pickle", "cPickle", "marshal", "shelve", "yaml", "tempfile", "ctypes"}

FILESYSTEM_CALLS = {
    "open", "os.open", "os.scandir", "os.listdir", "os.walk", "os.stat", "os.lstat",
    "os.makedirs", "os.path.exists", "os.path.isfile", "os.path.isdir",
}

FORBIDDEN_CALLS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen", "os.execv", "os.execve", "os.spawnv", "os.fork",
    "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pickle.load", "pickle.loads", "marshal.loads",
}


def source_files():
    for root, dirs, files in os.walk(PACKAGE_ROOT):
        dirs[:] = [name for name in dirs if name not in ("__pycache__", "brand")]
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


def relative(path):
    return os.path.relpath(path, PACKAGE_ROOT)


def parsed():
    for path in source_files():
        with open(path, "r", encoding="utf-8") as handle:
            yield relative(path), ast.parse(handle.read(), path)


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def imports(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.add(node.module)
    return found


def calls(tree):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name:
                found.append((name, node.lineno))
    return found


def string_constants(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value, node.lineno


def keyword_arguments(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                yield dotted(node.func), keyword, node.lineno


class Network(unittest.TestCase):
    def test_no_network_module_is_imported(self):
        offenders = []
        for name, tree in parsed():
            for module in sorted(imports(tree) & NETWORK_MODULES):
                offenders.append("%s imports %s" % (name, module))
        self.assertEqual([], offenders)

    def test_socket_is_imported_only_by_sysinfo(self):
        importers = sorted(name for name, tree in parsed() if "socket" in imports(tree))
        self.assertEqual(["sysinfo.py"], importers)

    def test_socket_is_used_only_for_the_local_hostname(self):
        used = []
        for name, tree in parsed():
            for call, line in calls(tree):
                if call.split(".")[0] == "socket":
                    used.append("%s:%d %s" % (name, line, call))
        self.assertEqual(["sysinfo.py:112 socket.gethostname"], used)

    def test_no_socket_is_ever_constructed_or_connected(self):
        offenders = []
        for name, tree in parsed():
            for call, line in calls(tree):
                if call in ("socket.socket", "socket.create_connection", "socket.connect"):
                    offenders.append("%s:%d %s" % (name, line, call))
        self.assertEqual([], offenders)


class ShellExecution(unittest.TestCase):
    def test_subprocess_is_imported_only_by_the_shell_module(self):
        importers = sorted(name for name, tree in parsed() if "subprocess" in imports(tree))
        self.assertEqual(["shell.py"], importers)

    def test_subprocess_run_is_the_only_subprocess_call(self):
        used = []
        for name, tree in parsed():
            for call, line in calls(tree):
                if call.split(".")[0] == "subprocess":
                    used.append("%s:%d %s" % (name, line, call))
        self.assertEqual(["shell.py:85 subprocess.run"], used)

    def test_shell_true_is_never_passed(self):
        offenders = []
        for name, tree in parsed():
            for _, keyword, line in keyword_arguments(tree):
                if keyword.arg == "shell":
                    offenders.append("%s:%d shell=..." % (name, line))
        self.assertEqual([], offenders)

    def test_the_argument_vector_is_a_list_not_a_string(self):
        with open(os.path.join(PACKAGE_ROOT, "shell.py"), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and dotted(node.func) == "subprocess.run":
                self.assertTrue(node.args, "subprocess.run called with no argument vector")
                self.assertIsInstance(node.args[0], ast.BinOp)
                return
        self.fail("subprocess.run not found in shell.py")

    def test_a_real_command_runs_from_a_list(self):
        from macverify import shell

        result = shell.run(["/usr/bin/true"])
        self.assertTrue(result["ok"])
        self.assertIsNone(result["skipped_reason"])


class DynamicExecution(unittest.TestCase):
    def test_no_forbidden_call_anywhere(self):
        offenders = []
        for name, tree in parsed():
            for call, line in calls(tree):
                if call in FORBIDDEN_CALLS:
                    offenders.append("%s:%d %s" % (name, line, call))
        self.assertEqual([], offenders)

    def test_no_serialisation_or_temp_file_module_is_imported(self):
        offenders = []
        for name, tree in parsed():
            for module in sorted(imports(tree) & FORBIDDEN_MODULES):
                offenders.append("%s imports %s" % (name, module))
        self.assertEqual([], offenders)


class Elevation(unittest.TestCase):
    def test_privileged_binaries_are_blocked(self):
        from macverify import shell

        for name in ("sudo", "su", "doas", "sudoedit", "security", "systemsetup"):
            self.assertIn(name, shell.BLOCKED_BINARIES)

    def test_blocked_binary_is_refused_before_execution(self):
        from macverify import shell

        result = shell.run(["sudo", "-n", "true"])
        self.assertFalse(result["ok"])
        self.assertIsNone(result["rc"])
        self.assertEqual("privileged command refused by audit policy", result["skipped_reason"])

    def test_blocking_is_by_basename_so_a_full_path_cannot_slip_through(self):
        from macverify import shell

        result = shell.run(["/usr/bin/sudo", "true"])
        self.assertEqual("privileged command refused by audit policy", result["skipped_reason"])


class Portability(unittest.TestCase):
    def test_no_string_constant_hardcodes_a_home_directory(self):
        offenders = []
        for name, tree in parsed():
            for value, line in string_constants(tree):
                if "/Users/" in value or value.startswith("/home/"):
                    offenders.append("%s:%d %r" % (name, line, value[:60]))
        self.assertEqual([], offenders)

    def test_a_module_that_opens_tilde_paths_expands_them(self):
        checked = 0
        for name, tree in parsed():
            tildes = [value for value, _ in string_constants(tree) if value.startswith("~/")]
            if not tildes:
                continue
            names = {call for call, _ in calls(tree)}
            if not (names & FILESYSTEM_CALLS):
                continue
            checked += 1
            expands = any(call.endswith("expanduser") or call.endswith("home") for call in names)
            self.assertTrue(expands, "%s has %d tilde paths and touches the filesystem but never expands one" % (name, len(tildes)))
        self.assertGreaterEqual(checked, 4, "the tilde-expansion check matched almost nothing, so it is not proving much")


class RepositoryHygiene(unittest.TestCase):
    def tracked_text_files(self):
        root = os.path.dirname(PACKAGE_ROOT)
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "brand", "build", "dist", ".venv")
                       and not d.endswith(".egg-info")]
            for name in sorted(files):
                if name.endswith((".py", ".md", ".toml", ".yml", ".yaml", ".json", ".cfg")):
                    yield os.path.relpath(os.path.join(base, name), root)

    def test_no_credential_shaped_literal_is_committed(self):
        from macverify.collectors import secrets

        root = os.path.dirname(PACKAGE_ROOT)
        offenders = []
        for relative in self.tracked_text_files():
            try:
                with open(os.path.join(root, relative), "r", encoding="utf-8") as handle:
                    text = handle.read()
            except (OSError, UnicodeDecodeError):
                continue
            for hit in secrets._scan_text(relative, text):
                if hit["detector"] == "name_hint":
                    continue
                offenders.append("%s:%s %s" % (relative, hit["line"], hit["detector"]))
        self.assertEqual([], offenders,
                         "a credential-shaped literal is committed; assemble test fixtures at runtime instead")


class Conventions(unittest.TestCase):
    def test_the_assistant_modules_carry_no_code_comments(self):
        recent = ("aicommon.py", "collectors/ai_assistants.py",
                  "collectors/github_copilot.py", "collectors/openai_codex.py")
        for name in recent:
            with open(os.path.join(PACKAGE_ROOT, name), "r", encoding="utf-8") as handle:
                comments = [line.strip() for line in handle if line.lstrip().startswith("#")]
            self.assertEqual([], comments, name)

    def test_every_module_parses_on_the_running_interpreter(self):
        self.assertGreater(len(list(parsed())), 30)


if __name__ == "__main__":
    unittest.main()
