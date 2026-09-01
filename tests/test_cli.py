import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(arguments, home=None):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = REPO_ROOT
    if home is not None:
        environment["HOME"] = home
    completed = subprocess.run(
        [sys.executable, "-m", "macverify"] + arguments,
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
    )
    return completed.returncode, completed.stdout.decode("utf-8", "replace"), completed.stderr.decode("utf-8", "replace")


class Invocation(unittest.TestCase):
    def test_version_matches_pyproject(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(0, code)
        with open(os.path.join(REPO_ROOT, "pyproject.toml"), "r", encoding="utf-8") as handle:
            declared = re.search(r'^\s*version\s*=\s*"([^"]+)"', handle.read(), re.M).group(1)
        self.assertEqual("macverify %s" % declared, out.strip())

    def test_help_lists_every_flag(self):
        code, out, _ = run_cli(["--help"])
        self.assertEqual(0, code)
        for flag in ("--only", "--skip", "--json-only", "--html-only", "--out", "--timeout",
                     "--lang", "--project", "--verbose", "--list-domains", "--quick-fixes", "--check"):
            self.assertIn(flag, out, flag)

    def test_help_describes_the_tool_accurately(self):
        _, out, _ = run_cli(["--help"])
        self.assertIn("Read-only", out)
        self.assertNotIn("macaudit", out)

    def test_list_domains_matches_the_registry(self):
        from macverify import registry

        code, out, _ = run_cli(["--list-domains"])
        self.assertEqual(0, code)
        self.assertEqual(list(registry.DOMAINS), out.split())

    def test_check_exits_zero_on_a_supported_machine(self):
        code, out, _ = run_cli(["--check"])
        self.assertEqual(0, code)
        self.assertIn("supported", out)

    def test_unknown_flag_is_rejected(self):
        code, _, err = run_cli(["--definitely-not-a-flag"])
        self.assertEqual(2, code)
        self.assertIn("unrecognized arguments", err)


class Output(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix="macverify-cli-")
        cls.code, cls.out, cls.err = run_cli(["--only", "security", "--only", "openai_codex"], home=cls.home)
        cls.reports = os.path.join(cls.home, ".macverify", "reports")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_run_succeeds(self):
        self.assertEqual(0, self.code, self.err)

    def test_default_output_directory_is_under_home(self):
        self.assertTrue(os.path.isdir(self.reports), self.out)

    def test_report_directory_is_owner_only(self):
        for path in (os.path.dirname(self.reports), self.reports):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(0o700, mode, "%s is %s" % (path, oct(mode)))

    def test_report_files_are_owner_only(self):
        written = os.listdir(self.reports)
        self.assertTrue(written)
        for name in written:
            mode = stat.S_IMODE(os.stat(os.path.join(self.reports, name)).st_mode)
            self.assertEqual(0o600, mode, "%s is %s" % (name, oct(mode)))

    def test_dataset_is_valid_json_with_the_expected_shape(self):
        datasets = [name for name in os.listdir(self.reports) if name.startswith("audit_") and name.endswith(".json")]
        self.assertEqual(1, len(datasets))
        with open(os.path.join(self.reports, datasets[0]), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for key in ("schema_version", "tool", "generated_at", "system", "compatibility",
                    "scope", "run", "summary", "findings", "quick_fixes", "domains"):
            self.assertIn(key, data)
        self.assertEqual("macverify", data["tool"]["name"])
        self.assertEqual("read-only", data["tool"]["mode"])

    def test_html_report_is_self_contained(self):
        pages = [name for name in os.listdir(self.reports) if name.endswith(".html")]
        self.assertEqual(1, len(pages))
        with open(os.path.join(self.reports, pages[0]), "r", encoding="utf-8") as handle:
            html = handle.read()
        self.assertNotIn("<script src=", html)
        self.assertNotIn('href="http', html.replace('href="https://', "SAFE"))
        self.assertNotIn("<img src=\"http", html)

    def test_assistant_export_is_written(self):
        self.assertIn("ai_assistant_findings.json", os.listdir(self.reports))

    def test_stdout_states_the_malware_limitation(self):
        self.assertIn("cannot detect malware", self.out)

    def test_stdout_states_read_only_and_offline(self):
        self.assertIn("read-only", self.out)
        self.assertIn("offline", self.out)


class Packaging(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(REPO_ROOT, "pyproject.toml"), "r", encoding="utf-8") as handle:
            self.pyproject = handle.read()

    def test_declares_no_runtime_dependencies(self):
        self.assertNotIn("\ndependencies", self.pyproject)

    def test_supports_python_39(self):
        self.assertIn('requires-python = ">=3.9"', self.pyproject)

    def test_console_script_entry_point(self):
        self.assertIn('macverify = "macverify.__main__:main"', self.pyproject)

    def test_entry_point_target_is_callable(self):
        from macverify.__main__ import main

        self.assertTrue(callable(main))

    def test_packages_are_explicit_so_assets_are_not_shipped(self):
        self.assertIn('packages = ["macverify", "macverify.collectors"]', self.pyproject)


if __name__ == "__main__":
    unittest.main()
