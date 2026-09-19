import json
import os
import shutil
import tempfile
import unittest

from macverify import registry, runner
from macverify.context import Context

ASSISTANT_DOMAINS = ("claude_code", "github_copilot", "openai_codex", "ai_assistants")

ACCEPTABLE = ("ok", "unavailable", "requires_privileges")


class BareMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix="macverify-bare-")
        os.makedirs(os.path.join(cls.home, "project"))
        cls.previous_home = os.environ.get("HOME")
        os.environ["HOME"] = cls.home
        context = Context(timeout=5.0, cwd=os.path.join(cls.home, "project"))
        cls.results = runner.run_all(list(registry.DOMAINS), context)

    @classmethod
    def tearDownClass(cls):
        if cls.previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = cls.previous_home
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_every_domain_returned_something(self):
        self.assertEqual(set(registry.DOMAINS), set(self.results))

    def test_no_domain_raised(self):
        failures = {name: payload.get("reason") for name, payload in self.results.items()
                    if payload.get("status") == "error"}
        self.assertEqual({}, failures)

    def test_every_status_is_a_known_value(self):
        for name, payload in sorted(self.results.items()):
            self.assertIn(payload.get("status"), ACCEPTABLE, name)

    def test_assistant_domains_report_absence_with_a_reason(self):
        for name in ASSISTANT_DOMAINS:
            payload = self.results[name]
            self.assertEqual("unavailable", payload.get("status"), name)
            self.assertTrue((payload.get("reason") or "").strip(), name)
            self.assertEqual([], payload.get("findings"))

    def test_missing_ssh_directory_is_not_an_error(self):
        identity = self.results["identity"]
        self.assertNotEqual("error", identity.get("status"))

    def test_results_are_json_serialisable(self):
        json.dumps(self.results, default=str)

    def test_every_finding_carries_its_evidence(self):
        for name, payload in sorted(self.results.items()):
            for finding in payload.get("findings") or []:
                self.assertTrue(finding.get("id"), name)
                self.assertTrue(finding.get("title"), name)
                self.assertTrue(finding.get("evidence"), finding.get("id"))
                self.assertTrue(finding.get("why_it_matters"), finding.get("id"))
                self.assertIn(finding.get("severity"), ("critical", "warning", "info"), finding.get("id"))


class Registry(unittest.TestCase):
    def test_every_registered_domain_imports_and_exposes_collect(self):
        for name in registry.DOMAINS:
            module = registry.load(name)
            self.assertTrue(callable(getattr(module, "collect", None)), name)

    def test_assistant_family_is_registered(self):
        for name in ASSISTANT_DOMAINS:
            self.assertIn(name, registry.DOMAINS)
            self.assertIn(name, registry.AI_ASSISTANT_DOMAINS)

    def test_domain_labels_exist_in_both_languages(self):
        from macverify import i18n

        for name in registry.DOMAINS:
            for language in ("en", "es"):
                self.assertNotEqual(name, i18n.domain_label(language, name), "%s/%s" % (name, language))

    def test_unknown_domains_are_reported_not_raised(self):
        selected, unknown = registry.resolve(only=["toolchain", "not_a_domain"])
        self.assertEqual(["toolchain"], selected)
        self.assertEqual(["not_a_domain"], unknown)

    def test_only_and_skip_are_both_applied(self):
        selected, unknown = registry.resolve(only=["toolchain", "storage"], skip=["storage"])
        self.assertEqual(["toolchain"], selected)
        self.assertEqual([], unknown)

    def test_an_unknown_name_in_skip_is_reported(self):
        selected, unknown = registry.resolve(skip=["storage", "not_a_domain"])
        self.assertNotIn("storage", selected)
        self.assertEqual(["not_a_domain"], unknown)


class SshConfiguration(unittest.TestCase):
    """~/.ssh/config is parsed on every supported interpreter.

    The Host line was matched with an inline `(?i)` after `^`, which Python 3.11
    rejects outright, so the whole identity domain failed for anyone who had an
    ssh config at all. CI never saw it: its runners have no ~/.ssh/config.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="macverify-ssh-")
        os.makedirs(os.path.join(self.home, ".ssh"), mode=0o700)
        with open(os.path.join(self.home, ".ssh", "config"), "w", encoding="utf-8") as handle:
            handle.write("Host example\n  HostName example.com\n  User someone\n\nhost lower\n  Port 2222\n")
        self.previous_home = os.environ.get("HOME")
        os.environ["HOME"] = self.home

    def tearDown(self):
        if self.previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.previous_home
        shutil.rmtree(self.home, ignore_errors=True)

    def test_an_ssh_config_does_not_break_the_identity_domain(self):
        from macverify.collectors import identity

        payload = identity.collect(Context(timeout=5.0))
        self.assertEqual("ok", payload.get("status"))
        self.assertEqual("ok", payload["ssh"].get("status"), payload["ssh"].get("reason"))
        self.assertEqual(["example", "lower"], [item["pattern"] for item in payload["ssh"]["config_hosts"]])


if __name__ == "__main__":
    unittest.main()
