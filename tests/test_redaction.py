"""Redaction tests.

Every credential here is fabricated and assembled at runtime from fragments, so
no contiguous credential-shaped literal exists in this file. That keeps the
repository clean to secret scanners, including macverify's own detector, which
would otherwise flag its own test fixtures.
"""

import json
import os
import shutil
import tempfile
import unittest

from macverify import report_html, report_md
from macverify.collectors import secrets
from macverify.context import Context


def synthetic(prefix, body):
    return prefix + body


PLANTED = {
    "openai_legacy": synthetic("sk-", "abc123DEADBEEF0987654321abcdefXYZQRSTUV"),
    "openai_project": synthetic("sk-", "proj-ZZTOPsecretVALUE1234567890abcdefghijklmn"),
    "github_token": synthetic("ghp_", "w" * 36),
    "shell_password": "hunter2SuperSecretPassword",
    "aws_key_id": synthetic("AKIA", "IOSFODNN7EXAMPLE"),
    "aws_secret": "wJalrXUtnFEMIbKbrutalWKEYlongEXAMPLEKEY",
    "client_secret": "abcdefghijklmnopqrstuvwxyz012345",
    "anthropic_key": synthetic("sk-", "ant-api03-" + "Z" * 30),
}

ZSHRC = "\n".join([
    "export API_KEY=" + PLANTED["openai_legacy"],
    'export OPENAI_API_KEY="' + PLANTED["openai_project"] + '"',
    "export GITHUB_TOKEN=" + PLANTED["github_token"],
    "export DB_PASSWORD='" + PLANTED["shell_password"] + "'",
]) + "\n"

AWS = "\n".join([
    "[default]",
    "aws_access_key_id = " + PLANTED["aws_key_id"],
    "aws_secret_access_key = " + PLANTED["aws_secret"],
]) + "\n"

APP_ENV = "\n".join([
    "CLIENT_SECRET=" + PLANTED["client_secret"],
    "ANTHROPIC_API_KEY=" + PLANTED["anthropic_key"],
]) + "\n"


def build_home(root):
    os.makedirs(os.path.join(root, ".aws"))
    os.makedirs(os.path.join(root, ".config", "demo"))
    for relative, body in (
        (".zshrc", ZSHRC),
        (os.path.join(".aws", "credentials"), AWS),
        (os.path.join(".config", "demo", "app.env"), APP_ENV),
    ):
        with open(os.path.join(root, relative), "w", encoding="utf-8") as handle:
            handle.write(body)


def dataset_for(payload):
    return {
        "schema_version": 1,
        "tool": {"name": "macverify", "version": "test", "mode": "read-only"},
        "generated_at": "2026-01-01T00:00:00Z",
        "system": {},
        "compatibility": {"supported": True, "warnings": [], "capability_notes": []},
        "scope": {"reads": [], "cannot_detect": [], "recommended_scanners": []},
        "run": {"domains": ["secrets"], "per_command_timeout_seconds": 8, "language": "en",
                "extra_projects": [], "statuses": {"secrets": "ok"}},
        "summary": {"finding_counts": {"critical": 0, "warning": 0, "info": 0},
                    "total_findings": len(payload["findings"]),
                    "domains_ok": ["secrets"], "domains_degraded": []},
        "findings": payload["findings"],
        "quick_fixes": {"note": "", "counts": {"commands": 0, "inspect": 0, "apply": 0, "careful": 0, "manual_steps": 0},
                        "commands": [], "manual_steps": []},
        "domains": {"secrets": payload},
    }


class Redaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix="macverify-redaction-")
        build_home(cls.home)
        cls.previous_home = os.environ.get("HOME")
        os.environ["HOME"] = cls.home
        cls.payload = secrets.collect(Context(cwd=cls.home))
        cls.json_text = json.dumps(cls.payload, indent=2, default=str)
        dataset = dataset_for(cls.payload)
        cls.html_text = report_html.render(dataset, "en")
        cls.markdown_text = report_md.render(dataset, "en")

    @classmethod
    def tearDownClass(cls):
        if cls.previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = cls.previous_home
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_the_planted_credentials_were_actually_found(self):
        self.assertGreaterEqual(self.payload["match_count"], 8)

    def test_no_full_secret_value_in_any_output(self):
        for label, secret in sorted(PLANTED.items()):
            for surface, text in (("json", self.json_text), ("html", self.html_text), ("markdown", self.markdown_text)):
                self.assertNotIn(secret, text, "%s leaked into %s" % (label, surface))

    def test_no_secret_body_fragment_in_any_output(self):
        for label, secret in sorted(PLANTED.items()):
            fragment = secret[4:16]
            self.assertGreater(len(fragment), 6)
            for surface, text in (("json", self.json_text), ("html", self.html_text), ("markdown", self.markdown_text)):
                self.assertNotIn(fragment, text, "%s body fragment leaked into %s" % (label, surface))

    def test_masked_prefix_is_four_characters(self):
        for hit in self.payload["matches"]:
            masked = hit["masked_prefix"]
            self.assertTrue(masked.endswith("*" * 12), masked)
            self.assertLessEqual(len(masked.rstrip("*")), 4, masked)

    def test_policy_statement_is_present(self):
        self.assertIn("no secret value is read into the report", self.payload["policy"])

    def test_mask_never_returns_more_than_a_prefix(self):
        self.assertEqual("abcd" + "*" * 12, secrets.mask("abcdefghijklmnop"))
        self.assertNotIn("efghijklmnop", secrets.mask("abcdefghijklmnop"))


if __name__ == "__main__":
    unittest.main()
