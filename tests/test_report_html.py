"""Report integrity tests.

The HTML report is one self-contained file whose interactivity lives in a single
inline IIFE. A stray character anywhere in that script is a parse error, and a
parse error means no tab responds, no section is ever unhidden and the whole
report renders as a nav bar above a blank page. These tests assert the rendered
document is structurally sound, not merely that it was produced.
"""

import unittest
from html.parser import HTMLParser

from macverify import findings as F
from macverify import quickfix, report_html

CONTROL_CHARACTERS = set(range(0x00, 0x09)) | set(range(0x0E, 0x20)) | set(range(0x7F, 0xA0))


def sample_findings():
    return [
        F.finding("network", "warning", "Remote Login is enabled", "sshd is accepting connections",
                  "An open listener widens the attack surface.", "sudo systemsetup -setremotelogin off", False),
        F.finding("toolchain", "info", "Multiple python interpreters installed",
                  "pyenv 3.12.13 and /usr/bin/python3 3.9.6",
                  "Ambiguity about which interpreter runs.", "pyenv versions", True),
        F.finding("storage", "info", "Reclaimable caches", "13.7 GB across 17 paths",
                  "Caches regenerate and can be cleared.", "du -sh ~/Library/Caches", True),
    ]


def dataset():
    items = F.sort_findings(sample_findings())
    plan = quickfix.build(items)
    domains = {}
    for name in ("network", "toolchain", "storage"):
        domains[name] = {"status": "ok", "findings": [i for i in items if i["domain"] == name],
                         "detail": {"example": "value"}}
    return {
        "schema_version": 1,
        "tool": {"name": "macverify", "version": "test", "mode": "read-only"},
        "generated_at": "2026-01-01T00:00:00Z",
        "system": {"hostname": "test-host", "user": "tester"},
        "compatibility": {"supported": True, "warnings": [], "capability_notes": []},
        "scope": {"reads": ["configuration"], "cannot_detect": ["malware"], "recommended_scanners": ["KnockKnock"]},
        "run": {"domains": list(domains), "per_command_timeout_seconds": 8, "language": "en",
                "extra_projects": [], "statuses": {name: "ok" for name in domains}},
        "summary": {"finding_counts": F.counts(items), "total_findings": len(items),
                    "domains_ok": list(domains), "domains_degraded": []},
        "findings": items,
        "quick_fixes": plan,
        "domains": domains,
    }


def script_of(html):
    opening = html.index("<script>") + len("<script>")
    return html[opening:html.index("</script>", opening)]


def unterminated_string(script):
    quote = None
    escaped = False
    for line_number, line in enumerate(script.split("\n"), start=1):
        for character in line:
            if escaped:
                escaped = False
            elif character == "\\" and quote:
                escaped = True
            elif quote:
                if character == quote:
                    quote = None
            elif character in ('"', "'"):
                quote = character
        if quote:
            return line_number, line.strip()
        escaped = False
    return None


class Markup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = report_html.render(dataset(), "en")

    def test_no_control_characters_survive_into_the_document(self):
        found = sorted({hex(ord(c)) for c in self.html if ord(c) in CONTROL_CHARACTERS})
        self.assertEqual([], found)

    def test_the_document_parses(self):
        errors = []

        class Reader(HTMLParser):
            def error(self, message):
                errors.append(message)

        Reader(convert_charrefs=True).feed(self.html)
        self.assertEqual([], errors)

    def test_every_tab_points_at_a_section_that_exists(self):
        import re
        tabs = re.findall(r'class="tab"[^>]*data-view="([^"]+)"', self.html)
        tabs += re.findall(r'data-view="([^"]+)"[^>]*class="tab"', self.html)
        views = set(re.findall(r'<section class="view" id="([^"]+)"', self.html))
        self.assertTrue(tabs)
        self.assertTrue(views)
        for name in tabs:
            self.assertIn(name, views)

    def test_every_internal_jump_target_exists(self):
        import re
        targets = set(re.findall(r'data-goto="([^"]+)"', self.html))
        views = set(re.findall(r'<section class="view" id="([^"]+)"', self.html))
        for name in targets:
            self.assertIn(name, views)


class InlineScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = script_of(report_html.render(dataset(), "en"))

    def test_no_string_literal_is_broken_across_a_newline(self):
        self.assertIsNone(unterminated_string(self.script))

    def test_the_newline_escape_reaches_the_browser_as_an_escape(self):
        self.assertIn('join("\\n")', self.script)
        self.assertNotIn('join("\n")', self.script)

    def test_the_script_is_one_immediately_invoked_function(self):
        self.assertTrue(self.script.strip().startswith("(function"))
        self.assertTrue(self.script.strip().endswith("})();"))

    def test_braces_and_parentheses_balance(self):
        for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
            self.assertEqual(self.script.count(opener), self.script.count(closer))


class Stylesheet(unittest.TestCase):
    def test_css_escapes_reach_the_browser_as_escapes(self):
        self.assertIn('content: "\\2212"', report_html.STYLE)
        self.assertNotIn("\x91", report_html.STYLE)

    def test_the_style_and_script_blocks_are_raw_literals(self):
        with open(report_html.__file__.replace(".pyc", ".py"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn('STYLE = r"""', source)
        self.assertIn('SCRIPT = r"""', source)


if __name__ == "__main__":
    unittest.main()
