import unittest

from macverify import findings as F
from macverify import quickfix

DESTRUCTIVE_COMMANDS = (
    "rm -rf ~/Library/Caches/pip",
    "brew uninstall node",
    "brew cleanup",
    "docker system prune -a",
    "rmdir /tmp/example",
    "killall Finder",
    "launchctl bootout gui/501/com.example.agent",
    "npm cache clean --force",
    "yarn cache clean",
    "git clean -fd",
    "pip cache purge",
)

ELEVATED_COMMANDS = (
    "sudo spctl --master-enable",
    "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
    "sudo grep -r NOPASSWD /etc/sudoers",
    "sudo powermetrics --samplers smc -n 1",
)

READ_ONLY_COMMANDS = (
    "ls -la ~/Library/LaunchAgents",
    "brew doctor",
    "brew outdated",
    "git status",
    "softwareupdate -l",
    "stat -f '%Sp' ~/.ssh/id_rsa",
    "defaults read com.apple.finder",
)


def finding_with(action, severity="warning"):
    return F.finding("test", severity, "A title", "evidence", "why it matters", action, True)


class Tiering(unittest.TestCase):
    def test_destructive_commands_are_always_careful(self):
        for command in DESTRUCTIVE_COMMANDS:
            tier, _ = quickfix._command_tier(command)
            self.assertEqual("careful", tier, command)

    def test_elevated_commands_are_always_careful(self):
        for command in ELEVATED_COMMANDS:
            tier, elevated = quickfix._command_tier(command)
            self.assertEqual("careful", tier, command)
            self.assertTrue(elevated, command)

    def test_read_only_commands_are_inspect(self):
        for command in READ_ONLY_COMMANDS:
            tier, elevated = quickfix._command_tier(command)
            self.assertEqual("inspect", tier, command)
            self.assertFalse(elevated, command)

    def test_a_compound_command_takes_the_highest_tier_of_its_parts(self):
        for command in (
            "ls ~/Library && rm -rf ~/Library/Caches/pip",
            "brew list; brew uninstall node",
            "git status || sudo rm /etc/hosts",
            "cat /etc/hosts | grep example && brew cleanup",
        ):
            tier, _ = quickfix._command_tier(command)
            self.assertEqual("careful", tier, command)

    def test_a_safe_prefix_never_downgrades_a_dangerous_suffix(self):
        safe, _ = quickfix._command_tier("ls -la")
        compound, _ = quickfix._command_tier("ls -la && rm -rf /tmp/x")
        self.assertEqual("inspect", safe)
        self.assertEqual("careful", compound)

    def test_elevation_is_detected_through_a_compound_command(self):
        _, elevated = quickfix._command_tier("brew list && sudo brew upgrade")
        self.assertTrue(elevated)

    def test_an_unknown_binary_is_not_assumed_read_only(self):
        tier, _ = quickfix._command_tier("some-unknown-tool --wipe-everything")
        self.assertIn(tier, ("apply", "careful"))
        self.assertNotEqual("inspect", tier)

    def test_a_full_path_to_a_destructive_binary_is_still_careful(self):
        tier, _ = quickfix._command_tier("/bin/rm -rf /tmp/example")
        self.assertEqual("careful", tier)

    def test_tier_ranking_is_ordered_by_risk(self):
        self.assertLess(quickfix.TIER_RANK["inspect"], quickfix.TIER_RANK["apply"])
        self.assertLess(quickfix.TIER_RANK["apply"], quickfix.TIER_RANK["careful"])


class Classification(unittest.TestCase):
    def test_a_gui_instruction_becomes_a_manual_step_not_a_command(self):
        entry = quickfix.classify(finding_with("System Settings > Network > Firewall"))
        self.assertIsNone(entry.get("command"))
        self.assertTrue(entry.get("manual_step"))

    def test_a_trailing_comment_is_split_into_a_note(self):
        entry = quickfix.classify(finding_with("softwareupdate -l   # this audit did not check online"))
        self.assertEqual("softwareupdate -l", entry["command"])
        self.assertIn("did not check online", entry["note"])

    def test_a_finding_without_an_action_yields_nothing_to_run(self):
        entry = quickfix.classify(finding_with(None))
        self.assertIsNone(entry.get("command"))


class Plan(unittest.TestCase):
    def setUp(self):
        self.plan = quickfix.build([
            finding_with("ls -la ~/Library/LaunchAgents"),
            finding_with("ls -la ~/Library/LaunchAgents", severity="info"),
            finding_with("chmod 600 ~/.netrc"),
            finding_with("rm -rf ~/Library/Caches/pip"),
            finding_with("sudo spctl --master-enable"),
            finding_with("System Settings > General > Sharing"),
        ])

    def test_identical_commands_are_deduplicated(self):
        commands = [entry["command"] for entry in self.plan["commands"]]
        self.assertEqual(len(commands), len(set(commands)))

    def test_every_tier_is_a_known_tier(self):
        for entry in self.plan["commands"]:
            self.assertIn(entry["tier"], quickfix.TIERS)

    def test_counts_match_the_entries(self):
        counts = self.plan["counts"]
        self.assertEqual(len(self.plan["commands"]), counts["commands"])
        self.assertEqual(len(self.plan["manual_steps"]), counts["manual_steps"])
        for tier in quickfix.TIERS:
            self.assertEqual(len(quickfix.by_tier(self.plan, tier)), counts[tier])

    def test_nothing_elevated_or_destructive_escapes_the_careful_tier(self):
        for entry in self.plan["commands"]:
            if entry["needs_elevation"] or any(marker in entry["command"] for marker in ("rm ", "prune", "uninstall")):
                self.assertEqual("careful", entry["tier"], entry["command"])

    def test_the_plan_states_that_nothing_was_executed(self):
        self.assertIn("executed none", self.plan["note"])

    def test_every_command_traces_back_to_a_finding(self):
        for entry in self.plan["commands"]:
            self.assertTrue(entry["finding_ids"])
            self.assertTrue(entry["titles"])


if __name__ == "__main__":
    unittest.main()
