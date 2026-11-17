# New test file for the dev_safety_hooks gap-closing item (audit methods
# advlab-harness:M16, advlab-harness:M18, advlab-project:M33 -- Claude Code
# PreToolUse guard against destructive commands run in this repo).
#
# Gap confirmed before writing this test: no .claude/ directory existed in
# this worktree (ls .claude -> "No such file or directory"). This file is a
# NEW file per the task's no-conflict rule.
#
# RED -> GREEN: before .claude/hooks/guard_destructive.py and
# .claude/settings.json exist, every test below fails (the subprocess tests
# fail because the script path does not exist / cannot be launched, and the
# settings tests fail with FileNotFoundError). After the hook and settings
# file are added, all tests pass.
#
# No "AC:" docstring line here: this is a core/dev item (not an app spec AC).
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK_PATH = REPO_ROOT / ".claude" / "hooks" / "guard_destructive.py"
SETTINGS_PATH = REPO_ROOT / ".claude" / "settings.json"


def run_hook(payload):
    """Feed a synthetic PreToolUse JSON payload to guard_destructive.py on
    stdin, as Claude Code itself does, and return the finished subprocess.

    payload may be a dict (will be JSON-encoded) or a raw string (used as-is,
    so malformed-input cases can be exercised).
    """
    stdin_text = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, "-I", str(HOOK_PATH)],
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
    )


def bash_payload(command):
    return {
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "synthetic test command"},
    }


class GuardDestructiveBlocksDangerousCommands(unittest.TestCase):
    """exit code 2 == blocked, for each of the >=3 required destructive
    pattern classes named in the AC: rm -rf, git push --force, DROP/TRUNCATE.
    """

    def test_rm_rf_is_blocked(self):
        for cmd in ("rm -rf /tmp/stuff", "rm -fr ./build", "rm -r -f /data"):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_force_push_is_blocked(self):
        for cmd in (
            "git push --force origin main",
            "git push -f origin feature/x",
            "git push --force-with-lease origin main",
        ):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_sql_drop_truncate_is_blocked(self):
        for cmd in (
            'sqlite3 db.sqlite "DROP TABLE users;"',
            'mysql -e "TRUNCATE TABLE sessions;"',
            'psql -c "DROP DATABASE prod;"',
        ):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 2, result.stderr)


class GuardDestructiveAsksForAmbiguousCommands(unittest.TestCase):
    """exit code 1 == ask, for commands that are risky but not unambiguously
    destructive (plain push to a protected branch, or a bare push whose
    target branch is not named)."""

    def test_plain_push_to_protected_branch_asks(self):
        for cmd in ("git push origin main", "git push origin master"):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_bare_push_asks(self):
        for cmd in ("git push", "git push origin"):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 1, result.stderr)


class GuardDestructiveAllowsSafeCommands(unittest.TestCase):
    """exit code 0 == allowed, for ordinary dev commands."""

    def test_safe_commands_are_allowed(self):
        for cmd in (
            "git status",
            "git push origin feature/my-branch",
            "python -m pytest -q tests/test_bts_sbom_pkg.py",
            "ls -la",
            "rm report.txt",
        ):
            with self.subTest(cmd=cmd):
                result = run_hook(bash_payload(cmd))
                self.assertEqual(result.returncode, 0, result.stderr)


class GuardDestructiveFailsClosedOnMalformedInput(unittest.TestCase):
    """Honesty contract: absence of evidence is never a pass. Malformed hook
    input, or a command the hook cannot read, must not be silently allowed;
    it blocks (exit 2) with an honest stderr message."""

    def test_invalid_json_blocks(self):
        result = run_hook("{not valid json")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.strip())

    def test_empty_stdin_blocks(self):
        result = run_hook("")
        self.assertEqual(result.returncode, 2)

    def test_missing_command_text_blocks(self):
        payload = {
            "session_id": "test-session",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {},
        }
        result = run_hook(payload)
        self.assertEqual(result.returncode, 2)


class ClaudeSettingsJsonWiresTheHook(unittest.TestCase):
    """.claude/settings.json must exist, be valid JSON, wire a PreToolUse
    hook to guard_destructive.py, declare the three permission tiers
    (allow/ask/deny) from method M16, and disable bypass-permissions mode."""

    def setUp(self):
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            self.settings = json.load(f)

    def test_pretooluse_hook_is_wired_to_guard_script(self):
        pretool_hooks = self.settings["hooks"]["PreToolUse"]
        commands = [
            h["command"]
            for entry in pretool_hooks
            for h in entry.get("hooks", [])
        ]
        self.assertTrue(
            any("guard_destructive.py" in c for c in commands),
            commands,
        )

    def test_permission_tiers_present(self):
        permissions = self.settings["permissions"]
        for tier in ("allow", "ask", "deny"):
            self.assertIn(tier, permissions)
            self.assertIsInstance(permissions[tier], list)
            self.assertGreater(len(permissions[tier]), 0)

    def test_bypass_permissions_mode_is_disabled(self):
        self.assertEqual(self.settings.get("disableBypassPermissionsMode"), "disable")


if __name__ == "__main__":
    unittest.main()
