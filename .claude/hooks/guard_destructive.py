#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block destructive Bash commands in this repo.

Gap-closing item "dev_safety_hooks" (audit methods advlab-harness:M16,
advlab-harness:M18, advlab-project:M33 -- own implementation, not copied
from course material). Wired by the opt-in example ../settings.example.json as a PreToolUse hook
matching the Bash tool.

Protocol (Claude Code hook stdin/exit-code contract used by this item):
  * stdin carries one JSON object describing the pending tool call
    (fields of interest: "tool_name", "tool_input").
  * exit 0  -- allow: the command is safe, the tool call proceeds.
  * exit 1  -- ask: the command is ambiguous, Claude Code should ask the
               operator to confirm before proceeding (reason on stderr).
  * exit 2  -- block: the command matches a known-destructive pattern and
               the tool call is blocked outright (reason on stderr).

Honesty contract: absence of evidence is never a pass. If the hook cannot
read the command (malformed JSON, no object on stdin, or no command text in
tool_input), it fails CLOSED (exit 2) with an explicit stderr message rather
than silently allowing an unknown command through.

stdlib only, no network, ASCII-only output.
"""
import json
import re
import sys

# ---------------------------------------------------------------------------
# Destructive patterns (exit 2 / block). At least these three classes:
#   1. rm -rf / -fr (recursive + force delete), any flag order or spelling.
#   2. git push --force / -f / --force-with-lease (history-rewriting push).
#   3. SQL DROP TABLE|DATABASE|SCHEMA or TRUNCATE TABLE.
# ---------------------------------------------------------------------------
RM_RF_RE = re.compile(
    r"\brm\b"
    r"(?=.*(?:-[a-zA-Z]*r[a-zA-Z]*\b|--recursive\b))"
    r"(?=.*(?:-[a-zA-Z]*f[a-zA-Z]*\b|--force\b))",
    re.IGNORECASE,
)
FORCE_PUSH_RE = re.compile(
    r"\bgit\b.*\bpush\b.*(?:--force\b|--force-with-lease\b|\s-f\b)",
    re.IGNORECASE,
)
SQL_DROP_TRUNCATE_RE = re.compile(
    r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b",
    re.IGNORECASE,
)

BLOCK_PATTERNS = (
    ("rm -rf (recursive force delete)", RM_RF_RE),
    ("git push --force (history-rewriting push)", FORCE_PUSH_RE),
    ("SQL DROP/TRUNCATE statement", SQL_DROP_TRUNCATE_RE),
)

# ---------------------------------------------------------------------------
# Ambiguous patterns (exit 1 / ask): a non-force push that names a protected
# branch, or a bare push whose target branch is not named at all (so it is
# not knowable here whether it lands on a protected branch).
# ---------------------------------------------------------------------------
GIT_PUSH_RE = re.compile(r"\bgit\s+push\b", re.IGNORECASE)
PROTECTED_BRANCH_RE = re.compile(r"\b(?:main|master)\b", re.IGNORECASE)
BARE_PUSH_RE = re.compile(r"^\s*git\s+push(?:\s+origin)?\s*$", re.IGNORECASE)


def _flatten_strings(value):
    """Collect every string found in a (possibly nested) tool_input value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_strings(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten_strings(v) for v in value)
    return ""


def extract_command_text(payload):
    """Pull the shell command (or best-effort text) out of a hook payload."""
    tool_input = payload.get("tool_input", {})
    if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
        return tool_input["command"]
    return _flatten_strings(tool_input)


def classify_command(text):
    """Return (decision, reason) where decision is 'block' / 'ask' / 'allow'."""
    command = text.strip()
    if not command:
        return "block", "no command text found in hook input (unknown is never treated as safe)"

    for name, pattern in BLOCK_PATTERNS:
        if pattern.search(command):
            return "block", "matched destructive pattern: " + name

    if GIT_PUSH_RE.search(command):
        has_force = re.search(r"--force\b|--force-with-lease\b|\s-f\b", command, re.IGNORECASE)
        if not has_force:
            targets_protected = PROTECTED_BRANCH_RE.search(command)
            is_bare = BARE_PUSH_RE.match(command) is not None
            if targets_protected or is_bare:
                return "ask", "git push to a protected or unspecified branch without --force"

    return "allow", "no destructive or ambiguous pattern matched"


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print("guard_destructive: empty hook input on stdin; blocking", file=sys.stderr)
        return 2

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print("guard_destructive: malformed hook input (invalid JSON): %s" % exc, file=sys.stderr)
        return 2

    if not isinstance(payload, dict):
        print("guard_destructive: malformed hook input (expected a JSON object)", file=sys.stderr)
        return 2

    command_text = extract_command_text(payload)
    decision, reason = classify_command(command_text)

    if decision == "block":
        print("guard_destructive: BLOCKED - " + reason, file=sys.stderr)
        return 2
    if decision == "ask":
        print("guard_destructive: ASK - " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
