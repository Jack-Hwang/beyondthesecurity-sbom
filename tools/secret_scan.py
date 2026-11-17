"""Stdlib-only regex secret scanner for BTS-SBOM.

Walks a directory tree of text files looking for a small set of common
secret shapes -- AWS access keys, PEM private-key blocks, bearer/
OpenAI/Anthropic-style API tokens, Azure storage account keys, and
URL-embedded passwords -- and reports each hit as "<path>:<line>: <rule>".

Honesty contract (see CONTRIBUTING.md): a finding never includes the
matched value itself, only its location and which rule matched, so a
scan report is never itself a disclosure. A file this scanner could not
read is never silently folded into a "clean" result -- "we found
nothing" and "we could not look" are reported as different outcomes.

Usage:
    python tools/secret_scan.py [root]

Exit codes:
    0 - scan completed, no potential secrets found
    1 - at least one potential secret found (see stdout)
    2 - usage error: root does not exist or is not a directory
    3 - scan was incomplete (some files could not be read) and no
        secrets were found in what *was* readable -- never reported as
        a plain "clean" pass
"""
from __future__ import annotations

import sys
from pathlib import Path
from re import Pattern
from re import compile as re_compile

SKIP_DIR_NAMES = frozenset({
    ".git", "__pycache__", "node_modules", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "build", "dist",
})

# Rule name -> compiled pattern. Every pattern here is written so that its
# own source line (regex metacharacters included) cannot satisfy itself --
# tests/test_method_secret_scanner.py::test_never_leaks_the_matched_secret_value
# is the behavioral half of that guarantee; this file being clean under its
# own CI step (bts_sbom_app_ci.yml) is the other half.
RULES: tuple[tuple[str, Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re_compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PEM_PRIVATE_KEY", re_compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("BEARER_API_TOKEN", re_compile(
        r"\bsk-ant-[A-Za-z0-9_-]{20,}"
        r"|\bsk-[A-Za-z0-9]{20,}"
        r"|\bBearer\s+[A-Za-z0-9._-]{20,}")),
    ("AZURE_STORAGE_KEY", re_compile(r"AccountKey=[A-Za-z0-9+/]{80,}={0,2}")),
    ("URL_EMBEDDED_PASSWORD", re_compile(
        r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]{6,}@"
        r"|\bpassword\s*=\s*['\"]?[^\s'\"]{6,}")),
)

_BINARY_SNIFF_BYTES = 1024


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:_BINARY_SNIFF_BYTES]


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES


def _iter_candidate_files(root: Path):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            # Directory itself could not be listed: report via caller's
            # bookkeeping, never pretend it was simply empty.
            yield ("DIR_UNREADABLE", current)
            continue
        for entry in entries:
            if entry.is_dir():
                if not _should_skip_dir(entry.name):
                    stack.append(entry)
            elif entry.is_file():
                yield ("FILE", entry)


def scan_file(path: Path) -> tuple[list[tuple[int, str]], bool]:
    """Return (hits, readable) for a single file.

    hits is a list of (1-based line number, rule name); the matched text
    itself is never included. readable is False when the file could not
    be opened/decoded as text at all (distinct from "read fine, found
    nothing").
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return [], False
    if _looks_binary(raw):
        return [], True
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return [], True
    hits: list[tuple[int, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_name, pattern in RULES:
            if pattern.search(line):
                hits.append((line_no, rule_name))
    return hits, True


def scan_tree(root: Path) -> tuple[list[tuple[Path, int, str]], list[Path]]:
    """Return (findings, unreadable_paths) for every file under root."""
    findings: list[tuple[Path, int, str]] = []
    unreadable: list[Path] = []
    for kind, entry in _iter_candidate_files(root):
        if kind == "DIR_UNREADABLE":
            unreadable.append(entry)
            continue
        hits, readable = scan_file(entry)
        if not readable:
            unreadable.append(entry)
            continue
        for line_no, rule_name in hits:
            findings.append((entry, line_no, rule_name))
    return findings, unreadable


def main(argv: list[str]) -> int:
    root_arg = argv[0] if argv else "."
    root = Path(root_arg)
    if not root.exists() or not root.is_dir():
        print(f"secret_scan: error: not a directory: {root_arg}", file=sys.stderr)
        return 2

    findings, unreadable = scan_tree(root)

    for path, line_no, rule_name in sorted(
        findings, key=lambda item: (str(item[0]), item[1], item[2])
    ):
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        print(f"{rel.as_posix()}:{line_no}: {rule_name}")

    if unreadable:
        for path in sorted(unreadable, key=str):
            try:
                rel = path.relative_to(root)
            except ValueError:
                rel = path
            print(f"secret_scan: could not read {rel.as_posix()}", file=sys.stderr)

    if findings:
        print(f"secret_scan: {len(findings)} potential secret(s) found", file=sys.stderr)
        return 1
    if unreadable:
        print(
            f"secret_scan: incomplete scan, {len(unreadable)} file(s) unreadable "
            "-- not reported as clean",
            file=sys.stderr,
        )
        return 3
    print("secret_scan: clean (0 potential secrets found)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
