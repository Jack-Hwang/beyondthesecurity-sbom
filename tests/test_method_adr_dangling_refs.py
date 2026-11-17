"""ADR dangling-reference closure (lecture method M33: ADR template with
Decision/Rationale/Rejected-Alternatives/Consequences, 'a human decides,
Claude only explores alternatives', superseded by a new ADR number rather
than a date suffix).

Gap this closes: ``bts_sbom/sectors.py`` and
``bts_sbom_app/web/css/tokens.css`` each carry a code comment that cites
"ADR-0005" / "ADR-0006" as the design rationale, but no ``docs/adr/``
directory existed anywhere in the repository -- a dangling reference to a
decision record that was never written. This test module:

1. provides ``adr_lint(path)``, a small stdlib-only structure checker for
   the 4 required ADR sections (also requiring >= 1 rejected alternative,
   per the lecture note that an ADR with no rejected alternative is
   "a decision with no record of why the other option was dropped");
2. asserts the two ADR documents exist, lint clean, and are the real
   target of the two dangling code comments above.

Honesty contract: ``adr_lint`` never treats a missing or unreadable file as
a silent pass -- a malformed path is an explicit error, not a result.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

REPO = Path(__file__).resolve().parents[1]
ADR_DIR = REPO / "docs" / "adr"
ADR_0005 = ADR_DIR / "ADR-0005-css-load-order.md"
ADR_0006 = ADR_DIR / "ADR-0006-evidence-latest-history.md"

SECTORS_PY = REPO / "bts_sbom" / "sectors.py"
TOKENS_CSS = REPO / "bts_sbom_app" / "web" / "css" / "tokens.css"

REQUIRED_SECTIONS = ("Decision", "Rationale", "Rejected Alternatives", "Consequences")
_SECTION_RE = re.compile(r"^#{1,3}\s+(.+?)\s*$", re.MULTILINE)
_REJECTED_ROW_RE = re.compile(r"^\s*[-*|]\s*\S", re.MULTILINE)


def adr_lint(path) -> List[str]:
    """Check an ADR document for the 4 required sections and >= 1 rejected
    alternative. Returns a list of problem strings (empty == lint clean).

    A missing or unreadable file is never a silent pass: it raises
    ``FileNotFoundError`` / ``OSError`` like any other honest I/O error,
    the same way the rest of BTS-SBOM treats absent evidence as absent,
    not as a measured zero.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")  # raises if path is missing/unreadable

    headings = [m.group(1).strip() for m in _SECTION_RE.finditer(text)]
    problems: List[str] = []
    for section in REQUIRED_SECTIONS:
        if section not in headings:
            problems.append("missing required section: %s" % section)

    if "Rejected Alternatives" in headings:
        start = text.index("Rejected Alternatives")
        after = text[start:]
        next_heading = _SECTION_RE.search(after, len(after.splitlines()[0]) + 1)
        body = after[: next_heading.start()] if next_heading else after
        body = "\n".join(body.splitlines()[1:])  # drop the heading line itself
        rows = [m for m in _REJECTED_ROW_RE.finditer(body)]
        if not rows:
            problems.append("Rejected Alternatives section lists no alternative")

    return problems


# ── the ADR documents exist and lint clean ──────────────────────────────────

def test_adr_0005_exists_and_lints_clean():
    assert ADR_0005.is_file(), "docs/adr/ADR-0005-css-load-order.md is missing"
    assert adr_lint(ADR_0005) == []


def test_adr_0006_exists_and_lints_clean():
    assert ADR_0006.is_file(), "docs/adr/ADR-0006-evidence-latest-history.md is missing"
    assert adr_lint(ADR_0006) == []


# ── the dangling code comments now resolve to a real document ──────────────

def test_sectors_py_adr_0006_comment_resolves_to_real_file():
    text = SECTORS_PY.read_text(encoding="utf-8")
    assert "ADR-0006" in text, "expected code comment referencing ADR-0006 is gone"
    assert ADR_0006.is_file(), "ADR-0006 code comment is dangling: no such file"


def test_tokens_css_adr_0005_comment_resolves_to_real_file():
    text = TOKENS_CSS.read_text(encoding="utf-8")
    assert "ADR-0005" in text, "expected code comment referencing ADR-0005 is gone"
    assert ADR_0005.is_file(), "ADR-0005 code comment is dangling: no such file"


def test_adr_0006_mentions_append_only_history_decision():
    text = ADR_0006.read_text(encoding="utf-8")
    assert "append-only" in text.lower()
    assert "history" in text.lower()


def test_adr_0005_mentions_css_load_order_decision():
    text = ADR_0005.read_text(encoding="utf-8")
    assert "tokens.css" in text
    assert "app.css" in text


# ── adr_lint honesty: malformed input is an explicit error, never a pass ────

def test_adr_lint_raises_on_missing_file():
    missing = ADR_DIR / "ADR-9999-does-not-exist.md"
    try:
        adr_lint(missing)
    except (FileNotFoundError, OSError):
        pass
    else:
        raise AssertionError("adr_lint silently accepted a missing file")


def test_adr_lint_reports_missing_sections(tmp_path):
    incomplete = tmp_path / "ADR-0000-incomplete.md"
    incomplete.write_text(
        "# ADR-0000: incomplete\n\n## Decision\n\nDo the thing.\n", encoding="utf-8"
    )
    problems = adr_lint(incomplete)
    assert any("Rationale" in p for p in problems)
    assert any("Rejected Alternatives" in p for p in problems)
    assert any("Consequences" in p for p in problems)


def test_adr_lint_reports_rejected_alternatives_with_no_rows(tmp_path):
    no_rows = tmp_path / "ADR-0001-empty-alternatives.md"
    no_rows.write_text(
        "# ADR-0001\n\n"
        "## Decision\n\nDo the thing.\n\n"
        "## Rationale\n\nBecause reasons.\n\n"
        "## Rejected Alternatives\n\n"
        "## Consequences\n\nIt works.\n",
        encoding="utf-8",
    )
    problems = adr_lint(no_rows)
    assert any("lists no alternative" in p for p in problems)
