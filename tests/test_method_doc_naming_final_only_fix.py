"""Regression test for the repository's own Final-Only-Rule naming violation.

Course material (paraphrased, not quoted): a document that gets superseded
should be edited or replaced in place rather than kept alongside a dated or
versioned sibling copy -- ship exactly one current file per topic, and put
any date or version number inside the document (a heading or front-matter
line), never baked into the tracked filename.

Before the fix, docs/ANALYSIS_2026-11-17.md violated this with an ISO date
embedded in the filename. This test enumerates every tracked docs/*.md and
specs/*.md file and fails if any filename stem matches a dated/versioned
pattern (``_v12``, an 8-digit compact date, an ISO ``YYYY-MM-DD`` date, or a
``_final``/``_old`` marker). It is red against the pre-fix tree (one
offender) and green once the doc is renamed to docs/BTS_SBOM_ANALYSIS.md with
the date moved into the document body instead of the filename.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# _v12 / _v2.3 style version suffix, an 8-digit compact date (_20261117), an
# ISO date (2026-11-17) anywhere in the stem, or a trailing _final / _old
# marker.
DATED_OR_VERSIONED = re.compile(
    r"(_v\d+(?:\.\d+)*|\d{4}-\d{2}-\d{2}|\d{8}|_final\b|_old\b)",
    re.IGNORECASE,
)


def _offending_doc_filenames() -> list[str]:
    offenders = []
    for glob_pattern in ("docs/*.md", "specs/*.md"):
        for path in sorted(REPO_ROOT.glob(glob_pattern)):
            if DATED_OR_VERSIONED.search(path.stem):
                offenders.append(path.relative_to(REPO_ROOT).as_posix())
    return offenders


def test_no_dated_or_versioned_doc_filenames():
    offenders = _offending_doc_filenames()
    assert offenders == [], (
        "tracked docs/*.md or specs/*.md filenames must not carry a dated or "
        "versioned suffix; move the date/version into a heading or "
        "front-matter line inside the document instead. Offending file(s): "
        + ", ".join(offenders)
    )
