"""Static non-overlap check for MODULE_OWNERS.md (gap-closing item: module_owners_map).

Closes the audit gap recorded for method ids advlab-project:M16,
practice-prompts:PP-20 and w1s3:w1s3-35: this repository has several
agents/sub-agents touching different top-level paths concurrently (the same
pattern ECU_Sentinel's e2e notes call the "concurrent agent committing"
conflict). Without a single table naming exactly one owning scope per
top-level path, two agents can edit the same directory without either of
them knowing a boundary exists.

This test parses MODULE_OWNERS.md as a plain markdown table and proves,
mechanically, that it covers every top-level directory in the repository
exactly once, with no two rows claiming overlapping/nesting paths. It fails
(red) when the file is absent and fails again if the table ever drifts out
of sync with the actual directory layout (a stale or hand-edited row is
caught, not silently trusted).

Acceptance (core/dev item, no AC id): MODULE_OWNERS.md lists exactly one
owning row for each of the repository's 10 top-level directories, with 0
overlapping path prefixes and 0 uncovered top-level directories.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OWNERS_FILE = REPO / "MODULE_OWNERS.md"

# Directories that are not product modules (VCS/CI metadata, caches) are
# never expected to appear in MODULE_OWNERS.md.
_EXCLUDED_DIR_NAMES = {"__pycache__", ".git", ".github"}

_TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")


def _actual_top_level_dirs() -> list[str]:
    """Top-level directories that actually exist in the repo right now."""
    return sorted(
        p.name
        for p in REPO.iterdir()
        if p.is_dir()
        and not p.name.startswith(".")
        and p.name not in _EXCLUDED_DIR_NAMES
    )


def _normalize_path_cell(cell: str) -> str:
    """Strip markdown/code decoration and a trailing slash from a path cell."""
    cleaned = cell.strip().strip("`").strip()
    cleaned = cleaned.rstrip("/")
    return cleaned


def parse_owners_table(text: str) -> list[tuple[str, str]]:
    """Parse the first markdown table in `text` into (path, owner) pairs.

    Skips the header row and the `---|---` separator row. Raises ValueError
    on a data row that has fewer than 2 cells (malformed table: an honest
    error, not a silently-dropped row).
    """
    rows: list[tuple[str, str]] = []
    seen_header = False
    for line in text.splitlines():
        m = _TABLE_ROW_RE.match(line.strip())
        if not m:
            continue
        cells = [c.strip() for c in m.group(1).split("|")]
        if not seen_header:
            # First table row encountered is the header.
            seen_header = True
            continue
        if all(set(c) <= {"-", ":", " "} and c for c in cells):
            # Markdown header/body separator row, e.g. |---|---|.
            continue
        if len(cells) < 2:
            raise ValueError(f"malformed MODULE_OWNERS.md row (need >=2 cells): {line!r}")
        path = _normalize_path_cell(cells[0])
        owner = cells[1].strip()
        if path:
            rows.append((path, owner))
    return rows


def _paths_overlap(a: str, b: str) -> bool:
    """True if path `a` nests inside/equals path `b` or vice versa."""
    if a == b:
        return True
    return a.startswith(b + "/") or b.startswith(a + "/")


def test_module_owners_file_exists() -> None:
    assert OWNERS_FILE.is_file(), (
        "MODULE_OWNERS.md is missing - absence of an owners table is not a "
        "pass; no boundary exists for concurrent agents to respect."
    )


def test_module_owners_table_has_rows() -> None:
    rows = parse_owners_table(OWNERS_FILE.read_text(encoding="utf-8"))
    assert rows, "MODULE_OWNERS.md has no parseable table rows"


def test_every_row_has_a_named_owner() -> None:
    rows = parse_owners_table(OWNERS_FILE.read_text(encoding="utf-8"))
    blank = [path for path, owner in rows if not owner]
    assert not blank, f"rows with no owner assigned (blank is never a pass): {blank}"


def test_no_two_rows_overlap() -> None:
    rows = parse_owners_table(OWNERS_FILE.read_text(encoding="utf-8"))
    paths = [path for path, _owner in rows]
    overlaps = []
    for i, a in enumerate(paths):
        for b in paths[i + 1 :]:
            if _paths_overlap(a, b):
                overlaps.append((a, b))
    assert not overlaps, f"overlapping/nesting owner rows found: {overlaps}"


def test_every_top_level_directory_is_covered_exactly_once() -> None:
    rows = parse_owners_table(OWNERS_FILE.read_text(encoding="utf-8"))
    owned_paths = [path for path, _owner in rows]
    actual_dirs = _actual_top_level_dirs()

    counts = {d: owned_paths.count(d) for d in actual_dirs}
    uncovered = [d for d, n in counts.items() if n == 0]
    duplicated = [d for d, n in counts.items() if n > 1]

    assert not uncovered, f"top-level dirs with no owning row: {uncovered}"
    assert not duplicated, f"top-level dirs owned by more than one row: {duplicated}"

    stale = [p for p in owned_paths if p not in actual_dirs]
    assert not stale, (
        f"MODULE_OWNERS.md rows name directories that do not exist in the "
        f"repo (stale, not honest): {stale}"
    )
