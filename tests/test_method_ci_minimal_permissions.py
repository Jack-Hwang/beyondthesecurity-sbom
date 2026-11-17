"""Gap-closing test for the "ci_minimal_permissions" audit item (dim D6).

Audit finding (own words, not slide text): neither GitHub Actions workflow in
this repo declared a `permissions:` block, so CI jobs ran with the (often
broader) org/repo default token scope instead of an explicit minimal one.

This test targets the bts-sbom CORE package workflow
(.github/workflows/ci.yml). Its single "package" job only checks out the
repo, lints, runs pytest and uploads build artifacts as a demo — it never
pushes a commit, a tag, a release, or a package registry entry, so a
read-only `contents: read` token is enough. We parse the workflow text with
a narrow, stdlib-only scanner (no PyYAML) to confirm:

  1. a top-level (column-0) `permissions:` key exists in the file, and
  2. the permissions block maps to exactly {"contents": "read"} — no extra
     scope, and in particular no write-scoped entry (e.g. `contents: write`,
     `id-token: write`) that the job does not need.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CI_YML = REPO / ".github" / "workflows" / "ci.yml"


def _top_level_permissions_block(text: str) -> dict[str, str] | None:
    """Return the top-level `permissions:` mapping, or None if absent.

    Only matches a `permissions:` key that starts at column 0 (i.e. a
    workflow-level key, not one nested under a job or step). Collects the
    indented `key: value` lines that immediately follow it, stopping at the
    next column-0 key or end of file.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^permissions:\s*(#.*)?$", line):
            block: dict[str, str] = {}
            for follow in lines[i + 1:]:
                if follow.strip() == "" or follow.startswith("#"):
                    continue
                if not follow.startswith((" ", "\t")):
                    break  # next top-level key: block is over
                m = re.match(r"^\s+([\w-]+):\s*([\w-]+)\s*(#.*)?$", follow)
                if not m:
                    break
                block[m.group(1)] = m.group(2)
            return block
    return None


def test_ci_yml_declares_a_top_level_permissions_block():
    text = CI_YML.read_text(encoding="utf-8")
    block = _top_level_permissions_block(text)
    assert block is not None, (
        "ci.yml has no top-level `permissions:` block; the package job "
        "inherits the broader default token scope instead of an explicit "
        "minimal one"
    )


def test_ci_yml_permissions_block_is_exactly_contents_read():
    text = CI_YML.read_text(encoding="utf-8")
    block = _top_level_permissions_block(text)
    assert block is not None
    assert block == {"contents": "read"}, (
        "expected exactly {'contents': 'read'} (0 write-scoped entries), "
        "got %r" % (block,)
    )


def test_ci_yml_permissions_block_has_zero_write_scoped_entries():
    text = CI_YML.read_text(encoding="utf-8")
    block = _top_level_permissions_block(text)
    assert block is not None
    write_scoped = {k: v for k, v in block.items() if v == "write"}
    assert write_scoped == {}, (
        "found write-scoped permission(s) the package job does not need: "
        "%r" % (write_scoped,)
    )
