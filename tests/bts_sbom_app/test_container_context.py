"""The cloud build uploads the whole build context: only what the Dockerfile copies may be in it."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _lines(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return [ln.strip() for ln in fh.read().splitlines()]


def test_the_build_context_is_an_allowlist_of_exactly_what_the_dockerfile_copies():
    """AC: BSA-AC-1200"""
    ignore = [ln for ln in _lines(".dockerignore") if ln and not ln.startswith("#")]
    assert ignore[0] == "*"                                                                       # deny everything, then re-include
    included = {ln[1:] for ln in ignore if ln.startswith("!")}
    copied = set()
    for ln in _lines("Dockerfile.bts-sbom-app"):
        m = re.match(r"^COPY\s+(.+)\s+\S+$", ln)
        if m:
            copied.update(m.group(1).split())
    assert copied == {"pyproject.toml", "README.md", "LICENSE", "bts_sbom", "bts_sbom_app", "knowledge", "evals"}          # 7 of 7 copied paths
    assert copied <= included and included - copied == {"Dockerfile.bts-sbom-app"}                 # nothing else is re-included except the Dockerfile itself
    for secret_bearing in ("evidence", "_attic", "downloads", ".claude", ".git", "tests", "docs", ".env", "bts_sbom_osv_local.db"):
        assert secret_bearing not in included, secret_bearing                                      # 9 of 9 sensitive or irrelevant paths stay out of the context
    assert "**/__pycache__" in ignore and "**/*.pyc" in ignore
