"""Spec discipline: EARS shape + measured numbers + two-way traceability (lecture 'EARS lint')."""
from __future__ import annotations

import os

from sbomplus import speclint

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(ROOT, "specs", "sbomplus_features.md")


def test_every_ac_is_ears_shaped_with_a_number():
    assert speclint.lint(SPEC) == []
    assert len(speclint.parse(SPEC)) >= 40


def test_every_ac_has_a_test_and_every_test_reference_exists():
    missing, extra = speclint.trace(SPEC, os.path.join(ROOT, "tests", "sbomplus"))
    assert missing == [] and extra == []
