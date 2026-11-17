"""Regression tests for the loop regression gate's detection-collapse / unknown-metric blind spot.

docs/ANALYSIS_2026-11-17.md section 3 item 6 (sbomplus/loop.py:43-63, confirmed critical/high, loop.py:49):
gate() only compared keys present and non-None in BOTH the baseline and the candidate metrics vector. That let three
things silently "pass" as "no regression":
  (a) a metric measured in the baseline but missing/None in the candidate (an honest "we didn't measure it" collapsed
      to "didn't regress" instead of "unknown");
  (b) a candidate that detects zero components/vulnerabilities against a healthy baseline (components/vulns were not
      gated metrics at all); and
  (c) a candidate with (almost) no metrics at all, since every comparison was simply skipped.
This violates the product's honesty contract (absence of evidence is never a pass) applied to the loop's own
engineering gate. These tests are new (file created only for this fix); no existing test file is modified.
"""
from __future__ import annotations

from bts_sbom_app import loop


def test_total_detection_collapse_fails_the_gate():
    """AC: BSA-AC-200

    Direct repro from the analysis report: a candidate that detects 0 components / 0 vulnerabilities against a
    healthy baseline, with the resulting rates collapsing to None (denominator 0) or staying trivially 1.0, must
    FAIL -- not be accepted as "no regression".
    """
    base = {"components": 2000, "vulns": 1200, "license_resolved_rate": 0.9, "plan_verified_rate": 0.8,
            "fix_applied_rate": 0.7, "sbom_ref_rate": 1.0, "cyclonedx_valid_rate": 1.0, "spdx_valid_rate": 1.0}
    cand = {"components": 0, "vulns": 0, "license_resolved_rate": None, "plan_verified_rate": None,
            "fix_applied_rate": None, "sbom_ref_rate": 1.0, "cyclonedx_valid_rate": 1.0, "spdx_valid_rate": 1.0}
    g = loop.gate(base, cand)
    assert g["pass"] is False
    assert any("components" in f and "collapse" in f for f in g["failed"])
    assert any("vulns" in f and "collapse" in f for f in g["failed"])


def test_components_collapse_to_zero_fails_alone():
    """AC: BSA-AC-200 (vector 1 of 3): components baseline > 0, candidate == 0 -> fail, even with vulns untouched."""
    base = {"components": 500, "vulns": 10}
    cand = {"components": 0, "vulns": 10}
    g = loop.gate(base, cand)
    assert g["pass"] is False
    assert any("components" in f for f in g["failed"])
    assert not any("vulns" in f for f in g["failed"])


def test_vulns_collapse_to_zero_fails_alone():
    """AC: BSA-AC-200 (vector 2 of 3): vulns baseline > 0, candidate == 0 -> fail, even with components untouched."""
    base = {"components": 500, "vulns": 10}
    cand = {"components": 500, "vulns": 0}
    g = loop.gate(base, cand)
    assert g["pass"] is False
    assert any("vulns" in f for f in g["failed"])
    assert not any("components" in f for f in g["failed"])


def test_metric_present_in_baseline_but_missing_in_candidate_fails():
    """AC: BSA-AC-200 (vector 3 of 3): a rate metric the baseline measured but the candidate omits entirely is
    UNKNOWN, not a pass -- it must block acceptance as undecidable (covers the empty-candidate defect, loop.py:49)."""
    base = {"license_resolved_rate": 0.9, "citation_accuracy": 0.95}
    cand = {"license_resolved_rate": 0.9}                      # citation_accuracy never measured this pass
    g = loop.gate(base, cand)
    assert g["pass"] is False
    assert any("citation_accuracy" in u for u in g["undecidable"])


def test_metric_present_in_baseline_but_none_in_candidate_fails():
    """AC: BSA-AC-200: explicit None in the candidate is treated the same as a missing key -- still 'unknown'."""
    base = {"sbom_ref_rate": 1.0}
    cand = {"sbom_ref_rate": None}
    g = loop.gate(base, cand)
    assert g["pass"] is False
    assert any("sbom_ref_rate" in u for u in g["undecidable"])


def test_candidate_with_no_metrics_at_all_fails_against_a_measured_baseline():
    """AC: BSA-AC-200: loop.py:49's literal case -- an (almost) empty candidate vector must not look like
    'no regression' just because every per-key comparison was skipped."""
    base = {"components": 2000, "vulns": 1200, "license_resolved_rate": 0.9}
    g = loop.gate(base, {})
    assert g["pass"] is False
    assert len(g["failed"]) + len(g["undecidable"]) >= 3


def test_baseline_without_a_metric_never_blocks():
    """A metric the baseline never had (e.g. a newly added measurement) cannot regress -- it is skipped, not failed.
    Covers components/vulns, a HIGHER rate and a LOWER metric all absent from the baseline at once."""
    base = {"license_resolved_rate": 0.9}                       # no components/vulns/citation_accuracy/stage_errors here
    cand = {"license_resolved_rate": 0.9, "components": 0, "vulns": 0, "citation_accuracy": None, "stage_errors": 999}
    g = loop.gate(base, cand)
    assert g["pass"] is True
    assert g["failed"] == []


def test_component_drop_within_cap_passes_but_beyond_cap_fails():
    """AC: BSA-AC-200: a relative count drop within the documented collapse_cap (default 50%) is a normal delta;
    beyond the cap it fails even though the candidate still detected something (not a hard zero)."""
    base = {"components": 1000}
    within = loop.gate(base, {"components": 600})               # -40%, inside the 50% cap
    assert within["pass"] is True
    beyond = loop.gate(base, {"components": 400})                # -60%, beyond the 50% cap
    assert beyond["pass"] is False
    assert any("components" in f for f in beyond["failed"])



def test_gate_return_shape_stays_backwards_compatible():
    """gate() must keep returning its original keys (pass, deltas, failed, warnings, delta_limit); new keys may be
    added (e.g. collapse_cap) but nothing existing may be removed or renamed."""
    g = loop.gate({"license_resolved_rate": 0.9}, {"license_resolved_rate": 0.9})
    for key in ("pass", "deltas", "failed", "warnings", "delta_limit"):
        assert key in g


def test_existing_rate_delta_and_float_guard_semantics_are_unchanged():
    """The pre-existing 0.02 absolute delta_limit and the +1e-9 float-noise guard on a normal rate metric must be
    untouched by the collapse/unavailable-metric guards added here."""
    k = loop.HIGHER[0]
    assert loop.gate({k: 0.917}, {k: 0.897})["pass"] is True     # exactly -0.02: passes (float noise)
    assert loop.gate({k: 1.0}, {k: 0.9799})["pass"] is False      # more than -0.02: fails
