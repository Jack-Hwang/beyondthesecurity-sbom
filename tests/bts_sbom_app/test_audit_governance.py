"""Audit sampling (licence-resolution + closed triage/VEX decisions), the 6-gate governance checklist, and the
prompt re-pin evidence gate. No network; every sample is seeded and deterministic."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from bts_sbom_app import audit, govgate, licenses, pii_guard, promptreg as pr, triage

LONG = "You are a careful reviewer. Use ONLY the evidence JSON and never invent identifiers or numbers. "


# --------------------------------------------------------------------------------- BSA-AC-1180: audit.sample_size
def test_sample_size_is_cochran_finite_population_corrected_capped_and_zero_for_an_empty_population():
    """AC: BSA-AC-1180"""
    assert audit.sample_size(100, margin=0.1, confidence=0.9) == 41          # hand-computed: n0=67.6425, fpc -> 40.59 -> ceil 41
    assert audit.sample_size(0, margin=0.1, confidence=0.9) == 0             # an empty population needs no sample
    assert audit.sample_size(5, margin=0.1, confidence=0.9) == 5             # never more than the population itself
    assert audit.sample_size(-3) == 0
    # a tighter margin (more precision demanded) never needs FEWER samples than a looser one, same population
    assert audit.sample_size(1000, margin=0.05, confidence=0.9) >= audit.sample_size(1000, margin=0.1, confidence=0.9)
    with pytest.raises(ValueError):
        audit.sample_size(10, confidence=1.5)


# ------------------------------------------------------------------------- BSA-AC-1181: licenses.audit_sample (a)
def _components(n_per_source: int = 20) -> list:
    comps = []
    for i, src in enumerate(["lockfile", "deps.dev", "registry:npm"] * n_per_source):
        comps.append({"name": "pkg-%s-%d" % (src.replace(":", "_"), i), "version": "1.0.%d" % i,
                      "ecosystem": "npm", "license": "MIT", "license_source": src})
    for i in range(4):                                                        # unresolved components must never enter the queue
        comps.append({"name": "unresolved-%d" % i, "version": "1.0", "ecosystem": "npm", "license": "", "license_source": ""})
    return comps


def test_license_audit_sample_draws_at_least_10pc_min_1_per_source_deterministically_and_zero_when_unresolved():
    """AC: BSA-AC-1181"""
    comps = _components(20)
    r = licenses.audit_sample(comps, frac=0.1, seed=7)
    assert r["by_source"] == {"lockfile": 20, "deps.dev": 20, "registry:npm": 20}
    assert r["sampled"] == {"lockfile": 2, "deps.dev": 2, "registry:npm": 2}          # ceil(20*0.1) = 2 per source
    assert len(r["queue"]) == 6 and all(c["license"] for c in r["queue"])             # every sampled item is RESOLVED
    assert all(c.get("audit_reason") for c in r["queue"])
    r_again = licenses.audit_sample(comps, frac=0.1, seed=7)
    assert r_again["queue"] == r["queue"]                                            # same seed -> identical queue
    r_diff_seed = licenses.audit_sample(comps, frac=0.1, seed=99)
    assert r_diff_seed["queue"] != r["queue"]                                         # different seed -> different draw
    # a tiny source still gets its minimum of 1, never 0 while it has at least one resolved component
    one_each = [{"name": "x", "version": "1", "ecosystem": "npm", "license": "MIT", "license_source": "lockfile"}]
    assert licenses.audit_sample(one_each, frac=0.1, seed=0)["sampled"] == {"lockfile": 1}
    # a project with nothing resolved samples nothing (0 resolved -> 0 sampled, never invented)
    none_resolved = [{"name": "x", "version": "1", "ecosystem": "npm", "license": "", "license_source": ""}]
    empty = licenses.audit_sample(none_resolved, frac=0.1, seed=0)
    assert empty["by_source"] == {} and empty["sampled"] == {} and empty["queue"] == []


# -------------------------------------------------------------------------- BSA-AC-1182: triage.stratified_audit (b)
def _vulns_and_store(n: int = 40):
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    vulns, store = [], {}
    for i in range(n):
        sev = sevs[i % 4]
        vid = "CVE-2024-%04d" % i
        vulns.append({"id": vid, "package": "pkg%d" % i, "version": "1.0", "ecosystem": "PyPI", "severity": sev})
        if i % 4 in (0, 2):                                      # only CRITICAL (0) and MEDIUM (2) lanes get CLOSED decisions
            store[vid] = {"status": "accepted", "note": "reviewed and accepted risk for this release cycle", "by": "alice"}
        # HIGH (1) and LOW (3) are left undecided: their lanes have 0 CLOSED decisions
    return vulns, store


def test_closed_decisions_keeps_only_not_affected_or_accepted():
    """AC: BSA-AC-1182"""
    vulns, store = _vulns_and_store(8)
    ev = triage.evaluate(vulns, store)
    closed = triage.closed_decisions(ev)
    assert {f["triage"]["state"] for f in closed} == {"accepted"}
    assert len(closed) == 4                                        # i in (0,2,4,6) of 8 -> CRITICAL/MEDIUM only


def test_stratified_audit_draws_sample_size_per_severity_lane_deterministically_and_zero_for_an_undecided_lane():
    """AC: BSA-AC-1182"""
    vulns, store = _vulns_and_store(40)
    r = triage.stratified_audit(vulns, store, seed=3, margin=0.1, confidence=0.9)
    assert r["closed_total"] == 20 and r["by_lane"] == {"CRITICAL": 10, "MEDIUM": 10}
    expected_n = audit.sample_size(10, margin=0.1, confidence=0.9)
    assert expected_n == 9                                          # hand-computed: n0=67.64, fpc(n=10) -> 8.46 -> ceil 9
    assert r["sampled"] == {"CRITICAL": 9, "MEDIUM": 9}
    assert "HIGH" not in r["by_lane"] and "LOW" not in r["by_lane"]  # undecided lanes never entered the audit: 0, not invented
    assert len(r["queue"]) == 18 and all(f.get("audit_reason") for f in r["queue"])
    r_again = triage.stratified_audit(vulns, store, seed=3, margin=0.1, confidence=0.9)
    assert r_again["queue"] == r["queue"]                            # same seed -> identical queue
    r_diff = triage.stratified_audit(vulns, store, seed=11, margin=0.1, confidence=0.9)
    assert r_diff["queue"] != r["queue"]                             # different seed -> different draw


# --------------------------------------------------------------------------------------- BSA-AC-1183/1184: govgate
def test_govgate_reports_exactly_six_named_rows_in_fixed_order_for_any_root():
    """AC: BSA-AC-1183"""
    assert govgate.GATES == ("Spec", "AI-Review", "Security", "Compliance", "Observability", "Agent Access")
    with tempfile.TemporaryDirectory() as td:
        empty = govgate.evaluate(td)
    import bts_sbom_app.evals as evals_mod
    real = govgate.evaluate(evals_mod.repo_root())
    for result in (empty, real):
        assert len(result["rows"]) == 6
        assert tuple(r["gate"] for r in result["rows"]) == govgate.GATES
        assert all(r["status"] in ("pass", "fail") for r in result["rows"])


def test_govgate_main_exits_1_if_any_gate_fails_and_0_only_when_all_6_pass():
    """AC: BSA-AC-1184"""
    with tempfile.TemporaryDirectory() as td:
        empty = govgate.evaluate(td)
        failing = sum(1 for r in empty["rows"] if r["status"] == "fail")
        assert failing == 5 and empty["ok"] is False                 # Spec/AI-Review/Security/Compliance/Observability fail; Agent Access passes (it is not root-dependent)
        assert govgate.main(["--root", td]) == 1
    import bts_sbom_app.evals as evals_mod
    root = evals_mod.repo_root()
    real = govgate.evaluate(root)
    passing = sum(1 for r in real["rows"] if r["status"] == "pass")
    assert passing == 6 and real["ok"] is True
    assert govgate.main(["--root", root]) == 0


# --------------------------------------------------------------------------------- BSA-AC-1185/1186: promptreg C77
def _prompt_repo(tmp_path, name="repo"):
    root = tmp_path / name
    (root / "bts_sbom_app").mkdir(parents=True)
    (root / "evals").mkdir()
    (root / "bts_sbom_app" / "a.py").write_text(
        'PROMPT_VERSION = "a-v1"\nSYSTEM = ("%s"\n          "Return JSON.")\n' % LONG, encoding="utf-8")
    return str(root)


def _write_loop_history(root, entries):
    d = os.path.join(root, "evidence", "loop")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "history.json"), "w", encoding="utf-8") as fh:
        json.dump(entries, fh)


def test_update_require_loop_evidence_refuses_unless_a_fresh_loop_result_is_supplied_or_found(tmp_path):
    """AC: BSA-AC-1185"""
    root = _prompt_repo(tmp_path)
    digest_now = pr.digest(root)
    # case 1: MISSING - no evidence/loop/history.json at all -> refused
    with pytest.raises(ValueError, match="re-pin refused: no pass is recorded"):
        pr.update(root, "initial pin of the prompt", require_loop_evidence=True)
    assert pr.check(root)["pinned"] == 0                              # the refused call pinned nothing
    # case 2: MISMATCHED - a pass was recorded, but not measured on these prompts -> refused
    _write_loop_history(root, [{"pass": 1, "prompts": "0" * 12, "decision": "baseline"}])
    assert digest_now != "0" * 12
    with pytest.raises(ValueError, match="re-pin refused:.*current prompt digest is %s" % digest_now):
        pr.update(root, "initial pin of the prompt", require_loop_evidence=True)
    assert pr.check(root)["pinned"] == 0
    # case 3: FRESH (found) - the latest pass recorded exactly this prompt digest -> accepted
    _write_loop_history(root, [{"pass": 1, "prompts": "0" * 12, "decision": "baseline"}, {"pass": 2, "prompts": digest_now, "decision": "accept"}])
    done = pr.update(root, "initial pin of the prompt", require_loop_evidence=True)
    assert done["pinned"] == 1 and pr.check(root)["ok"] is True
    # FRESH (supplied) also works on a second repo with no evidence/loop directory at all, once the caller vouches directly
    root2 = _prompt_repo(tmp_path, "repo2")
    digest2 = pr.digest(root2)
    with pytest.raises(ValueError, match="supplied loop fingerprint .* does not match"):
        pr.update(root2, "initial pin of the prompt", require_loop_evidence=True, loop_fingerprint="f" * 12)
    done2 = pr.update(root2, "initial pin of the prompt", require_loop_evidence=True, loop_fingerprint=digest2)
    assert done2["pinned"] == 1 and pr.check(root2)["ok"] is True


def test_update_default_require_loop_evidence_false_keeps_every_pre_existing_caller_working(tmp_path):
    """AC: BSA-AC-1186"""
    root = _prompt_repo(tmp_path)
    # no evidence/loop directory exists anywhere under root, and require_loop_evidence is not passed at all (the
    # exact shape of the pre-existing `prompts --update --reason` CLI call and this module's own unit tests)
    assert not os.path.isdir(os.path.join(root, "evidence"))
    done = pr.update(root, "initial pin of the prompt")
    assert done["pinned"] == 1 and pr.check(root)["ok"] is True
    apath = os.path.join(root, "bts_sbom_app", "a.py")
    src = open(apath, encoding="utf-8").read()
    open(apath, "w", encoding="utf-8").write(src.replace("Return JSON.", "Return a JSON object.").replace('"a-v1"', '"a-v2"'))
    done2 = pr.update(root, "reworded the output instruction, version bumped")
    assert done2["changed"] == ["a.SYSTEM"] and pr.check(root)["ok"] is True


# ------------------------------------------------- BSA-AC-1187/1188/1189: triage.decide redacts the free-text note
def test_decide_redacts_pii_and_secret_shaped_substrings_in_the_stored_decision_and_the_vex_statement():
    """AC: BSA-AC-1187"""
    v = {"id": "CVE-2024-9999", "package": "pkgx", "version": "1.0", "ecosystem": "PyPI", "severity": "HIGH"}
    note = "contact jane.doe@example.com or call 010-1234-5678, key=AKIAABCDEFGHIJKLMNOP for access"
    store = {"CVE-2024-9999": {"status": "accepted", "note": note, "by": "alice"}}
    d = triage.decide(v, store)
    assert d is not None and d["state"] == "accepted"
    # the raw PII/secret-shaped substrings never reach the stored decision ...
    assert "jane.doe@example.com" not in d["note"] and "010-1234-5678" not in d["note"] and "AKIAABCDEFGHIJKLMNOP" not in d["note"]
    assert "[redacted:email]" in d["note"] and "[redacted:phone]" in d["note"] and "[redacted:aws-key]" in d["note"]
    # ... nor the exported VEX statement built from it (the action statement for an accepted/risk-accepted decision)
    st = triage.apply_to_statement({"status": "affected"}, d)
    assert "jane.doe@example.com" not in st["action_statement"] and "010-1234-5678" not in st["action_statement"]
    assert "AKIAABCDEFGHIJKLMNOP" not in st["action_statement"]
    assert "[redacted:email]" in st["action_statement"] and "[redacted:aws-key]" in st["action_statement"]
    # cross-check against the pii_guard module directly: this is exactly its (text, kinds) redaction of the same note
    expect_note, expect_kinds = pii_guard.redact(note)
    assert d["note"] == expect_note and set(expect_kinds) == {"email", "phone", "aws-key"}


def test_decide_leaves_a_note_with_only_a_cve_id_and_a_version_untouched():
    """AC: BSA-AC-1188"""
    v = {"id": "CVE-2024-9999", "package": "pkgx", "version": "1.0", "ecosystem": "PyPI", "severity": "HIGH"}
    note = "False positive: CVE-2024-9999 affects only version 2.3.4, not our pinned 1.0.0 build"
    store = {"CVE-2024-9999": {"status": "false-positive", "note": note, "justification": triage.JUSTIFICATIONS[0]}}
    d = triage.decide(v, store)
    assert d is not None and d["state"] == "not_affected"
    assert d["note"] == note                                   # no PII/secret shape in it -> byte-for-byte unchanged
    assert d["key"] == "CVE-2024-9999"                          # the advisory id itself is never touched either


def test_evaluate_and_apply_to_statement_redact_end_to_end_while_leaving_the_spdx_id_and_cve_id_alone():
    """AC: BSA-AC-1189"""
    note = "accepted under MIT license terms; contact security@example.com for details, CVE-2024-1111 tracked separately"
    vulns = [{"id": "CVE-2024-1111", "package": "pkgy", "version": "1.2.3", "ecosystem": "PyPI", "severity": "LOW"}]
    store = {"CVE-2024-1111": {"status": "accepted", "note": note, "by": "bob"}}
    ev = triage.evaluate(vulns, store)
    f = ev["findings"][0]
    assert f["triage"]["state"] == "accepted" and ev["counts"]["accepted"] == 1
    assert "security@example.com" not in f["triage"]["note"]
    assert "MIT" in f["triage"]["note"] and "CVE-2024-1111" in f["triage"]["note"]     # SPDX id and CVE id untouched
    st = triage.apply_to_statement({"status": "affected"}, f["triage"])
    assert "security@example.com" not in st["action_statement"]
    assert "MIT" in st["action_statement"] and "CVE-2024-1111" in st["action_statement"]
    # existing triage/VEX behaviour (justification/expiry/rejection rules) is untouched by the redaction wiring:
    # covered by the pre-existing tests in this file and in tests/bts_sbom_app/test_changes_triage.py (run alongside)
