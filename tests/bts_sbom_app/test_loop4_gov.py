"""Overnight feature-loop round 4 (backlog C26·C50·C07·C71): governance evidence the records already hold but
nothing surfaced - an append-only approval ledger that records EVERY effectful attempt (a digest mismatch is
exactly what an audit exists to show), the org-overridable remediation decision table (a malformed override file
rejects the WHOLE set - a half-applied policy is a lie), the license lookup's honest block reason (circuit_open
is 'we never asked', no longer collapsed into plain None), and resolved escalations read back as a REPORT-ONLY
eval-candidate feed (a human imports them; a silent feed would smuggle the reviewer's wording into the set)."""
from __future__ import annotations

import json
import os
import tempfile
from unittest import mock

from bts_sbom_app import actions, decision, escalation, escalation_report, licenses, net, resilience


def _proj_rec():
    return {"schema": "bts-sbom.project.v1", "name": "demo",
            "components": [{"name": "a", "version": "1", "ecosystem": "pypi"}],
            "vulns": [{"id": "CVE-1", "package": "a", "version": "1", "severity": "HIGH"}]}


def test_approval_ledger_records_every_attempt_with_the_actor(tmp_path):
    """AC: BSA-AC-1257. A patch attempt on a planless record audits nothing_to_patch; a bad token audits
    digest_mismatch (with the token-supplied flag); a committed VEX decision audits committed - each row with
    the actor the embedding supplied and a timestamp, append-only."""
    ev = str(tmp_path / "ev")
    acts = actions.ChatActions(".", ev, actor="10.1.2.3")
    rec = _proj_rec() | {"source": "."}
    acts.patch_apply(rec, "bogus-token")                       # empty component list -> nothing_to_patch (audited first)
    rec2 = _proj_rec() | {"source": "."} | {"plans": [{"component": "a", "ecosystem": "pypi", "current_version": "1", "safe_version": "2", "status": "upgrade"}]}
    r = acts.patch_apply(rec2, "deadbeefdeadbeef")
    assert r["status"] == "digest_mismatch"                    # a wrong token: refused AND written down
    rows = [json.loads(l) for l in open(acts.audit_path, encoding="utf-8")]
    assert [r["outcome"] for r in rows] == ["nothing_to_patch", "digest_mismatch"]
    assert rows[0]["actor"] == "10.1.2.3" and rows[1]["actor"] == "10.1.2.3"
    assert rows[1]["token_supplied"] is True and rows[1]["digest"]
    d = {"id": "CVE-1", "package": "a", "version": "1", "status": "false-positive", "reason": "the vulnerable code is not in our execute path, verified in ticket T-1",
         "justification": "vulnerable_code_not_in_execute_path"}
    commit = acts.decision_commit(d)
    assert commit["ok"] is True
    rows = [json.loads(l) for l in open(acts.audit_path, encoding="utf-8")]
    assert rows[-1]["kind"] == "vex_decision" and rows[-1]["outcome"] == "committed" and rows[-1]["key"] == commit["key"]


def test_remediation_overrides_apply_validate_and_reject_wholly(tmp_path, monkeypatch):
    """AC: BSA-AC-1258. A documented overrides file disables rules and changes match priorities; an unknown rule
    id rejects the WHOLE file (defaults stand, status says why) - never a half-applied policy."""
    defaults = decision.remediation_policy()
    assert decision.remediation_policy_status()["overrides"] == "none"
    p = tmp_path / "ovr.json"
    p.write_text(json.dumps({"disable": ["R6"], "priority": {"R4": 5}}), encoding="utf-8")
    monkeypatch.setenv("BTS_SBOM_REMEDIATION_OVERRIDES", str(p))
    t = decision.remediation_policy()
    ids = [r.rid for r in t.rules]
    assert "R6" not in ids and "R4" in ids
    assert next(r for r in t.rules if r.rid == "R4").priority == 5
    assert decision.remediation_policy_status()["overrides"] == "applied"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"disable": ["R99"]}), encoding="utf-8")
    monkeypatch.setenv("BTS_SBOM_REMEDIATION_OVERRIDES", str(bad))
    t2 = decision.remediation_policy()
    assert [r.rid for r in t2.rules] == [r.rid for r in defaults.rules]     # the defaults stand, whole
    st = decision.remediation_policy_status()
    assert st["overrides"] == "rejected" and "malformed" in st["detail"]
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("BTS_SBOM_REMEDIATION_OVERRIDES", str(broken))
    t3 = decision.remediation_policy()
    assert [r.rid for r in t3.rules] == [r.rid for r in defaults.rules]
    assert decision.remediation_policy_status()["overrides"] == "rejected"
    monkeypatch.delenv("BTS_SBOM_REMEDIATION_OVERRIDES")
    decision.remediation_policy()
    assert decision.remediation_policy_status()["overrides"] == "none"


def test_license_lookup_names_why_it_never_asked(monkeypatch, tmp_path):
    """AC: BSA-AC-1259. When the breaker short-circuits a source the lookup names the reason (circuit_open) -
    per-source meta on the lookup function AND lookup_blocked_reasons in resolve()'s stats - instead of
    collapsing 'we never asked' into plain None."""
    from bts_sbom_app import net as netmod

    def fake_oc(url, **kw):
        return resilience.Outcome(resilience.ACCESS_FAILURE, None, None, "circuit_open", 0)
    monkeypatch.setattr(netmod, "http_json_oc", fake_oc)
    ticks = {"n": 0}

    def fake_failures() -> int:                    # a counter that INCREASES between look()'s two reads (the real
        ticks["n"] += 1                            # one is a thread-local fed by the fetch path we bypassed)
        return ticks["n"]
    monkeypatch.setattr(netmod, "thread_access_failures", fake_failures)
    meta: dict = {}
    blocked = licenses._depsdev("pypi", "requests", "2.31.0", meta)
    assert blocked is None and meta["deps.dev"]["reason"] == "circuit_open"
    comps = [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}]
    stats = licenses.resolve(comps, str(tmp_path), online=True, cache_dir=str(tmp_path / "cache"),
                             sources=("deps.dev", "registry"), workers=1)
    assert stats.get("lookup_unavailable", 0) >= 1
    assert stats.get("lookup_blocked_reasons", {}).get("circuit_open", 0) >= 1
    assert not comps[0].get("license")                         # still honest: nothing learned, nothing invented


def test_eval_candidates_feed_is_report_only_and_filters_thin_notes(tmp_path):
    """AC: BSA-AC-1260. A resolved escalation with a real note becomes one candidate row (redacted question
    included); a noteless resolve is counted as skipped, never a row; the feed never imports itself."""
    tmp = str(tmp_path)
    p = escalation.build("no_progress", "세 번 물었는데 답이 없다", "proj")
    escalation.record(tmp, p, now="2026-11-28T01:00:00Z")
    escalation.resolve(tmp, p["id"], "짧은 메모", "rev", now="2026-11-28T02:00:00Z")   # passes resolve's own 5-char floor, under the feed's 10
    p2 = escalation.build("no_progress", "CVE-2024-1234이 왜 위험하다고 나오지", "proj")
    escalation.record(tmp, p2, now="2026-11-28T01:10:00Z")
    escalation.resolve(tmp, p2["id"], "CVE-2024-1234은 이 제품의 코드 경로에 없음을 확인해 제외했다", "rev",
                       now="2026-11-28T03:00:00Z")
    r = escalation_report.eval_candidates(tmp)
    assert r["count"] == 1 and r["skipped"] == 1
    row = r["candidates"][0]
    assert row["id"] == p2["id"] and row["question"] == p2["triggering_question"]
    assert "human" in r["note"]
