"""The deployment/governance lane (C82/C59/C35/C31/C80/C28/C64): the rollback trigger is a MACHINE-EVALUATED
number (canary.evaluate names which metric broke and by how much, and a missing measurement is hold, never a
silent pass), the bench history is finally READ back as a regression gate, the rendered image can be pinned by an
immutable digest, a reviewer finding that keeps recurring is tracked until someone kills it, the human approval
checkpoints each have written decision criteria, the corpora have a datasheet that goes stale by construction,
and triage corrections surface as report-only eval candidates."""
import json
import os
import subprocess
import sys
import types

from bts_sbom_app import bench_gate, canary, datasheet, review, triage

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ------------------------------------------------------------------ C82: the rollback trigger, machine-evaluated
def test_the_rollback_trigger_is_a_decision_table_not_a_feeling():
    """AC: BSA-AC-1270"""
    caps = {"grounding_f": 0.90, "error_rate": 0.02, "p95_ms": 800}
    d, r = canary.evaluate(caps, {"grounding_f": 0.95, "error_rate": 0.01, "p95_ms": 640})
    assert d == "promote" and len(r) == 3
    d2, r2 = canary.evaluate(caps, {"grounding_f": 0.83, "error_rate": 0.01, "p95_ms": 640})
    assert d2 == "rollback" and any("grounding_f 0.83" in x and "min cap 0.9" in x for x in r2)   # WHICH metric, both numbers
    d3, r3 = canary.evaluate(caps, {"grounding_f": 0.95})                                          # a metric we could not measure
    assert d3 == "hold" and any("not a number" in x for x in r3)                                   # undecidable, never a silent pass
    d5, r5 = canary.evaluate({}, {})
    assert d5 == "hold" and "not every cap was evaluated" in r5[0]                                 # no caps at all: nothing promotes
    d6, r6 = canary.evaluate({"p95_ms": 800}, {"p95_ms": 700})
    assert d6 == "hold" and "not gated on it" in "".join(r6)                                       # a cap nobody wrote is named as missing
    d6, r6 = canary.evaluate({"p95_ms": 800}, {"p95_ms": 700})
    assert "not gated on it" in "".join(r6)                                                        # a cap nobody wrote is named as missing
    plan = canary.plan("rev-a", "rev-b", 10)
    assert "rev-a=90 rev-b=10" in plan["canary"] and "rev-a=100 rev-b=0" in plan["rollback"]
    assert all(v.startswith("az containerapp") for v in plan.values())                             # command TEXT: execution stays human


# ------------------------------------------------------------------ C59: the bench history, read back as a gate
def _bench_rec(stamp, endpoints, ok=True, directory=""):
    p = os.path.join(directory, "bench_%s.json" % stamp)
    json.dump({"bench": {"ok": ok, "endpoints": endpoints}}, open(p, "w", encoding="utf-8"))


def test_the_bench_history_gates_a_latency_regression(tmp_path):
    """AC: BSA-AC-1270"""
    d = os.path.join(str(tmp_path), "supply_chain", "bench")            # the real layout under the evidence root
    os.makedirs(d, exist_ok=True)
    _bench_rec("20261128T010000Z", {"/healthz": {"p50_ms": 10, "p95_ms": 20, "http_status": 200}}, directory=d)
    one = bench_gate.gate(str(tmp_path))
    assert one["pass"] is False and "fewer than two" in one["undecidable"]                        # no history: undecidable, not a pass
    _bench_rec("20261128T020000Z", {"/healthz": {"p50_ms": 12, "p95_ms": 24, "http_status": 200}}, directory=d)
    ok = bench_gate.gate(str(tmp_path))
    assert ok["pass"] is True and ok["endpoints_checked"] == 1
    _bench_rec("20261128T030000Z", {"/healthz": {"p50_ms": 40, "p95_ms": 90, "http_status": 200}}, directory=d)  # 4.5x regression
    bad = bench_gate.gate(str(tmp_path))
    assert bad["pass"] is False and any("p95 90.0ms regressed beyond 1.5x" in f for f in bad["findings"])
    _bench_rec("20261128T040000Z", {"/healthz": {"p50_ms": 5, "p95_ms": 9, "http_status": 500}}, directory=d)
    dead = bench_gate.gate(str(tmp_path))
    assert dead["pass"] is False and any("HTTP 500" in f and "a fast failure is still a failure" in f for f in dead["findings"])


# ------------------------------------------------------------------ C35: the immutable digest pin
def _render(tmp_path, **extra):
    env = dict(os.environ, IMAGE="reg.azurecr.io/bts-sbom-app:t1", FQDN="bts-sbom.env.koreacentral.azurecontainerapps.io",
               LLM_KEY="k", LLM_BASE="https://r.openai.azure.com", ACCESS_TOKEN="tok1234567890",
               ACR_SERVER="reg.azurecr.io", ACR_USER="u", ACR_PASSWORD="p")
    env.update({k: v for k, v in extra.items() if v is not None})
    for k, v in extra.items():
        if v is None:
            env.pop(k, None)
    out = tmp_path / "r.yaml"
    p = subprocess.run([sys.executable, "-X", "utf8", "-I", os.path.join(ROOT, "scripts", "azure_render_app.py"),
                        os.path.join(ROOT, "deploy", "azure", "containerapp.yaml"), str(out)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
    return p, out


def test_the_image_can_be_pinned_by_a_digest_and_a_bad_one_is_refused(tmp_path):
    """AC: BSA-AC-1270"""
    p, out = _render(tmp_path, IMAGE_DIGEST="sha256:" + "a" * 64)
    assert p.returncode == 0
    text = out.read_text(encoding="ascii")
    assert 'image: "reg.azurecr.io/bts-sbom-app@sha256:%s"' % ("a" * 64) in text                   # the tag is replaced by the digest
    p2, _ = _render(tmp_path, IMAGE_DIGEST="deadbeef")
    assert p2.returncode != 0 and "sha256:<64 hex>" in (p2.stderr or "")
    p3, _ = _render(tmp_path, IMAGE="reg.azurecr.io/x@sha256:" + "b" * 64, IMAGE_DIGEST="sha256:" + "a" * 64)
    assert p3.returncode != 0 and "plain repo[:tag]" in (p3.stderr or "")
    p4, out4 = _render(tmp_path)                                                                    # no digest: the tag passes unchanged
    assert p4.returncode == 0 and 'bts-sbom-app:t1"' in out4.read_text(encoding="ascii")


# ------------------------------------------------------------------ C31: reviewer-finding convergence
def test_a_recurring_reviewer_finding_is_tracked_until_it_converges(tmp_path):
    """AC: BSA-AC-1270"""
    led = str(tmp_path / "review_convergence.jsonl")
    r1 = review.convergence(led, {"verdict": "changes_requested", "findings": [{"rule": "RV-SCOPE", "detail": "file(s) changed outside the plan: x"}]})
    assert r1["appended"] == 1 and r1["escalating"] == []
    review.convergence(led, {"verdict": "changes_requested", "findings": [{"rule": "RV-SCOPE", "detail": "file(s) changed outside the plan: x"}]})
    r3 = review.convergence(led, {"verdict": "changes_requested", "findings": [{"rule": "RV-SCOPE", "detail": "file(s) changed outside the plan: x"},
                                                                              {"rule": "RV-LOCKFILE", "detail": "a lockfile was edited directly"}]})
    assert len(r3["escalating"]) == 1 and "RV-SCOPE" in r3["escalating"][0] and "RV-LOCKFILE" not in r3["escalating"][0]
    assert r3["reviews_seen"] == 3
    pipeline_src = open(os.path.join(ROOT, "bts_sbom_app", "pipeline.py"), encoding="utf-8").read()
    assert "review_convergence" in pipeline_src                                                     # wired where the review runs


# ------------------------------------------------------------------ C64: triage corrections as eval candidates
def test_triage_decisions_surface_as_report_only_eval_candidates(tmp_path):
    """AC: BSA-AC-1270"""
    store = {"CVE-2018-18074": {"status": "not_affected", "reason": "우리는 영향받는 2.19.1 버전을 사용하지 않는다 - 2.20.0으로 고정되어 있다", "by": "보안팀"},
             "GHSA-xxxx-yyyy-zzzz": {"status": "not_affected", "reason": "짧다", "by": "보안팀"},
             "PYSEC-1": {"status": "affected", "reason": "사유가 20자 이상이지만 기록자가 없다"}}
    p = tmp_path / ".triage.json"
    p.write_text(json.dumps(store, ensure_ascii=False), encoding="utf-8")
    r = triage.eval_candidates(str(p))
    assert len(r["candidates"]) == 1 and r["candidates"][0]["id"] == "CVE-2018-18074" and r["candidates"][0]["by"] == "보안팀"
    assert r["skipped"] == 2 and "deliberate human step" in r["report_only"]                       # thin/anonymous: skipped, not rows


# ------------------------------------------------------------------ C80 + C28: the written criteria and the datasheet
def test_every_human_checkpoint_has_written_criteria_and_the_datasheet_is_current():
    """AC: BSA-AC-1270"""
    crit = open(os.path.join(ROOT, "docs", "REVIEWER_CRITERIA.md"), encoding="utf-8").read()
    for row in ("patch_apply", "decision_commit", "awaiting_approval", "ir advance", "reimpl publish"):
        assert row in crit, row
    assert "기각 조건" in crit and "승인 조건" in crit
    g = datasheet.gate(ROOT)
    assert g["ok"] is True and g["findings"] == [], g["findings"]


def test_a_corpus_change_under_a_stale_datasheet_is_caught(tmp_path):
    """AC: BSA-AC-1270"""
    stale = "# Dataset Datasheet\n\n## 동기·구성\n\n- `evals/rag_golden.json` — n=999, 전형 0 / 경계 0 / 적대 0, fingerprint `x`\n\n## 수집·출처\n\n## 위생·한계\n"
    (tmp_path / "ds.md").write_text(stale, encoding="utf-8")
    r = datasheet.gate(None, str(tmp_path / "ds.md"))
    assert r["ok"] is False and any("changed under the datasheet" in f and "rag_golden.json" in f for f in r["findings"])
    assert any("regenerate" in f for f in r["findings"])
