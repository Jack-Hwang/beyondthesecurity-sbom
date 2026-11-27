"""Chat core integrity (chat-core bundle: C02 tool-call isolation, C03 citation completeness, C79 assumed
distribution labelling, C16 compiler-availability note, C38 versions object, escalation root-cause wiring,
secret-shaped answer redaction, nl2sql freshness disclosure)."""
from __future__ import annotations

import json

from bts_sbom_app import chat, evals, nl2sql, reimpl_c
from bts_sbom_app.llm import ChatClient


def _ok(content: str):
    return 200, json.dumps({"choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 5, "completion_tokens": 7}})


# ------------------------------------------------------------------ C02: one failing tool call never drops the others
def test_a_failing_tool_call_is_isolated_in_run_never_dropping_the_others(monkeypatch):
    """AC: BSA-AC-1110"""
    rec = evals.synthetic_project()
    bot = chat.Chatbot(evals.build_index(), {"demo": rec})
    calls = [{"tool": "overview", "args": {}}, {"tool": "top_vulns", "args": {}},
             {"tool": "license", "args": {}}, {"tool": "patch", "args": {}}]
    real_run_tool = chat.run_tool
    secret = r"C:\Users\Administrator\AppData\Local\Temp\super-secret-token.txt"
    positions_checked = 0
    for fail_at in range(len(calls)):
        def flaky(rec_, tool, args, *a, _fail=calls[fail_at]["tool"], **kw):
            if tool == _fail:
                raise OSError("cannot read %s" % secret)
            return real_run_tool(rec_, tool, args, *a, **kw)
        monkeypatch.setattr(chat, "run_tool", flaky)
        out = bot._run(rec, calls)
        assert len(out) == 4                                                 # 0 of 4 results dropped
        errs = [o for o in out if o.get("error")]
        others = [o for o in out if not o.get("error")]
        assert len(errs) == 1 and errs[0]["tool"] == calls[fail_at]["tool"] and errs[0]["error_type"] == "OSError"
        assert len(others) == 3 and all(o["lines"] for o in others)           # the other 3 calls answered normally
        line = errs[0]["lines"][0]
        assert secret not in line and "Traceback" not in line and "cannot read" not in line   # never the message or a path
        positions_checked += 1
    monkeypatch.setattr(chat, "run_tool", real_run_tool)
    assert positions_checked == 4                                            # verified across 4 of 4 injected failure positions


def test_ask_marks_the_turn_partial_with_one_structured_error_claim(monkeypatch):
    """AC: BSA-AC-1110"""
    rec = evals.synthetic_project()
    bot = chat.Chatbot(evals.build_index(), {"demo": rec})
    monkeypatch.setattr(chat.Chatbot, "_tools", lambda self, q, r: self._run(r, [{"tool": "overview", "args": {}}]))

    def flaky(rec_, tool, args, *a, **kw):
        raise RuntimeError("boom at C:\\secret\\path")
    monkeypatch.setattr(chat, "run_tool", flaky)

    res = bot.ask("아무 질문", project="demo")
    assert res["status"] == "partial" and res["tool_errors"] == [{"tool": "overview", "error": "RuntimeError"}]
    assert res["found"] is True                                              # the turn survives: the error IS the answer, not a crash
    assert any("Tool 'overview' failed (RuntimeError)" in c["text"] for c in res["claims"])
    assert not any("secret" in c["text"] or "boom" in c["text"] for c in res["claims"])   # never the exception message


# ------------------------------------------------------------------ C03: numeric-token citation completeness
def test_an_uncited_number_in_the_llm_answer_is_demoted_to_the_extractive_answer(world):
    """AC: BSA-AC-1111"""
    rec = evals.synthetic_project()
    bot = chat.Chatbot(evals.build_index(), {"demo": rec}, ChatClient("k"))
    quote = "CVE-2018-18074 affects requests 2.19.1, severity HIGH (CVSS 7.5), fixed in 2.20.0."
    good = {"answer": "CVE-2018-18074 affects requests 2.19.1, fixed in 2.20.0.",
            "claims": [{"text": "a", "quote": quote, "source": "project:demo:vuln_lookup:CVE-2018-18074"}]}
    bad = {"answer": "CVE-2018-18074 affects requests 2.19.1, fixed in 9.9.9.",     # 9.9.9 was never in any cited quote
           "claims": [{"text": "a", "quote": quote, "source": "project:demo:vuln_lookup:CVE-2018-18074"}]}

    cite_good = chat.check_citations(good["answer"], good["claims"])
    cite_bad = chat.check_citations(bad["answer"], bad["claims"])
    assert cite_good["ok"] is True and cite_good["numbers"] == 4
    assert cite_bad["ok"] is False and cite_bad["uncited"] == ["9.9.9"]

    world.llm_handler = lambda body: _ok(json.dumps(good))
    r1 = bot.ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)
    assert r1["answer_source"] == "exaone" and r1["citation_accuracy"] == 1.0

    world.llm_handler = lambda body: _ok(json.dumps(bad))
    r2 = bot.ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)
    assert r2["answer_source"] == "tools"                                     # demoted, exactly like a failed verify_claims gate
    assert "not grounded" in r2["llm_note"] and "9.9.9" in r2["llm_note"]


def test_a_digit_boundary_fragment_of_a_cited_number_is_not_accepted_as_cited():
    """AC: BSA-AC-1111

    Regression for a confirmed defect: the previous digit-boundary substring search treated "." and "," as valid
    token boundaries, so a short number that is merely a punctuation-delimited FRAGMENT of a larger cited number
    (a CVSS score's decimal part, or a version's last segment) was wrongly reported as cited even though that
    exact short number was never asserted by any verified quote."""
    quote = "CVE-2018-18074 affects requests 2.19.1, severity HIGH (CVSS 7.5), fixed in 2.20.0."
    claims = [{"text": "a", "quote": quote, "source": "project:demo:vuln_lookup:CVE-2018-18074"}]

    hallucinated_cvss = chat.check_citations("The CVSS score is 5.", claims)         # "5" sits inside "7.5", never asserted alone
    assert hallucinated_cvss["ok"] is False and hallucinated_cvss["uncited"] == ["5"]

    hallucinated_version = chat.check_citations("upgrade to 19 to be safe.", claims)  # "19" sits inside "2.19.1"
    assert hallucinated_version["ok"] is False and hallucinated_version["uncited"] == ["19"]

    # the original case this function was written for still holds: a number that is a substring of a larger
    # cited number, with NO punctuation boundary at all, is still rejected.
    assert chat.check_citations("2.0 only", [{"text": "a", "quote": "version 12.0 is fine", "source": "s"}])["uncited"] == ["2.0"]


# ------------------------------------------------------------------ C79: an assumed default distribution is labelled
def test_license_risks_without_a_distribution_labels_the_default_as_an_assumption():
    """AC: BSA-AC-1112"""
    rec = evals.synthetic_project()
    assumed = chat.run_tool(rec, "license_risks", {})[0]["lines"]
    explicit = chat.run_tool(rec, "license_risks", {"distribution": "saas"})[0]["lines"]
    assert any("Assumption" in x and "ASSUMED" in x and "binary" in x for x in assumed)
    assert any("for a binary distribution" in x for x in assumed)             # still names what was actually screened
    assert not any("Assumption" in x for x in explicit) and any("for a saas distribution" in x for x in explicit)


# ------------------------------------------------------------------ C16: compiler-availability note for clean-room advice
def test_license_risks_names_the_compiler_gap_for_strong_copyleft_components(monkeypatch):
    """AC: BSA-AC-1113"""
    rec = evals.synthetic_project()
    rec["components"] = rec["components"] + [{"name": "gplthing", "version": "1.0", "ecosystem": "PyPI",
                                              "license": "GPL-3.0-only", "license_category": "strong-copyleft", "vulns": 0, "files": []}]
    monkeypatch.setattr(reimpl_c, "toolchain", lambda: {"cc": None, "cxx": None, "nm": None})
    no_compiler = chat.run_tool(rec, "license_risks", {})[0]["lines"]
    assert any("Compiler-availability note" in x and "0 of 1 strong-copyleft" in x and "gplthing" in x for x in no_compiler)

    monkeypatch.setattr(reimpl_c, "toolchain", lambda: {"cc": "/usr/bin/gcc", "cxx": "/usr/bin/g++", "nm": "/usr/bin/nm"})
    with_compiler = chat.run_tool(rec, "license_risks", {})[0]["lines"]
    assert not any("Compiler-availability note" in x for x in with_compiler)
    assert any("clean-room reimplementation" in x for x in with_compiler)     # the clean-room pointer itself is unaffected


# ------------------------------------------------------------------ C38: versions object (app/model/prompt/spec)
def test_versions_object_is_populated_and_prompt_digest_tracks_a_repin(monkeypatch):
    """AC: BSA-AC-1114"""
    rec = evals.synthetic_project()
    bot = chat.Chatbot(evals.build_index(), {"demo": rec})
    res = bot.ask("아무 질문", project="demo")
    v = res["versions"]
    assert set(v) == {"app", "model", "prompt_digest", "spec"}
    assert v["app"] and v["model"] == "none (no LLM client configured)" and v["spec"] and v["prompt_digest"]

    monkeypatch.setattr(chat.promptregmod, "digest", lambda root: "digest-before")
    before = bot._versions()
    monkeypatch.setattr(chat.promptregmod, "digest", lambda root: "digest-after")
    after = bot._versions()
    assert before["prompt_digest"] == "digest-before" and after["prompt_digest"] == "digest-after"
    assert before["prompt_digest"] != after["prompt_digest"]
    assert (before["app"], before["model"], before["spec"]) == (after["app"], after["model"], after["spec"])


# ------------------------------------------------------------------ wiring (a): escalation carries the project record so
# escalation.build can copy its coverage gaps into evidence_refs.root_cause
def test_escalate_passes_the_project_record_so_root_cause_rides_a_no_progress_payload(monkeypatch):
    """AC: BSA-AC-1115"""
    rec = evals.synthetic_project()
    rec["engine"] = {"data_status": "network_failure", "status": {}}           # gaps.of(rec) now yields one gap
    bot = chat.Chatbot(evals.build_index(), {"demo": rec})
    captured = {}
    real_build = chat.escmod.build

    def spy_build(*a, **kw):
        captured["rec"] = kw.get("rec")
        return real_build(*a, **kw)

    monkeypatch.setattr(chat.escmod, "build", spy_build)
    out = bot._escalate("no_progress", "아직도 모르겠어", "demo", [], False, False, ["아직도 모르겠어"], misses=3)
    assert captured["rec"] is rec                                             # the record itself rode along, not just its name
    root_cause = out["escalation"]["evidence_refs"].get("root_cause")
    assert root_cause and any(g["code"] == "data_status:network_failure" for g in root_cause)

    # backward compatible: a kind whose trigger is neither no_progress nor policy_gap still carries no root_cause,
    # and passing rec= never breaks a human_request escalation (no tool ran, rec not even picked up by build()).
    out2 = bot._escalate("human_request", "사람 연결해줘", "demo", [], False, False, ["사람 연결해줘"])
    assert "root_cause" not in out2["escalation"]["evidence_refs"]


# ------------------------------------------------------------------ wiring (b): the assembled chat answer is redacted for
# secret-shaped kinds only - never email/phone/RRN (SBOM answers legitimately quote maintainer emails)
def test_assembled_answer_redacts_secret_shaped_kinds_but_keeps_emails_and_phones(monkeypatch):
    """AC: BSA-AC-1116"""
    secret_line = "Maintainer: pkg-owner@example.com. Leaked token: ghp_" + "a" * 36 + ". Call 010-1234-5678 for help."
    masked, kinds = chat.redact_secret_kinds(secret_line)
    assert kinds == ["github-token"]
    assert "ghp_" not in masked and "[redacted:github-token]" in masked
    assert "pkg-owner@example.com" in masked and "010-1234-5678" in masked     # not touched: not secret-shaped

    assert chat.redact_secret_kinds("no secrets here, just prose") == ("no secrets here, just prose", [])

    rec = evals.synthetic_project()
    bot = chat.Chatbot(evals.build_index(), {"demo": rec})

    def fake_tools(self, q, r):
        return [{"tool": "overview", "source": "project:demo:overview", "lines": [secret_line], "trust": "tool"}]

    monkeypatch.setattr(chat.Chatbot, "_tools", fake_tools)
    res = bot.ask("아무 질문", project="demo")
    assert "ghp_" not in res["answer"] and "[redacted:github-token]" in res["answer"]
    assert "pkg-owner@example.com" in res["answer"] and "010-1234-5678" in res["answer"]
    assert res["pii_redacted"] == ["github-token"]


# ------------------------------------------------------------------ wiring (c): the nl2sql tool result states the OSV
# snapshot's per-ecosystem freshness, additively, after the existing status/sql/row/error lines
def test_nl2sql_tool_result_appends_the_snapshot_freshness_line(monkeypatch, tmp_path):
    """AC: BSA-AC-1117"""
    db_path = str(tmp_path / "osv.db")
    open(db_path, "w", encoding="utf-8").close()           # run_tool only checks os.path.exists; answer() is stubbed below

    def fake_answer(question, db_path=None, client=None, **kw):
        return {"question": question, "status": "success", "rows": [["PyPI", 3]], "sql": "SELECT 1",
                "source": "template", "attempts": 1, "as_of": {"PyPI": "2024-11-19", "npm": None}}

    monkeypatch.setattr(nl2sql, "answer", fake_answer)
    out = chat.run_tool(None, "nl2sql", {"q": "생태계별 취약점 수"}, db_path=db_path)
    assert out[0]["lines"][-1] == "as of: PyPI=2024-11-19, npm=never imported"
    assert out[0]["lines"][0] == "status: success"                            # additive: the existing lines are unchanged

    def fake_answer_unknown(question, db_path=None, client=None, **kw):
        return {"question": question, "status": "success", "rows": [[3]], "sql": "SELECT COUNT(*) FROM vulns",
                "source": "template", "attempts": 1, "as_of": {"unknown": None}}

    monkeypatch.setattr(nl2sql, "answer", fake_answer_unknown)
    out2 = chat.run_tool(None, "nl2sql", {"q": "취약점 개수"}, db_path=db_path)
    assert out2[0]["lines"][-1] == "as of: unknown"

    def fake_answer_no_as_of(question, db_path=None, client=None, **kw):
        return {"question": question, "status": "empty", "rows": [], "sql": "SELECT 1 WHERE 0", "source": "template", "attempts": 1}

    monkeypatch.setattr(nl2sql, "answer", fake_answer_no_as_of)
    out3 = chat.run_tool(None, "nl2sql", {"q": "아무것도 없음"}, db_path=db_path)
    assert not any(ln.startswith("as of:") for ln in out3[0]["lines"])        # no as_of key at all: no line added, never guessed


# --------------------------------------------------------------------------- C87: three-way support classification

def test_classify_support_grades_three_ways_and_keeps_the_gate_binary():
    """AC: BSA-AC-1253. A mirrored-polarity sentence in the cited document promotes a claim to 'contradicted';
    absence of support stays 'unsupported' with its reason; verify_claims' binary gate is untouched."""
    from bts_sbom_app.chat import classify_support, verify_claims
    docs = {"a.md": "CVE-2024-9999 is affected in versions below 2.0. CVE-2025-1111 is not affected in all versions."}
    claims = [
        {"source": "a.md", "quote": "CVE-2024-9999 is affected in versions below 2.0.", "text": "c1"},
        {"source": "a.md", "quote": "CVE-2025-1111 is affected in all versions.", "text": "c2"},
        {"source": "missing.md", "quote": "x", "text": "c3"},
        {"source": "a.md", "quote": "never quoted anywhere", "text": "c4"},
    ]
    r = classify_support(claims, docs)
    assert r["supported"] == 1 and r["contradicted"] == 1 and r["unsupported"] == 2
    reasons = {row["state"]: row["reason"] for row in r["rows"]}
    assert "no such source" in reasons["unsupported"] or reasons["unsupported"]
    v = verify_claims(claims[:2], docs)                                # the gate: still binary, unchanged
    assert v["verified"] == 1 and v["accuracy"] == 0.5
    neg = classify_support([{"source": "a.md", "quote": "전역 설치는 없다", "text": "ko"}],
                           {"a.md": "전역 설치는 있다."})              # Korean polarity pair, mirrored exactly
    assert neg["contradicted"] == 1
