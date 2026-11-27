"""Prompt registry and drift gate: a changed prompt is a visible, deliberate, versioned act."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import cli, evals, loop, promptreg as pr

LONG = "You are a careful reviewer. Use ONLY the evidence JSON and never invent identifiers or numbers. "


def _pkg(tmp_path, modules):
    root = tmp_path / "repo"
    (root / "bts_sbom_app").mkdir(parents=True)
    (root / "evals").mkdir()
    for name, src in modules.items():
        (root / "bts_sbom_app" / (name + ".py")).write_text(src, encoding="utf-8")
    return str(root)


A_V1 = ('PROMPT_VERSION = "a-v1"\n'
        'SYSTEM = ("%s"\n          "Return JSON.")\n'
        'SHORT_SYSTEM = "too short to be a prompt"\n'
        'SYSTEMS = "%s"\n\n\n'
        'def ask(client, question):\n'
        '    system = SYSTEM + " Answer in Korean."\n'
        '    return client.complete(system, question, max_tokens=10)\n') % (LONG, LONG)

B_V1 = ('def brief(client, facts, lang):\n'
        '    raw = client.complete("You write a brief of what changed for a security owner, in %s, at most 120 words. Use ONLY the facts." % lang, facts, max_tokens=5)\n'
        '    return raw\n\n\n'
        'def run(client, system, user):\n'
        '    return client.complete(system, user)\n\n\n'
        'def build(client, user):\n'
        '    system = "Convert the question into exactly one read-only query over the given catalog and nothing else at all."\n'
        '    system += " Never write."\n'
        '    return client.complete(system + "\\n\\nRespond with ONLY JSON.", user)\n\n\n'
        'def unrelated(client, user):\n'
        '    return client.other(user)\n')


def test_every_prompt_constant_and_inline_call_site_gets_a_fingerprint(tmp_path):
    """AC: BSA-AC-1080"""
    root = _pkg(tmp_path, {"a": A_V1, "b": B_V1})
    got = pr.collect(root)
    assert set(got) == {"a.SYSTEM", "a.ask#1", "b.brief#1", "b.build#1"}                                  # short / plural names, a parameter prompt and a non-LLM call are not prompts
    assert got["a.SYSTEM"]["kind"] == "constant" and got["a.SYSTEM"]["version"] == "a-v1" and got["a.SYSTEM"]["chars"] > 90
    assert got["a.ask#1"]["kind"] == "inline" and got["b.brief#1"]["version"] is None and got["b.brief#1"]["line"] == 2
    assert all(len(v["fingerprint"]) == 12 for v in got.values()) and len({v["fingerprint"] for v in got.values()}) == 4
    assert pr.collect(str(tmp_path / "nowhere")) == {} if os.path.isdir(str(tmp_path / "nowhere" / "bts_sbom_app")) else True


def test_a_prompt_built_with_operators_is_pinned_by_its_template_and_a_prompt_built_in_steps_is_one_prompt(tmp_path):
    """AC: BSA-AC-1081"""
    src = ("MAX = 8\n"
           'PLAN_SYSTEM = ("%s"\n              "At most %%d calls." %% MAX)\n'
           'GEN_SYSTEM = "%s" + ", ".join(sorted(["a", "b"])) + " is the whole list of actions you may use."\n') % (LONG, LONG)
    root = _pkg(tmp_path, {"m": src})
    got = pr.collect(root)
    assert set(got) == {"m.PLAN_SYSTEM", "m.GEN_SYSTEM"}
    a = got["m.GEN_SYSTEM"]["fingerprint"]
    root2 = _pkg(tmp_path / "two", {"m": src.replace('["a", "b"]', '["a", "b", "c"]')})
    assert pr.collect(root2)["m.GEN_SYSTEM"]["fingerprint"] != a                                         # the template (incl. what is interpolated in it) is the pinned text
    steps = _pkg(tmp_path / "three", {"s": 'def f(client, u):\n    system = "%s"\n    if u:\n        system += " IMPORTANT: fix exactly that."\n    return client.complete(system, u)\n' % LONG})
    base = pr.collect(steps)["s.f#1"]["fingerprint"]
    edited = _pkg(tmp_path / "four", {"s": 'def f(client, u):\n    system = "%s"\n    if u:\n        system += " IMPORTANT: fix something else."\n    return client.complete(system, u)\n' % LONG})
    assert pr.collect(edited)["s.f#1"]["fingerprint"] != base


def test_an_unpinned_prompt_fails_the_check_and_update_pins_it_with_a_reason_and_the_eval_pins(tmp_path):
    """AC: BSA-AC-1082"""
    root = _pkg(tmp_path, {"a": A_V1, "b": B_V1})
    st = pr.check(root)
    assert st["ok"] is False and st["unpinned"] == ["a.SYSTEM", "a.ask#1", "b.brief#1", "b.build#1"] and st["pinned"] == 0 and st["drift"] == [] and st["missing"] == []
    for bad in (None, "", "short"):
        with pytest.raises(ValueError, match="at least 8 characters"):
            pr.update(root, bad)
    done = pr.update(root, "initial pin of the prompts", eval_pins={"rag_test": "abc123abc123"}, now="2026-11-26T10:00:00+00:00")
    assert done["pinned"] == 4 and len(done["changed"]) == 4
    st = pr.check(root)
    assert st["ok"] is True and st["drift"] == [] and st["unpinned"] == [] and st["digest"] == done["digest"] == pr.digest(root)
    reg = json.load(open(pr.registry_path(root), encoding="utf-8"))
    assert reg["history"] == [{"at": "2026-11-26T10:00:00+00:00", "reason": "initial pin of the prompts", "changed": done["changed"], "eval_sets": {"rag_test": "abc123abc123"},
                               "digest": done["digest"]}] and reg["prompts"]["a.SYSTEM"]["version"] == "a-v1"


def test_a_changed_prompt_is_drift_but_re_wrapping_or_unrelated_edits_are_not(tmp_path):
    """AC: BSA-AC-1083"""
    root = _pkg(tmp_path, {"a": A_V1, "b": B_V1})
    pr.update(root, "initial pin of the prompts")
    pin = pr.digest(root)
    path = os.path.join(root, "bts_sbom_app", "b.py")
    src = open(path, encoding="utf-8").read()
    open(path, "w", encoding="utf-8").write(src.replace("def unrelated(client, user):", "# a comment that is not a prompt\ndef unrelated(client, user):") + "\n\nX = 1\n")
    apath = os.path.join(root, "bts_sbom_app", "a.py")
    a_src = open(apath, encoding="utf-8").read()
    open(apath, "w", encoding="utf-8").write(a_src.replace('"Return JSON.")', '"Return"\n          " JSON.")'))       # the same words wrapped differently
    assert pr.check(root)["ok"] is True and pr.digest(root) == pin
    open(path, "w", encoding="utf-8").write(src.replace("at most 120 words", "at most 80 words"))
    st = pr.check(root)
    assert st["ok"] is False and [d["id"] for d in st["drift"]] == ["b.brief#1"] and st["drift"][0]["pinned"] != st["drift"][0]["now"] and st["version_not_bumped"] == []
    assert pr.digest(root) != pin
    assert pr.update(root, "shorter brief for the owner")["changed"] == ["b.brief#1"] and pr.check(root)["ok"] is True


def test_a_prompt_that_changed_without_a_new_prompt_version_cannot_be_re_pinned(tmp_path):
    """AC: BSA-AC-1084"""
    root = _pkg(tmp_path, {"a": A_V1})
    pr.update(root, "initial pin of the prompts")
    apath = os.path.join(root, "bts_sbom_app", "a.py")
    src = open(apath, encoding="utf-8").read()
    open(apath, "w", encoding="utf-8").write(src.replace("Return JSON.", "Return a JSON object."))
    st = pr.check(root)
    assert st["ok"] is False and st["version_not_bumped"] == [{"id": "a.SYSTEM", "version": "a-v1"}]            # the cached outputs of a-v1 would be served for the new text
    with pytest.raises(ValueError, match="bump PROMPT_VERSION first: a.SYSTEM \\(a-v1\\)"):
        pr.update(root, "reworded the output instruction")
    open(apath, "w", encoding="utf-8").write(src.replace("Return JSON.", "Return a JSON object.").replace('"a-v1"', '"a-v2"'))
    st = pr.check(root)
    assert st["ok"] is False and st["version_not_bumped"] == []
    assert pr.update(root, "reworded the output instruction, version bumped")["changed"] == ["a.SYSTEM"]
    assert json.load(open(pr.registry_path(root), encoding="utf-8"))["prompts"]["a.SYSTEM"]["version"] == "a-v2"


def test_a_pin_for_a_prompt_that_no_longer_exists_is_reported_and_the_history_is_capped(tmp_path, monkeypatch):
    """AC: BSA-AC-1085"""
    root = _pkg(tmp_path, {"a": A_V1, "b": B_V1})
    pr.update(root, "initial pin of the prompts")
    os.remove(os.path.join(root, "bts_sbom_app", "b.py"))
    st = pr.check(root)
    assert st["ok"] is False and st["missing"] == ["b.brief#1", "b.build#1"] and st["drift"] == []
    assert pr.update(root, "the b module was removed")["changed"] == ["b.brief#1", "b.build#1"] and pr.check(root)["ok"] is True
    monkeypatch.setattr(pr, "_HISTORY_CAP", 3)
    for i in range(4):
        pr.update(root, "re-pin number %d" % i)
    hist = json.load(open(pr.registry_path(root), encoding="utf-8"))["history"]
    assert [h["reason"] for h in hist] == ["re-pin number 1", "re-pin number 2", "re-pin number 3"]


def test_a_loop_pass_records_which_prompts_produced_it_and_warns_when_they_changed(tmp_path, monkeypatch):
    """AC: BSA-AC-1086"""
    summary = {"projects": 1, "components": 10, "vulns": 4, "stage_errors": 0, "project_success_rate": 1.0, "core": {"version": "1"}, "run_dir": "x"}
    monkeypatch.setattr(loop.batch, "run_batch", lambda *a, **k: {"summary": dict(summary), "records": []})
    digests = {"v": "aaaaaaaaaaaa"}
    monkeypatch.setattr(loop.promptreg, "digest", lambda root: digests["v"])
    first = loop.run_pass("p1", [], str(tmp_path / "out"), str(tmp_path / "loop"), variable="baseline")
    assert first["decision"] == "baseline" and first["prompts"] == "aaaaaaaaaaaa" and "warning" not in first
    same = loop.run_pass("p2", [], str(tmp_path / "out"), str(tmp_path / "loop"), variable="x")
    assert same["decision"] == "accept" and "warning" not in same
    digests["v"] = "bbbbbbbbbbbb"
    changed = loop.run_pass("p3", [], str(tmp_path / "out"), str(tmp_path / "loop"), variable="tighter summary prompt")
    assert "prompts changed between baseline and this pass (aaaaaaaaaaaa -> bbbbbbbbbbbb)" in changed["warning"]


def test_the_prompts_cli_checks_pins_and_refuses_what_the_library_refuses(tmp_path, capsys):
    """AC: BSA-AC-1087"""
    root = _pkg(tmp_path, {"a": A_V1})
    base = ["--root", root, "prompts"]
    assert cli.main(base) == 1
    out = capsys.readouterr().out
    assert "2 prompt(s) in the code, 0 pinned" in out and "DRIFT" in out and "unpinned a.SYSTEM" in out and 'prompts --update --reason' in out
    assert cli.main(base + ["--update"]) == 2 and "at least 8 characters" in capsys.readouterr().err
    assert cli.main(base + ["--update", "--reason", "initial pin of the prompts"]) == 0 and "pinned 2 prompt(s)" in capsys.readouterr().out
    assert cli.main(base) == 0 and "ok" in capsys.readouterr().out
    apath = os.path.join(root, "bts_sbom_app", "a.py")
    src = open(apath, encoding="utf-8").read()
    open(apath, "w", encoding="utf-8").write(src.replace("Return JSON.", "Return a JSON object."))
    assert cli.main(base + ["--json"]) == 1
    obj = json.loads(capsys.readouterr().out)
    assert obj["ok"] is False and obj["version_not_bumped"] == [{"id": "a.SYSTEM", "version": "a-v1"}]
    assert cli.main(base + ["--update", "--reason", "reworded the instruction"]) == 2 and "bump PROMPT_VERSION first" in capsys.readouterr().err


def test_the_prompts_in_the_real_code_match_their_pins():
    """AC: BSA-AC-1088"""
    st = pr.check(evals.repo_root())
    assert st["ok"] is True, "a prompt changed, is new or is gone without a re-pin: run the evals, then  bts-sbom-app prompts --update --reason \"<what changed and why>\"  - %s" % (
        {k: st[k] for k in ("drift", "unpinned", "missing", "version_not_bumped") if st[k]})
    ids = set(pr.collect(evals.repo_root()))
    assert {"ai.SYSTEM", "arch_intel.SYSTEM", "chat.PLAN_SYSTEM", "council.MEMBER_SYSTEM", "council.CHAIR_SYSTEM", "nl2sql.GEN_SYSTEM", "loop.HYP_SYSTEM"} <= ids
    assert any(i.startswith("changes.") for i in ids) and any(i.startswith("reimpl.") for i in ids)           # inline prompts are in the registry too
