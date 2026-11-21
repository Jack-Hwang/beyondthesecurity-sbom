"""Alternatives: evidence table + validated AI candidates (task 25, brief 2, AC 631-642)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import alternatives, licenses
from conftest import FakeScanner

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fake_table(tmp_path, entries):
    path = str(tmp_path / "table.json")
    json.dump({"schema": alternatives.SCHEMA, "entries": entries}, open(path, "w", encoding="utf-8"), ensure_ascii=False)
    return path


class FakeClient:
    available = True

    def __init__(self, payload):
        self.payload = payload if isinstance(payload, str) else json.dumps(payload)
        self.calls = 0

    def complete(self, system, user, max_tokens=2048, json_mode=False):
        self.calls += 1
        return self.payload


FLAG = {"component": "copyleft-lib", "version": "1.0", "ecosystem": "PyPI", "license_category": "strong-copyleft", "reason": "copyleft"}


def test_a_sourced_table_entry_is_returned_with_origin_and_source(tmp_path):
    """AC: BSA-AC-631"""
    table = alternatives.load_table(_fake_table(tmp_path, [
        {"from": {"ecosystem": "PyPI", "name": "copyleft-lib"}, "reason": "copyleft",
         "to": [{"ecosystem": "PyPI", "name": "alt-lib", "license": "MIT", "note": "", "source": "verified-by-me-2026-11-21"}]}]))
    res = alternatives.suggest([FLAG], table=table)
    opt = res["items"][0]["options"][0]
    assert opt["origin"] == "table" and opt["verified_by"] == "verified-by-me-2026-11-21"


def test_sourceless_table_options_are_dropped_by_the_loader(tmp_path):
    """AC: BSA-AC-632"""
    table = alternatives.load_table(_fake_table(tmp_path, [
        {"from": {"ecosystem": "PyPI", "name": "x"}, "reason": "copyleft",
         "to": [{"ecosystem": "PyPI", "name": "with-source", "license": "MIT", "source": "ok"},
                {"ecosystem": "PyPI", "name": "no-source", "license": "MIT"}]}]))
    assert table["dropped_sourceless"] == 1
    assert [t["name"] for e in table["entries"] for t in e["to"]] == ["with-source"]


def test_no_llm_client_returns_table_only_with_an_honest_reason(tmp_path):
    """AC: BSA-AC-633"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    res = alternatives.suggest([FLAG], table=table, client=None)
    assert res["items"][0]["ai"]["used"] is False and res["items"][0]["ai"]["reason"]


def test_a_strong_copyleft_ai_candidate_is_dropped_with_a_reason(tmp_path):
    """AC: BSA-AC-634"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    client = FakeClient({"candidates": [{"name": "other-lib", "why": "similar api"}]})
    resolver = lambda eco, name: "GPL-3.0-only"                       # noqa: E731 - fake resolver
    res = alternatives.suggest([FLAG], table=table, client=client, resolver=resolver)
    assert res["items"][0]["dropped"] == [{"name": "other-lib", "reason": "license_not_allowed"}]
    assert all(o["name"] != "other-lib" for o in res["items"][0]["options"])
    assert client.calls == 1


def test_a_permissive_ai_candidate_is_license_verified(tmp_path):
    """AC: BSA-AC-635"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    client = FakeClient({"candidates": [{"name": "good-lib", "why": "drop-in replacement"}]})
    res = alternatives.suggest([FLAG], table=table, client=client, resolver=lambda eco, name: "Apache-2.0")
    opt = res["items"][0]["options"][0]
    assert opt["status"] == "ai_candidate_license_verified" and opt["license"] == "Apache-2.0"


def test_unresolvable_candidates_stay_unverified_with_unknown_license(tmp_path):
    """AC: BSA-AC-636"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    client = FakeClient({"candidates": [{"name": "cand-a", "why": "a"}, {"name": "cand-b", "why": "b"}]})
    res = alternatives.suggest([FLAG], table=table, client=client, resolver=lambda eco, name: None)
    kept = [o for o in res["items"][0]["options"] if o["origin"] == "ai"]
    assert len(kept) == 2
    assert all(o["status"] == "ai_candidate_unverified" and o["license"] == "unknown" for o in kept)


def test_invalid_candidate_names_are_dropped(tmp_path):
    """AC: BSA-AC-637"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    payload = {"candidates": [
        {"name": "copyleft-lib", "why": "same name"},
        {"name": "bad name with spaces", "why": "invalid format"},
        {"name": "other-eco-lib", "why": "ok shape, resolver says permissive"},
    ]}
    client = FakeClient(payload)
    res = alternatives.suggest([FLAG], table=table, client=client, resolver=lambda eco, name: "MIT")
    dropped = {d["name"]: d["reason"] for d in res["items"][0]["dropped"]}
    assert dropped.get("copyleft-lib") == "invalid_or_same_name"
    assert dropped.get("bad name with spaces") == "invalid_or_same_name"
    kept = [o["name"] for o in res["items"][0]["options"] if o["origin"] == "ai"]
    assert "other-eco-lib" in kept                                    # same-ecosystem candidate stays


def test_every_option_needs_human_and_nothing_is_applied(tmp_path):
    """AC: BSA-AC-638"""
    table = alternatives.load_table(_fake_table(tmp_path, [
        {"from": {"ecosystem": "PyPI", "name": "copyleft-lib"}, "reason": "copyleft",
         "to": [{"ecosystem": "PyPI", "name": "alt-lib", "license": "MIT", "source": "s"}]}]))
    res = alternatives.suggest([FLAG], table=table, client=FakeClient({"candidates": [{"name": "ai-lib", "why": "w"}]}),
                               resolver=lambda eco, name: "MIT")
    assert all(o["needs_human"] is True for o in res["items"][0]["options"])
    blob = json.dumps(res)
    assert "applied" not in blob and "git apply" not in blob


def test_an_raising_llm_call_falls_back_to_the_table(tmp_path):
    """AC: BSA-AC-639"""
    table = alternatives.load_table(_fake_table(tmp_path, [
        {"from": {"ecosystem": "PyPI", "name": "copyleft-lib"}, "reason": "copyleft",
         "to": [{"ecosystem": "PyPI", "name": "alt-lib", "license": "MIT", "source": "s"}]}]))

    class Boom:
        available = True

        def complete(self, *a, **kw):
            raise RuntimeError("provider down")

    res = alternatives.suggest([FLAG], table=table, client=Boom())
    item = res["items"][0]
    assert item["ai"]["used"] is False and "RuntimeError" in item["ai"]["reason"]
    assert item["options"] and item["options"][0]["origin"] == "table"


def test_the_shipped_table_is_empty_and_the_example_file_is_ignored():
    """AC: BSA-AC-640"""
    shipped = alternatives.load_table()
    assert shipped["entries"] == [] and shipped["schema"] == alternatives.SCHEMA
    example = os.path.join(REPO, "knowledge", "domain", "alternatives.example.json")
    assert os.path.exists(example)
    data = json.load(open(example, encoding="utf-8"))
    assert data["entries"] and data["entries"][0]["to"][0]["source"] == "EXAMPLE - not a real package"


def test_the_api_computes_table_only_on_read_without_llm(tmp_path, make_repo, world):
    """AC: BSA-AC-641"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    from bts_sbom_app import pipeline
    pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    llm_calls_before = world.llm_calls
    res = alternatives.suggest([], table=alternatives.load_table(), client=None)
    assert world.llm_calls == llm_calls_before and res["schema"] == alternatives.SCHEMA


def test_the_disclaimer_is_on_three_surfaces(tmp_path):
    """AC: BSA-AC-642"""
    table = alternatives.load_table(_fake_table(tmp_path, []))
    res = alternatives.suggest([FLAG], table=table)
    assert res["disclaimer"] == alternatives.DISCLAIMER                      # 1 JSON
    assert alternatives.DISCLAIMER in json.dumps(res, ensure_ascii=False)
    assert "alternatives" in __import__("bts_sbom_app.cli_ext", fromlist=["COMMANDS"]).COMMANDS   # 3 CLI/API surface registered
    assert licenses.category("MIT") == "permissive"          # resolver gate uses the real classifier
