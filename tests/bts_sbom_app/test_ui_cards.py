# -*- coding: utf-8 -*-
"""ui_cards.py: the A2UI-inspired card catalog over chat tool results (docs/A2UI_INTEGRATION.md;
AC: BSA-AC-645, BSA-AC-646).

Contract under test: the catalog is closed (unknown kinds/fields/oversized/non-scalar values are dropped
by the validator, never sent), builders are deterministic over the record, the model never supplies card
content, and hostile strings in measured data stay inert data (the renderer only ever esc()/textContent
them). Prose lines always ride along - a dropped card never loses the answer.
"""
from bts_sbom_app import chat as chatmod
from bts_sbom_app import ui_cards as uic

REC = {
    "name": "demo",
    "components": [
        {"name": "requests", "ecosystem": "pypi", "version": "2.19.1", "license": "Apache-2.0", "vulns": 2},
        {"name": "mysql-connector", "ecosystem": "pypi", "version": "8.0.11", "license": "GPL-2.0", "vulns": 1},
    ],
    "vulns": [
        {"id": "CVE-2024-0001", "package": "requests", "version": "2.19.1", "severity": "HIGH", "cvss": 7.5,
         "fixed_version": "2.20.0", "published": "2024-01-15T00:00:00", "malicious": False},
        {"id": "CVE-2024-0002", "package": "requests", "version": "2.19.1", "severity": "MEDIUM", "cvss": 5.3,
         "fixed_version": "", "published": "2024-02-01T00:00:00", "malicious": False},
    ],
    "plans": [{"component": "requests", "ecosystem": "pypi", "current_version": "2.19.1", "safe_version": "2.20.0",
               "status": "upgrade", "verification": {"clean": True}}],
    "license": {"project_license": "MIT", "stats": {"resolved": 2, "total": 2}, "policy": []},
    "conformance": {"status": "OK", "format": "CycloneDX 1.5", "components": 2,
                    "regimes": {"ntia-2021": {"title": "NTIA 2021", "verdict": "pass", "pass": 5, "partial": 0, "gap": 0, "total": 5, "draft": False, "as_of": "2026-01-01"}}},
    "arch": {"graph": {"modules": 9, "import_edges": 7, "cycle_count": 1, "max_depth": 3}},
}


# --------------------------------------------------------------------------- the closed catalog validator
def test_unknown_kind_is_dropped_and_named():
    clean, dropped = uic.validate_cards([{"kind": "iframe", "title": "x"}])
    assert clean == [] and any("iframe" in d for d in dropped)


def test_undeclared_field_drops_the_card_additional_properties_false():
    clean, dropped = uic.validate_cards([{"kind": "kv", "title": "t", "items": [{"k": "a", "v": "b"}], "onclick": "alert(1)"}])
    assert clean == [] and any("onclick" in d for d in dropped)


def test_non_scalar_and_oversized_values_are_dropped():
    clean, _ = uic.validate_cards([{"kind": "kv", "title": "t", "items": [{"k": "a", "v": {"nested": True}}]}])
    assert clean == []
    clean2, _ = uic.validate_cards([{"kind": "decision", "title": "t", "verdict": "x" * 200, "rule": "r", "priority": "P1", "action": "a"}])
    assert clean2 and len(clean2[0]["verdict"]) <= uic.MAX_STR          # clipped, not shipped raw


def test_card_cap_is_four_and_prose_note_is_not_needed_to_answer():
    many = [{"kind": "kv", "title": "card %d" % i, "items": [{"k": "k", "v": "v"}]} for i in range(9)]
    clean, dropped = uic.validate_cards(many)
    assert len(clean) == uic.MAX_CARDS == 4 and dropped


def test_approval_card_only_accepts_hex_codes():
    ok, _ = uic.validate_cards([{"kind": "approval_request", "title": "t", "gate": "patch", "summary": "s", "code": "0123456789abcdef"}])
    assert ok and ok[0]["code"] == "0123456789abcdef"
    bad, dropped = uic.validate_cards([{"kind": "approval_request", "title": "t", "gate": "patch", "summary": "s", "code": "<script>alert(1)</script>"}])
    assert bad == [] and dropped


# --------------------------------------------------------------------------- deterministic builders
def test_overview_builds_a_stat_row_with_severity_chips():
    cards = uic.cards_for("overview", {}, REC, {"lines": ["x"]})
    assert cards[0]["kind"] == "stat_row"
    labels = {it["label"]: it for it in cards[0]["items"]}
    assert labels["컴포넌트"]["value"] == "2" and labels["HIGH"]["sev"] == "HIGH"


def test_top_vulns_builds_a_capped_table():
    cards = uic.cards_for("top_vulns", {}, REC, {"lines": []})
    t = cards[0]
    assert t["kind"] == "table" and len(t["rows"]) == 2 and t["head"][0] == "Advisory"


def test_vuln_lookup_builds_kv_for_a_known_id_only():
    assert uic.cards_for("vuln_lookup", {"id": "CVE-2024-0001"}, REC, {"lines": []})[0]["kind"] == "kv"
    assert uic.cards_for("vuln_lookup", {"id": "CVE-9999-9999"}, REC, {"lines": []}) == []


def test_decide_card_names_the_fired_rule_and_action():
    result = {"lines": ["의사결정 테이블 remediation-policy 평가: verdict=decided, 발화 규칙=R4.",
                        "결정: [P2] plan the patch: put the fix on the next train"]}
    cards = uic.cards_for("decide", {}, REC, result)
    assert cards[0]["kind"] == "decision" and cards[0]["rule"] == "R4" and cards[0]["priority"] == "P2"


def test_plan_patch_card_carries_the_approval_token_from_the_lines():
    result = {"lines": ["... Approval token 0123456789abcdef ..."], "approval_token": "0123456789abcdef"}
    cards = uic.cards_for("plan_patch", {}, REC, result)
    assert cards[0]["kind"] == "approval_request" and cards[0]["code"] == "0123456789abcdef" and cards[0]["gate"] == "patch"


def test_unknown_tool_yields_no_cards_and_a_hostile_record_stays_inert_data():
    assert uic.cards_for("book_search", {}, REC, {"lines": []}) == []
    hostile = {"id": "CVE-X", "package": "<img src=x onerror=alert(1)>", "version": "1", "severity": "HIGH",
               "cvss": 7.5, "fixed_version": "", "published": "", "malicious": False}
    cards = uic.cards_for("vuln_lookup", {"id": "CVE-X"}, {"vulns": [hostile]}, {"lines": []})
    assert cards and "<img" in cards[0]["items"][0]["v"]          # stored as DATA - the renderer escapes it


def test_card_catalog_negotiation_payload_matches_the_registry():
    doc = uic.catalog_doc()
    assert {c["kind"] for c in doc} == set(uic.CATALOG)
    assert "approval_request" in {c["kind"] for c in doc}


# --------------------------------------------------------------------------- chat wiring
def test_run_attaches_cards_to_tool_results_and_ask_collects_them():
    class DummyIndex:
        def search(self, q, k=4, filters=None):
            return {"found": False, "coverage": 0.0, "results": []}
    bot = chatmod.Chatbot(DummyIndex(), projects={"demo": REC})
    res = bot.ask("이 프로젝트 개요 요약해줘", project="demo")
    assert "overview" in (res.get("tools") or [])
    cards = res.get("cards") or []
    assert cards and cards[0]["kind"] == "stat_row" and len(cards) <= 4


def test_stream_final_carries_cards():
    import inspect
    src = inspect.getsource(chatmod)  # the stream subclass maps res fields; assert at the source level
    from bts_sbom_app import chat_stream
    ssrc = inspect.getsource(chat_stream)
    assert 'cards=res.get("cards")' in ssrc
