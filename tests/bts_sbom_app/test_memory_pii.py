"""Conversation case facts, escalation root-cause evidence, PII/secret redaction and the quality consistency gate.

Four features from the memory-pii bundle:
  * conversation.CaseFacts - case identifiers held outside the 3-turn deque (AC-1120, AC-1121);
  * escalation.build copying gaps.of(rec) into evidence_refs['root_cause'] (AC-1122);
  * pii_guard.redact masking PII/secret shapes while leaving the product's own id vocabulary alone (AC-1123),
    applied inside escalation.record/resolve so an escalation log never carries PII (AC-1124);
  * quality.consistency, the 6th TOP10 metric, gated without changing the existing 5-gate report shape (AC-1125).
"""
from __future__ import annotations

import copy

from bts_sbom_app import escalation as esc
from bts_sbom_app import conversation, evals, gaps, pii_guard, quality

# ---------------------------------------------------------------------------------------------------- AC-1120/1121
#: (turn-1 text naming one identifier, the >3-turns-later follow-up, the identifier that must survive in the merge)
FOLLOWUP_SCENARIOS = [
    ("CVE-2024-10001 있어?", "그 취약점 패치 있어?", "CVE-2024-10001"),
    ("GHSA-abcd-1234-efgh 확인해줘", "그 취약점은 심각해?", "GHSA-ABCD-1234-EFGH"),
    ("PYSEC-2024-77 패치있어?", "그 취약점 심각도는?", "PYSEC-2024-77"),
    ("RUSTSEC-2024-1 영향있어?", "그 취약점 확인해줘", "RUSTSEC-2024-1"),
    ("GO-2024-1234 있어?", "그 취약점 패치됐어?", "GO-2024-1234"),
    ("lodash@4.17.15 취약점 있어?", "그 컴포넌트 버전 패치됐어?", "lodash@4.17.15"),
    ("flask@1.0 영향 있어?", "그 버전 문제 있어?", "flask@1.0"),
    ("MIT 라이선스 괜찮아?", "그 라이선스 의무사항 있어?", "MIT"),
    ("Apache-2.0 라이선스 조건은?", "그 라이선스는 카피레프트야?", "Apache-2.0"),
    ("leftpad 알아?", "그 패키지 위험해?", "leftpad"),
]
_FILLER = ["오늘 날씨 어때", "점심 메뉴 추천해줘", "내일 일정 확인해줘"]


def test_case_facts_resolve_an_identifier_mentioned_more_than_3_turns_earlier():
    """AC: BSA-AC-1120"""
    resolved = 0
    for first_q, followup_q, expect in FOLLOWUP_SCENARIOS:
        mem = conversation.ConversationMemory()
        mem.record(first_q, [], True, "demo")
        for f in _FILLER:
            mem.record(f, [], True, "demo")
        assert len(mem.turns) == conversation.MAX_TURNS                      # the window is still bounded at 3
        assert first_q not in [t["question"] for t in mem.turns]             # turn 1 really did fall out of it
        q, is_followup = conversation.resolve_followup(followup_q, mem)
        if is_followup and expect in q:
            resolved += 1
    assert resolved == len(FOLLOWUP_SCENARIOS) == 10                         # 10 of 10 (>= the 9-of-10 floor)
    # 0 regressions: a fresh/plain/full-question call is unchanged by the case-facts addition
    mem = conversation.ConversationMemory()
    q, f = conversation.resolve_followup("그중 HIGH만 보여줘", mem)
    assert f is False and q == "그중 HIGH만 보여줘"
    plain, fp = conversation.resolve_followup("requests 라이선스 알려줘", mem)
    assert fp is False and plain == "requests 라이선스 알려줘"


def test_case_facts_logs_a_conflicting_later_value_with_both_values_and_turn_numbers():
    """AC: BSA-AC-1121"""
    mem = conversation.ConversationMemory()
    mem.record("lodash@4.17.15 취약점 있어?", [], True, "demo")   # turn 1: component fact recorded
    mem.record("오늘 날씨 어때", [], True, "demo")                 # turn 2: nothing extracted
    mem.record("lodash@4.17.21 패치됐어?", [], True, "demo")      # turn 3: SAME component, a DIFFERENT version
    mem.record("leftpad 패키지도 확인해줘", [], True, "demo")      # turn 4: first bare entity, no conflict yet
    mem.record("requests 도 확인해줘", [], True, "demo")          # turn 5: a DIFFERENT bare entity

    assert len(mem.case_facts.conflicts) == 2                    # 2 of 2 conflicting-key scenarios recorded
    by_key = {c["key"]: c for c in mem.case_facts.conflicts}
    comp = by_key["component:lodash"]
    assert comp["old_value"] == "lodash@4.17.15" and comp["new_value"] == "lodash@4.17.21"
    assert comp["old_turn"] == 1 and comp["new_turn"] == 3
    ent = by_key["entity"]
    assert ent["old_value"] == "leftpad" and ent["new_value"] == "requests"
    assert ent["old_turn"] == 4 and ent["new_turn"] == 5
    # the newer value is what a follow-up resolves to - nothing is lost, but the current fact is the current one
    assert mem.case_facts.get("component:lodash")["value"] == "lodash@4.17.21"
    assert mem.case_facts.get("entity")["value"] == "requests"


# ---------------------------------------------------------------------------------------------------------- AC-1126
#: natural sentences that merely CONTAIN an email - none of them is a component@version mention
EMAIL_ONLY_TEXTS = [
    "please email me at jane.doe@example.com thanks",
    "my contact is bob.lee@example.org for this",
    "send it to user2@sub.example.io when ready",
    "reach me at a.b.c@example.net anytime",
    "here is my address contact@example.com ok",
]
GENUINE_COMPONENT_VERSIONS = ["lodash@4.17.15", "flask@1.0", "requests@2.31.0", "django@4.2", "numpy@1.26.0"]


def test_case_facts_component_regex_never_conflates_an_email_with_a_component_at_version():
    """AC: BSA-AC-1126"""
    no_false_component = 0
    for text in EMAIL_ONLY_TEXTS:
        facts = conversation._extract_facts(text)
        if not any(kind == "component" for kind, _key, _value in facts):
            no_false_component += 1
    assert no_false_component == len(EMAIL_ONLY_TEXTS) == 5           # 5 of 5 email-only turns recorded 0 component facts

    genuine_ok = 0
    for pv in GENUINE_COMPONENT_VERSIONS:
        facts = conversation._extract_facts("%s 취약점 있어?" % pv)
        if ("component", "component:" + pv.split("@")[0].lower(), pv) in facts:
            genuine_ok += 1
    assert genuine_ok == len(GENUINE_COMPONENT_VERSIONS) == 5         # 5 of 5 genuine component@version turns still extracted

    # end-to-end: an email-containing turn in between no longer shadows the earlier, genuinely-relevant component fact
    mem = conversation.ConversationMemory()
    mem.record("lodash@4.17.15 취약점 있어?", [], True, "demo")        # turn 1: real component fact
    mem.record("제 이메일은 jane.doe@example.com 입니다", [], True, "demo")  # turn 2: unrelated email mention
    mem.record("오늘 날씨 어때", [], True, "demo")                      # turn 3: filler
    q, is_followup = conversation.resolve_followup("그 컴포넌트 버전 패치됐어?", mem)
    assert is_followup and "lodash@4.17.15" in q and "example.com" not in q
    assert mem.case_facts.latest("component")["value"] == "lodash@4.17.15"


# ---------------------------------------------------------------------------------------------------------- AC-1127
#: SPDX ids in licenses.CATEGORY that double as ordinary English words / tool names - none of these sentences is about licensing
LICENSE_LOOKALIKE_TEXTS = [
    "please return this in JSON format",
    "이거 curl 명령어로 테스트해봐",
    "use Ruby for this script",
    "X11 forwarding works now",
    "install PostgreSQL please",
    "check the MS-PL docs",
]
LICENSE_CONTEXT_TEXTS = [("MIT 라이선스 괜찮아?", "MIT"), ("Apache-2.0 license terms?", "Apache-2.0")]


def test_case_facts_license_fact_requires_a_license_context_keyword_in_the_same_turn():
    """AC: BSA-AC-1127"""
    no_false_license = 0
    for text in LICENSE_LOOKALIKE_TEXTS:
        facts = conversation._extract_facts(text)
        if not any(kind == "license" for kind, _key, _value in facts):
            no_false_license += 1
    assert no_false_license == len(LICENSE_LOOKALIKE_TEXTS) == 6      # 6 of 6 ordinary-word turns recorded 0 license facts

    genuine_ok = 0
    for text, spdx in LICENSE_CONTEXT_TEXTS:
        facts = conversation._extract_facts(text)
        if ("license", "license:" + spdx, spdx) in facts:
            genuine_ok += 1
    assert genuine_ok == len(LICENSE_CONTEXT_TEXTS) == 2               # 2 of 2 genuine license-context turns still extracted

    # end-to-end: an unrelated "JSON format" turn no longer shadows the earlier, genuinely-discussed MIT license fact
    mem = conversation.ConversationMemory()
    mem.record("MIT 라이선스 괜찮아?", [], True, "demo")                 # turn 1: real license fact
    mem.record("이 결과 JSON 포맷으로 출력해줘", [], True, "demo")         # turn 2: unrelated, no license keyword
    mem.record("오늘 날씨 어때", [], True, "demo")                        # turn 3: filler
    q, is_followup = conversation.resolve_followup("그 라이선스 의무사항 또 있어?", mem)
    assert is_followup and "MIT" in q and "JSON" not in q
    assert mem.case_facts.latest("license")["value"] == "MIT"


# ---------------------------------------------------------------------------------------------------------- AC-1128
def test_case_facts_facts_and_conflicts_are_bounded_with_least_recently_seen_eviction():
    """AC: BSA-AC-1128"""
    cf = conversation.CaseFacts()
    for i in range(600):
        cf.update("CVE-2024-%05d 있어?" % i, i + 1)
    assert len(cf.facts) == conversation.MAX_CASE_FACTS == 500         # bounded at exactly MAX_CASE_FACTS
    assert "advisory:CVE-2024-00000" not in cf.facts                   # the oldest (turn 1) was evicted first
    assert "advisory:CVE-2024-00599" in cf.facts                       # the newest (turn 600) survives
    assert min(f["turn"] for f in cf.facts.values()) == 101            # the 100 oldest turns were evicted

    cf2 = conversation.CaseFacts()
    for i in range(250):
        cf2.update("lodash@%d.0.0 ok?" % i, i + 1)                     # same key every time -> 249 real conflicts
    assert len(cf2.conflicts) == conversation.MAX_CASE_CONFLICTS == 200  # bounded at exactly MAX_CASE_CONFLICTS
    assert cf2.conflicts[0]["new_turn"] > 1                             # the oldest conflict record was dropped first

    # the single-tenant/process-wide sharing limitation is stated honestly, not silently assumed
    assert "single-tenant" in conversation.CaseFacts.__doc__.lower() or "single-tenant" in (conversation.CaseFacts.__doc__ or "")
    assert "process-wide" in conversation.CaseFacts.__doc__


# ---------------------------------------------------------------------------------------------------------- AC-1129
def test_case_facts_a_case_only_difference_is_not_logged_as_a_false_conflict():
    """AC: BSA-AC-1129"""
    cf = conversation.CaseFacts()
    cf.update("Lodash@4.17.15 ok?", 1)
    cf.update("lodash@4.17.15 ok?", 2)                                  # same component, same version, different case only
    assert cf.conflicts == []                                           # 0 false conflicts logged
    assert cf.facts["component:lodash"]["value"] == "lodash@4.17.15"    # newest spelling is still what is stored

    cf2 = conversation.CaseFacts()
    cf2.update("MIT 라이선스 괜찮아?", 1)
    cf2.update("mit 라이선스 괜찮아?", 2)                                 # same license, case only
    assert cf2.conflicts == []

    # a genuine value change is still recorded as a real conflict regardless of letter case
    cf3 = conversation.CaseFacts()
    cf3.update("Lodash@4.17.15 ok?", 1)
    cf3.update("LODASH@4.17.21 ok?", 2)                                  # a real version change, different case
    assert len(cf3.conflicts) == 1
    assert cf3.conflicts[0]["old_value"] == "Lodash@4.17.15" and cf3.conflicts[0]["new_value"] == "LODASH@4.17.21"


# ---------------------------------------------------------------------------------------------------------- AC-1122
def _project_rec(**engine_overrides):
    rec = copy.deepcopy(evals.synthetic_project())
    rec["engine"] = {"core": "0", "sources": [], "unsupported": [],
                      "status": {"mode": "online", "unqueried": 0, "version_unresolved": 0, "network_fallback_offline": 0},
                      "data_status": "complete", "vulnerability_presence": "found", "notes": []}
    for k, v in engine_overrides.items():
        if k == "status":
            rec["engine"]["status"].update(v)
        else:
            rec["engine"][k] = v
    return rec


def test_escalation_build_copies_gaps_into_root_cause_for_no_progress_and_policy_gap_kinds():
    """AC: BSA-AC-1122"""
    partial = _project_rec(status={"mode": "offline"})
    g = gaps.of(partial)
    assert g                                                      # sanity: this record really is partial
    enriched = 0
    for kind in ("no_progress", "policy_gap:legal"):
        p = esc.build(kind, "아무 질문", "demo", [], rec=partial, misses=3 if kind == "no_progress" else 0)
        if p["evidence_refs"].get("root_cause") == g:              # copied verbatim - 0 invented entries
            enriched += 1
    assert enriched == 2                                           # 2 of 2 kinds enriched

    clean = _project_rec()
    assert gaps.of(clean) == []
    p2 = esc.build("no_progress", "아무 질문", "demo", [], rec=clean, misses=3)
    assert "root_cause" not in p2["evidence_refs"]                  # 1 of 1 empty-gap case: the key is OMITTED

    # human_request is neither no_progress nor policy_gap: root_cause is never added even when rec has gaps
    p3 = esc.build("human_request", "담당자 연결해줘", "demo", [], rec=partial)
    assert "root_cause" not in p3["evidence_refs"]
    # backward compatible: every existing call site (no rec= kwarg at all) is unaffected
    p4 = esc.build("no_progress", "아무 질문", "demo", [], misses=3)
    assert "root_cause" not in p4["evidence_refs"] and esc.validate(p4) == []


# ---------------------------------------------------------------------------------------------------------- AC-1123
#: (kind, text containing it, the literal secret substring that must not survive redaction)
PII_SHAPES = [
    ("email", "contact jane.doe@example.com now", "jane.doe@example.com"),
    ("phone", "call 010-1234-5678 now", "010-1234-5678"),
    ("rrn", "주민번호 901231-1234567 확인", "901231-1234567"),
    ("aws-key", "key AKIAABCDEFGHIJ123456 leaked", "AKIAABCDEFGHIJ123456"),
    ("github-token", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 leaked", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("bearer-token", "Authorization: Bearer abcdef1234567890xyz", "abcdef1234567890xyz"),
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJBAK"),
    ("secret-assignment", "api_key=sk_live_ABCDEFGHIJ1234567890", "sk_live_ABCDEFGHIJ1234567890"),
]
#: advisory ids, SPDX ids, versions and an ordinary number - none of this module's own vocabulary is ever touched
NON_PII_TOKENS = ["CVE-2024-12345", "GHSA-abcd-1234-efgh", "Apache-2.0", "GPL-3.0-or-later", "1.2.3", "42"]


def test_pii_guard_masks_every_seeded_shape_and_never_touches_the_products_own_ids():
    """AC: BSA-AC-1123"""
    masked_count = 0
    for kind, text, needle in PII_SHAPES:
        masked, kinds = pii_guard.redact(text)
        if kind in kinds and ("[redacted:%s]" % kind) in masked and needle not in masked:
            masked_count += 1
    assert masked_count == len(PII_SHAPES) == 8                   # 8 of 8 seeded PII/secret shapes caught

    untouched = 0
    for tok in NON_PII_TOKENS:
        text = "the recorded value is %s in this record" % tok
        masked, kinds = pii_guard.redact(text)
        if masked == text and kinds == []:
            untouched += 1
    assert untouched == len(NON_PII_TOKENS) == 6                  # 0 of 6 non-PII tokens altered
    assert pii_guard.redact("")[0] == "" and pii_guard.redact(None)[0] == ""


# ---------------------------------------------------------------------------------------------------------- AC-1124
_EMAILS = ["alice.kim@example.com", "bob.lee@example.org", "carol.park@example.net", "dave.choi@example.io", "erin.jung@example.co"]
_PHONES = ["010-1111-2222", "010-3333-4444", "02-555-6666", "010-7777-8888", "031-999-0000"]
_RRNS = ["900101-1234567", "850505-2345678", "720909-1456789", "991231-4567890", "650630-1987654"]
_TOKENS = ["ghp_abcdefghijklmnopqrstuvwxyz1111111111", "ghp_abcdefghijklmnopqrstuvwxyz2222222222",
           "ghp_abcdefghijklmnopqrstuvwxyz3333333333", "ghp_abcdefghijklmnopqrstuvwxyz4444444444",
           "ghp_abcdefghijklmnopqrstuvwxyz5555555555"]
SEEDED_SECRETS = _EMAILS + _PHONES + _RRNS + _TOKENS
assert len(SEEDED_SECRETS) == 20


def test_escalation_record_and_resolve_redact_pii_before_it_reaches_the_log(tmp_path):
    """AC: BSA-AC-1124"""
    ev = str(tmp_path)
    corpus = (["담당자 이메일로 보내주세요: %s" % e for e in _EMAILS]
              + ["전화번호로 연락 주세요: %s" % p for p in _PHONES]
              + ["주민번호 확인 부탁드립니다: %s" % r for r in _RRNS]
              + ["leaked credential found: %s" % t for t in _TOKENS])
    assert len(corpus) == 20
    last_id = None
    for i, text in enumerate(corpus):
        payload = esc.build("human_request", text, "demo-%d" % i, [])
        recorded = esc.record(ev, payload)
        assert recorded["logged"] is True
        last_id = recorded["id"]

    raw = open(esc.log_path(ev), encoding="utf-8").read()
    leaked = [s for s in SEEDED_SECRETS if s in raw]
    assert leaked == [] and len(SEEDED_SECRETS) == 20              # 0 of 20 seeded PII substrings recoverable

    # the reviewer's resolution note goes through the same guard
    note = "called the user at 010-2222-3333 and emailed zzz-contact@example.com to confirm"
    done = esc.resolve(ev, last_id, note, "reviewer-one")
    assert "010-2222-3333" not in done["resolution"]["note"] and "zzz-contact@example.com" not in done["resolution"]["note"]
    assert done["resolution"]["note"].count("[redacted:") == 2
    raw2 = open(esc.log_path(ev), encoding="utf-8").read()
    assert "010-2222-3333" not in raw2 and "zzz-contact@example.com" not in raw2


def test_escalation_id_distinguishes_questions_that_differ_only_in_a_redacted_pii_span(tmp_path):
    """AC: BSA-AC-1124"""
    ev = str(tmp_path)
    # two DIFFERENT people's phone numbers redact to the byte-identical text - the id must still tell them apart
    q1 = "phone is 010-1111-2222 please connect me to a human"
    q2 = "phone is 010-9999-8888 please connect me to a human"
    p1 = esc.build("human_request", q1, "demo", [])
    p2 = esc.build("human_request", q2, "demo", [])
    assert p1["triggering_question"] == p2["triggering_question"]      # redacted text IS identical (both [redacted:phone])
    assert p1["id"] != p2["id"]                                        # but the ids are NOT - the 8-hex id is not reversible
    r1 = esc.record(ev, p1)
    r2 = esc.record(ev, p2)
    assert r1["logged"] is True and r1["duplicate"] is False
    assert r2["logged"] is True and r2["duplicate"] is False            # 0 silently dropped as a false duplicate
    raw = open(esc.log_path(ev), encoding="utf-8").read()
    assert "010-1111-2222" not in raw and "010-9999-8888" not in raw   # still fully redacted in the log

    # a LITERAL repeat of the same original question still dedupes as before (id is stable for identical input)
    p3 = esc.build("human_request", q1, "demo", [])
    assert p3["id"] == p1["id"]
    r3 = esc.record(ev, p3)
    assert r3["logged"] is False and r3["duplicate"] is True


# ---------------------------------------------------------------------------------------------------------- AC-1125
def test_consistency_flags_opposite_status_claims_without_changing_the_locked_5_gate_shape():
    """AC: BSA-AC-1125"""
    ok_claims = [{"text": "CVE-2024-1234 patch available for requests"}, {"text": "MIT is permissive"}]
    bad_claims = [{"text": "CVE-2024-1234 affected this project"}, {"text": "CVE-2024-1234 unaffected per vendor advisory"}]
    assert quality.consistency(ok_claims)["rate"] == 0.0
    bad = quality.consistency(bad_claims)
    assert bad["rate"] == 1.0 and bad["contradictions"] == [{"subject": "CVE-2024-1234", "labels": ["affected", "unaffected"]}]
    gate = quality.consistency_gate(bad_claims)
    assert gate["pass"] is False and gate["value"] == 1.0 and gate["threshold"] == quality.CONSISTENCY_THRESHOLD

    # 0 of 1 locked-shape consumer tests broken: the existing 5-gate report shape is untouched by the 6th metric
    rep = quality.top10_report()
    assert set(rep["gates"]) == {"faithfulness", "relevance", "completeness", "tool_accuracy", "over_refusal"}
    for g in rep["gates"].values():
        assert set(g) == {"value", "threshold", "pass"}
    assert "consistency" in rep["metrics"] and "consistency_gate" in rep
    assert rep["consistency_gate"]["threshold"] == quality.CONSISTENCY_THRESHOLD
    assert rep["consistency_gate"]["pass"] is (rep["consistency_gate"]["value"] <= quality.CONSISTENCY_THRESHOLD)


#: (text, the status label it must classify as) - natural NEGATED phrasing, not the bare antonym word
NEGATED_STATUS_PHRASES = [
    ("this project is not vulnerable to CVE-2024-1234", "unaffected"),
    ("requests has no patch available for this issue", "no_patch"),
    ("CVE-2024-1234 미영향", "unaffected"),               # Korean negation the module already recognises
    ("requests 패치 없음", "no_patch"),                    # Korean negation the module already recognises
]


def test_claim_status_classifies_natural_negated_phrasing_instead_of_the_positive_substring_it_contains():
    """AC: BSA-AC-1125"""
    correct = 0
    for text, expect in NEGATED_STATUS_PHRASES:
        if quality._claim_status(text) == expect:
            correct += 1
    assert correct == len(NEGATED_STATUS_PHRASES) == 4             # 4 of 4 negated phrasings classified by their negation

    # the direct contradiction from the confirmed finding: a positive claim and a NATURALLY-NEGATED one about the
    # same CVE must still be flagged - this used to be silently missed (both resolved to "affected")
    claims = [{"text": "CVE-2024-1234 affects this project, it is vulnerable"},
              {"text": "Per the vendor advisory, this project is not vulnerable to CVE-2024-1234"}]
    result = quality.consistency(claims)
    assert result["rate"] == 1.0
    assert result["contradictions"] == [{"subject": "CVE-2024-1234", "labels": ["affected", "unaffected"]}]

    # a bare positive claim (no negation) is still classified as positive - the reordering did not flip this
    assert quality._claim_status("CVE-2024-1234 affects this project, it is vulnerable") == "affected"
    assert quality._claim_status("patch available for requests") == "patch_available"
