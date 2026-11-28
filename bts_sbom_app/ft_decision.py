"""The Fine-tuning decision table, MEASURED (course week 5 lesson 2, 5-2 의사결정표): '지식은 RAG, 행동·형식은
FT - 먼저 무엇을 바꿀지 판단한다' + '프롬프트 미정제면 프롬프트 먼저' + 비례성(FT는 최후). Teams answer 'should
we fine-tune?' from vibes; this module answers from THIS repository's artifacts:

* ``knowledge_gap``  - 1 - golden-set recall (the retrieval measurement): knowledge lives or dies in RAG, and no
                       amount of fine-tuning replaces a missing document;
* ``format_gap``     - 1 - answer correctness (C61 reference grader): wrong-shape answers with the documents
                       present are a BEHAVIOUR problem - the FT candidate, but only after prompt hygiene;
* ``routing_gap``    - 1 - the deterministic tool-accuracy floor: planner behaviour, not model knowledge.

The recommendation names its bucket and its numbers, and the DEFAULT stays against fine-tuning (비례성): FT is
suggested only when the format gap dominates while retrieval is already good - and even then as 'FT 후보, ADR-ft
절차(누출 검사·세그먼트 평가)를 통과한 뒤에만'. A knowledge gap recommends corpus work, never training.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from . import evals, evals_top10


def decide(root: Optional[str] = None) -> Dict[str, Any]:
    """The measured decision-table row: which gap dominates, what fixes it, and why FT is (or is not) the move."""
    root = root or evals.repo_root()
    rag = evals.rag_eval(root)
    ref = evals_top10.reference_eval(root)
    ta = evals_top10.tool_accuracy_eval(root)
    recall = rag.get("recall_at_k")
    correctness = ref.get("answer_correctness")
    floor = ta.get("tool_accuracy_read_floor")
    knowledge_gap = round(1 - recall, 3) if isinstance(recall, (int, float)) else None
    format_gap = round(1 - correctness, 3) if isinstance(correctness, (int, float)) else None
    routing_gap = round(1 - floor, 3) if isinstance(floor, (int, float)) else None
    gaps = {k: v for k, v in (("knowledge", knowledge_gap), ("format", format_gap), ("routing", routing_gap)) if v is not None}
    dominant = max(gaps, key=gaps.get) if gaps else None
    table = {
        "knowledge": "RAG 보강 - 문서/코퍼스를 채운다. 최신·사실 지식은 재학습 주기로는 못 따라온다(강의 5-2 의사결정표 1행)",
        "format": "프롬프트 정제 먼저(기준·few-shot) - 그 다음 FT 후보: 강의 3행 '아직 프롬프트 미정제 → 프롬프트·few-shot'과 비례성",
        "routing": "라우팅/플래너 개선 - 도구 선택은 행동 문제지만 먼저 정규식 라우터와 플래너 프롬프트를 점검한다",
    }
    if dominant is None:
        recommendation, reason = "판정 불능", "측정값이 하나도 없다 - evals를 먼저 돌린다 (조용한 통과 없음)"
    elif dominant == "knowledge":
        recommendation, reason = table["knowledge"], "golden recall %.3f - 지식 갭이 지배한다: 파인튜닝이 아니라 코퍼스다" % recall
    elif dominant == "format":
        if format_gap is not None and format_gap <= 0.15:
            recommendation, reason = ("유지 - FT 부적합(비례성)", "format 갭 %.3f는 프롬프트 정제로 닫을 범위다 - FT는 과설계" % format_gap)
        else:
            recommendation, reason = (table["format"], "answer correctness %.3f - 형식/행동 갭이 지배한다: 프롬프트 먼저, 그 다음 ADR-ft" % correctness)
    else:
        recommendation, reason = table["routing"], "read floor %.3f - 라우팅 갭이 지배한다" % floor
    return {"schema": "bts-sbom.ft-decision.v1",
            "measured": {"golden_recall": recall, "answer_correctness": correctness, "tool_read_floor": floor},
            "gaps": gaps, "dominant": dominant, "recommendation": recommendation, "reason": reason,
            "honesty": "이 판정은 측정에서 나왔다; FT 도입은 강의 절차(누출 검사·세그먼트 평가·ADR-ft)를 통과해야 하며 이 모듈은 그 결정을 대신하지 않는다"}
