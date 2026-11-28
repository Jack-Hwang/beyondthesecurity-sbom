"""Datasheet for Datasets (backlog C28; Gebru et al. 2021 via course week 5 lesson 4 "Origin & Lineage"): the
evaluation corpora + knowledge corpus get the same honest export the AI impact assessment gets - what is IN each
dataset, where it came from, how it is composed, and what its known limits are. Built like ai_impact: resolve the
live artifacts, cite only existing paths with measured counts, and machine-gate the committed document so a corpus
that changed under a stale datasheet is CAUGHT, not remembered.

Sections follow the datasheet questions that matter for an eval corpus: motivation/composition (n, 전형/경계/적대
per corpus - evalguard.composition), collection provenance (which files, what they were written for), and the
leak/duplication hygiene status (evalguard.leak_check on the retrieval sets). The staleness gate re-resolves the
cited paths and re-counts the corpora: a document whose numbers no longer match the data is stale by construction.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from . import evalguard, evals

SCHEMA = "bts-sbom.dataset-datasheet.v1"
DOC_PATH = os.path.join("docs", "DATASET_DATASHEET.md")
SECTIONS = ("동기·구성", "수집·출처", "위생·한계")
_PATHY = re.compile(r"`((?:evals|knowledge)/[A-Za-z0-9_./\-]+\.(?:json|jsonl|md))`")


def assess(root: Optional[str] = None) -> Dict[str, Any]:
    """Resolve the live corpus facts: per eval corpus its size, composition and fingerprint; per knowledge source
    its file count. Only paths that exist are cited."""
    root = root or evals.repo_root()
    inv = evals.eval_inventory(root)
    corpora = []
    for name, c in sorted(inv["sets"].items()):
        ext = ".jsonl" if name in evalguard.ADVERSARIAL_SETS else ".json"
        p = "evals/%s%s" % (name, ext)                # forward slashes: the corpus path is a doc identity, not a file handle
        if os.path.exists(os.path.join(root, *p.split("/"))):
            corpora.append({"path": p, "n": c["n"], "kinds": c["kinds"], "fingerprint": c["fingerprint"],
                            "rules": c["kind_rules"]})
    knowledge: List[Dict[str, Any]] = []
    kdir = os.path.join(root, "knowledge")
    if os.path.isdir(kdir):
        for sub in sorted(os.listdir(kdir)):
            sp = os.path.join(kdir, sub)
            if os.path.isdir(sp):
                n = sum(1 for _, _, fs in os.walk(sp) for f in fs if f.endswith(".md"))
                if n:
                    knowledge.append({"path": "knowledge/" + sub, "files": n})
    leak = evalguard.leak_check({k: v for k, v in (evals.rag_set_items(root) or {}).items()})
    return {"schema": SCHEMA, "corpora": corpora, "knowledge": knowledge,
            "leak": {"blocking": leak["blocking"], "warnings": leak["warnings"], "clean": leak["clean"]}}


def render(payload: Dict[str, Any]) -> str:
    """The datasheet markdown - measured composition per corpus, provenance per knowledge source, hygiene status."""
    L: List[str] = ["# Dataset Datasheet — bts-sbom 평가·지식 코퍼스", "",
                    "schema: %s | 이 문서는 코퍼스가 바뀌면 스테일로 판정된다 — `python -m bts_sbom_app datasheet --check`가 기계 판정." % payload["schema"], ""]
    L += ["## 동기·구성", "",
          "평가셋은 곧 평가가 찾아낼 수 있는 실패의 상한이다: 전형(일상 질의)·경계(주제 밖 ood)·적대(공격·교란)의 구성비가"
          " 그대로 커버리지를 정의한다. 아래는 각 코퍼스의 실측 구성(전형/경계/적대)과 내용 핀(fingerprint)이다.", ""]
    for c in payload["corpora"]:
        k = c["kinds"]
        L.append("- `%s` — n=%d, 전형 %d / 경계 %d / 적대 %d, fingerprint `%s`" % (
            c["path"], c["n"], k.get("typical", 0), k.get("boundary", 0), k.get("adversarial", 0), c["fingerprint"]))
    if not payload["corpora"]:
        L.append("- 미확인 (기록된 코퍼스 없음)")
    L += ["", "## 수집·출처", "",
          "RAG 골든셋은 제품 문서·강의 노트에서 질의를 작성해 만들었고, holdout(rag_test)은 튜닝 전에 작성되어 따로 핀을 갖는다."
          " injection 코퍼스는 공격 라벨/정상 라벨이 붙은 이중 언어 표본이다. 지식 코퍼스 출처:", ""]
    for k in payload["knowledge"]:
        L.append("- `%s` — %d개 문서" % (k["path"], k["files"]))
    if not payload["knowledge"]:
        L.append("- 미확인 (기록된 지식 출처 없음)")
    L += ["", "## 위생·한계", "",
          "- 누출 검사: blocking %d건, warning %d건 (%s — `python -m bts_sbom_app evalsets`가 재판정한다)." % (
              payload["leak"]["blocking"], payload["leak"]["warnings"], "clean" if payload["leak"]["clean"] else "findings 존재"),
          "- 한계: 골든셋이 작다(합계 %d건) — 점수는 Wilson 구간으로 읽어야 한다. chat_features는 전형뿐이다(구성표가 그 간극을 드러낸다)." % sum(c["n"] for c in payload["corpora"] if c["path"].startswith("evals/rag")),
          "- 이 문서의 모든 역따옴표 경로는 존재해야 하고 코퍼스 건수는 실측과 일치해야 한다 — 어긋나면 스테일이고 exit 1이다.", ""]
    return "\n".join(L)


def gate(root: Optional[str] = None, doc_path: Optional[str] = None) -> Dict[str, Any]:
    """Staleness machine-check of the committed datasheet: sections present, cited corpus paths exist, and the n /
    전형/경계/적대 numbers still match the live corpora (a corpus that changed under a stale datasheet is caught)."""
    root = root or evals.repo_root()
    doc = doc_path or os.path.join(root, DOC_PATH)
    findings: List[str] = []
    if not os.path.exists(doc):
        return {"schema": SCHEMA, "ok": False, "findings": ["datasheet document missing: %s" % DOC_PATH]}
    text = open(doc, encoding="utf-8", errors="replace").read()
    for s in SECTIONS:
        if ("## " + s) not in text:
            findings.append("required section missing: %s" % s)
    for m in _PATHY.finditer(text):
        if not os.path.exists(os.path.join(root, *m.group(1).replace("\\", "/").split("/"))):
            findings.append("cited corpus is gone (stale): %s" % m.group(1))
    live = {c["path"]: c for c in assess(root)["corpora"]}
    for m in re.finditer(r"`(evals/[A-Za-z0-9_.]+)` — n=(\d+), 전형 (\d+) / 경계 (\d+) / 적대 (\d+)", text):
        path, n, ty, bo, ad = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
        cur = live.get(path)
        if cur is None:
            findings.append("corpus cited in the datasheet no longer exists in the inventory: %s" % path)
        elif (cur["n"], cur["kinds"].get("typical", 0), cur["kinds"].get("boundary", 0), cur["kinds"].get("adversarial", 0)) != (n, ty, bo, ad):
            findings.append("%s changed under the datasheet: doc n=%d (%d/%d/%d) vs live n=%d (%d/%d/%d) - regenerate" % (
                path, n, ty, bo, ad, cur["n"], cur["kinds"].get("typical", 0), cur["kinds"].get("boundary", 0), cur["kinds"].get("adversarial", 0)))
    return {"schema": SCHEMA, "ok": not findings, "findings": findings}
