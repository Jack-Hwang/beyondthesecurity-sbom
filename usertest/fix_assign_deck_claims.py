# -*- coding: utf-8 -*-
"""Correct one unverified claim the previous round (usertest/update_assign_deck.py) wrote into the
assignment deck, and add the operation limits measured on 2026-11-28.  Run against the af7aa7c deck.

1. 'Easy Auth auth wall live (11-28)' on 아키텍처 ④ is FALSE - `az containerapp auth show` returns {}
   (not configured).  Authentication is the shared access token only -> the limit is restored.
   (It had been copied from a memory note instead of measured - that was the mistake.)

2. 아키텍처 ⑤ said rollback = previous-revision traffic 100%.  Verified TRUE by REST: 17 revisions are
   retained and Healthy (initial + 0000001..0000016), 0000016 at traffic 100.  TRAP: `az containerapp
   revision list` returns only the ACTIVE revision - an intermediate 'no previous revisions' correction
   was based on that and is not applied.  The line now cites the measured basis.

3. 성과·한계 gains the measured limits: cold start 35.4s (replica 0 -> first /healthz TTFB), 0 alert rules,
   0 backup vaults, LRS single region (bts-sbom-rg inventory: 5 resources).

Formatting-preserving paragraph surgery as in update_assign_deck.py.
"""
import copy
import io
import sys

from pptx import Presentation
from pptx.oxml.ns import qn

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PATH = r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx"


def find_shape(slide, name):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    raise KeyError(name)


def set_para_text(p, parts):
    runs = p.findall(qn("a:r"))
    template_rPr = None
    if runs:
        rPr = runs[0].find(qn("a:rPr"))
        template_rPr = copy.deepcopy(rPr) if rPr is not None else None
    for r in runs:
        p.remove(r)
    for br in p.findall(qn("a:br")):
        p.remove(br)
    endPr = p.find(qn("a:endParaRPr"))
    for text, bold in parts:
        r = p.makeelement(qn("a:r"), {})
        if template_rPr is not None:
            rPr = copy.deepcopy(template_rPr)
            if bold is not None:
                rPr.set("b", "1" if bold else "0")
            r.append(rPr)
        t = r.makeelement(qn("a:t"), {})
        t.text = text
        r.append(t)
        if endPr is not None:
            endPr.addprevious(r)
        else:
            p.append(r)


def paras(shape):
    return shape.text_frame._txBody.findall(qn("a:p"))


def insert_after(shape, idx, parts):
    src = paras(shape)[idx]
    p = copy.deepcopy(src)
    set_para_text(p, parts)
    src.addnext(p)


pres = Presentation(PATH)

# --- slide 11 (아키텍처 ④): restore the honest Easy Auth limit
s11 = pres.slides[10]
assert "Azure Container Apps" in find_shape(s11, "Title 1").text_frame.text
set_para_text(paras(find_shape(s11, "TextBox 17"))[2], [
    ("공개 인그레스 + 공유 토큰", True),
    (" — 사용자별 계정(Easy Auth)은 미설정(11-28 `az containerapp auth show` = {}). 이것이 현재의 한계", None),
])
s11.notes_slide.notes_text_frame.text = (
    "라이브 조회(2026-11-28): revision bts-sbom--0000016 Running, 이미지 ir-20261128b, 0.5 vCPU/1Gi, scale 0→1. "
    "이미지 풀은 시스템 할당 MI(AcrPull) — acr-password 시크릿은 삭제되었고 ACR 관리자 계정 OFF. "
    "Easy Auth는 미설정(`az containerapp auth show`가 {} 반환) — 인증은 공유 액세스 토큰 하나뿐. "
    "운영 설계는 다음 장(아키텍처 ⑤).")

# --- slide 12 (아키텍처 ⑤): rollback line cites its measured basis
s12 = pres.slides[11]
assert "아키텍처 ⑤" in find_shape(s12, "Title 1").text_frame.text
set_para_text(paras(find_shape(s12, "TextBox 17"))[1], [
    ("Git 전략 + 롤백", True),
    (" — feature→dev→release/stg→master · 태그 YYYYMMDDHHmm · 롤백은 이전 리비전 트래픽 100%", None),
    (" (11-28 REST 실측: 이전 리비전 16개 보존·Healthy, ACR 태그 15개도 잔존)", None),
])
s12.notes_slide.notes_text_frame.text = s12.notes_slide.notes_text_frame.text + (
    " 롤백 근거(2026-11-28 REST 실측): 리비전 17개(초기 1 + 0000001~0000016) 전부 보존·Healthy, 0000016이 트래픽 100%. "
    "주의: `az containerapp revision list`는 활성 리비전 1건만 돌려준다 — 전수는 REST /revisions로 확인했다.")

# --- slide 34 (성과와 한계)
s = pres.slides[33]
assert find_shape(s, "Title 1").text_frame.text.startswith("성과와 한계")
limit = find_shape(s, "한계 카드")
set_para_text(paras(limit)[1], [
    ("인증은 공유 토큰 하나 — Easy Auth 미설정(11-28 실측)·사용자 계정 없음", None)])
set_para_text(paras(limit)[3], [
    ("영어 질의 챗 found 27/32, 스케일 0이라 첫 요청은 콜드 스타트 — 11-28 실측 35.4초", None)])
insert_after(limit, 4, [
    ("운영 안전망 없음 — 경고 규칙 0 · 백업 0 · 단일 리전 LRS(11-28 실측)", None)])
nxt = find_shape(s, "다음 단계 카드")
set_para_text(paras(nxt)[1], [
    ("Easy Auth(AAD) 연동으로 사용자별 접근 통제 — 현재는 공유 토큰 1개", None)])
set_para_text(paras(nxt)[2], [
    ("상시 1대 + 예산 경보로 콜드 스타트(실측 35초)·비용 관리", None)])
insert_after(nxt, 5, [
    ("Workload Identity·Key Vault로 시크릿 이관 · 경고 규칙·Files 백업 수립", None)])
s.notes_slide.notes_text_frame.text = (
    "근거: readme.txt 0.6.0 실측(테스트 1,270 수집 / 1,254 통과 단독 실행, 2026-11-28) · 리비전 0000016(az CLI 11-28). "
    "정정(2026-11-28 실측): Easy Auth는 미설정(az containerapp auth show = {}) — 앞 판의 '인증 벽 라이브'는 오기였다. "
    "콜드 스타트 35.4초 = 레플리카 0 상태에서 /healthz 첫 요청 TTFB(기동 후 56ms); 로그 유도로 요청→스케줄 약 15초, "
    "스케줄→이미지 풀(3.72초·86MB)·기동 약 20초, 앱 리스닝 0.2초. "
    "bts-sbom-rg 인벤토리: 리소스 5개(ACR·LA·Storage·환경·앱) — 경고 규칙·액션 그룹·백업 자격증명·App Insights 없음. "
    "Storage Standard_LRS 단일 리전. 롤백 경로는 유효 — REST로 리비전 17개 보존 확인.")

pres.save(PATH)
print("corrected: slides 11, 12, 34 (1-based)")
