# -*- coding: utf-8 -*-
"""Update the 1-6주차 종합 과제 deck with the Azure-operations content that the new
AZURE_OPERATIONS_OVERVIEW deck carries and this deck lacks. Surgical, XML-level edits that keep
every paragraph's formatting (clone an existing paragraph as the template for new lines):

- NEW slide after 11 (아키텍처 ④):  아키텍처 ⑤ MI 풀 · Git 전략 · 리비전 롤백 (cloned design system)
- NEW slide after ⑰:               ⑱ 콘솔 5섹션 · A2UI · HITL 라이브 · 운영 계약 (screenshot = ops-deck UI render)
- UPDATE slide 11 (stale image/limits), slide ⑯ (cost line), slide 2 (stat cards),
  slide 6 (speclint line), slide 성과·한계 (v0.6.0 numbers, resolved/changed limits), MECE table cells.

All numbers are measured: revision 0000016 / ir-20261128b (az CLI, 2026-11-28), AC total 667 (speclint),
tests 1,270 / 1,254 passed solo (readme.txt 0.6.0 measurement of this tree), modules 93.
"""
import copy
import io
import sys

from pptx import Presentation
from pptx.oxml.ns import qn

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PATH = r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx"
SHOT = r"C:\firebaseprojects\beyondthesecurity-sbom\evidence\deck_render\slide_07.png"

pres = Presentation(PATH)


# ---------- low-level helpers (formatting-preserving text surgery) ----------

def find_shape(slide, name):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    raise KeyError(name)


def paras(shape):
    return shape.text_frame._txBody.findall(qn("a:p"))


def set_para_text(p, parts):
    """Replace the runs of one paragraph. parts = [(text, bold_or_None)] where None keeps the
    original first-run boldness pattern (single run). Formatting (rPr) is cloned from the
    paragraph's own first run, with bold forced only where asked."""
    template_rPr = None
    runs = p.findall(qn("a:r"))
    if runs:
        rPr = runs[0].find(qn("a:rPr"))
        template_rPr = copy.deepcopy(rPr) if rPr is not None else None
    elif p.findall(qn("a:fld")):  # never expected here
        raise ValueError("field runs unsupported")
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


def replace_lines(shape, lines):
    """Replace ALL paragraphs of a box: lines = [[(text, bold), ...], ...] (one inner list per paragraph).
    The first original paragraph is the formatting template; extra paragraphs are deep copies of it."""
    body = shape.text_frame._txBody
    originals = body.findall(qn("a:p"))
    template = copy.deepcopy(originals[0])
    for p in originals:
        body.remove(p)
    for parts in lines:
        p = copy.deepcopy(template)
        set_para_text(p, parts)
        body.append(p)


def append_para(shape, parts):
    """Append one paragraph cloned from the LAST paragraph's formatting."""
    body = shape.text_frame._txBody
    original = body.findall(qn("a:p"))[-1]
    p = copy.deepcopy(original)
    set_para_text(p, parts)
    body.append(p)


def set_box_runs(shape, para_idx, parts):
    set_para_text(paras(shape)[para_idx], parts)


def duplicate_slide(pres, index0):
    """Clone slide at 0-based index, insert the copy right after it. Copies shapes XML + rels + bg."""
    from pptx.opc.constants import RELATIONSHIP_TYPE as RT

    source = pres.slides[index0]
    dest = pres.slides.add_slide(source.slide_layout)
    # drop the placeholder shapes the layout seeded
    for shp in list(dest.shapes):
        shp._element.getparent().remove(shp._element)
    # background element, if authored on the slide
    src_cSld = source._element.find(qn("p:cSld"))
    dst_cSld = dest._element.find(qn("p:cSld"))
    src_bg = src_cSld.find(qn("p:bg"))
    if src_bg is not None:
        old = dst_cSld.find(qn("p:bg"))
        if old is not None:
            dst_cSld.remove(old)
        dst_cSld.insert(0, copy.deepcopy(src_bg))
    # shapes
    rid_map = {}
    for rel in list(source.part.rels.values()):
        if rel.reltype in (RT.SLIDE_LAYOUT, RT.NOTES_SLIDE):
            continue
        if rel.is_external:
            rid_map[rel.rId] = dest.part.rels.get_or_add_ext_rel(rel.reltype, rel.target_ref)
        else:
            rid_map[rel.rId] = dest.part.relate_to(rel.target_part, rel.reltype)
    for shp in source.shapes:
        el = copy.deepcopy(shp._element)
        for attr_el in el.iter():
            for attr in list(attr_el.attrib):
                v = attr_el.attrib[attr]
                if v in rid_map:
                    attr_el.attrib[attr] = rid_map[v]
        dest.shapes._spTree.append(el)
    # notes: keep it empty for the clone (we set our own below if needed)
    # move the new slide right after the source
    sldIdLst = pres.slides._sldIdLst
    ids = list(sldIdLst)
    new_id = ids[-1]
    sldIdLst.remove(new_id)
    sldIdLst.insert(index0 + 1, new_id)
    return dest


def set_notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


# ---------- 1. clone slide 11 (idx 10) -> new 아키텍처 ⑤ at position 12 ----------

arch5 = duplicate_slide(pres, 10)

t = find_shape(arch5, "Title 1")
replace_lines(t, [[("아키텍처 ⑤: 운영은 MI 풀·Git 전략·리비전 롤백 위에서 계속됩니다", None)]])

set_box_runs(find_shape(arch5, "Azure 앱"), 1,
             [("0.5 vCPU · 1Gi · 스케일 0→1 · 프로브 3종 · 리비전 0000016·ir-20261128b", None)])

acr = find_shape(arch5, "Azure ACR")
set_box_runs(acr, 0, [("ACR btsbomacr1126", None)])
set_box_runs(acr, 1, [("Basic · 클라우드 빌드 46~50s · MI(AcrPull)로 풀 — 관리자 계정 OFF", None)])

set_box_runs(find_shape(arch5, "Azure Files"), 1,
             [("evidence 볼륨 · 감사 대장 영속 · btsbomstg1127", None)])
set_box_runs(find_shape(arch5, "Azure 로그"), 1,
             [("콘솔·시스템 로그 · 진단 설정 · btsbom-logs", None)])

set_box_runs(find_shape(arch5, "TextBox 16"), 0, [("운영 설계 3가지", None)])

ops_card = find_shape(arch5, "TextBox 17")
replace_lines(ops_card, [
    [("이미지 풀 = 시스템 할당 MI", True), (" — acr-password 시크릿 삭제·ACR 관리자 OFF(리비전 0000008부터 라이브)", None)],
    [("Git 전략 + 리비전 롤백", True), (" — feature→dev→release/stg→master · 태그 YYYYMMDDHHmm · 롤백은 이전 리비전 트래픽 100%", None)],
    [("영속은 Azure Files 한 곳", True), (" — OSV DB를 공유에 두면 잠금 대기 780s → 시드→로컬 복사로 96s·락 오류 0(AC-1226~1227)", None)],
])

set_box_runs(find_shape(arch5, "출처"), 0,
             [("근거: docs/AZURE_IDENTITY.md · GIT_STRATEGY.md · AZURE_OPERATIONS_OVERVIEW.pptx · 2026-11-28 az CLI 실측", None)])
set_notes(arch5,
          "근거(2026-11-28 az CLI 실측): 리비전 bts-sbom--0000016 Running(이미지 ir-20261128b, 병행 IR 레인 배포분). "
          "MI 전환: 시스템 할당 principal a597a9ae-…에 AcrPull 1건 → 레지스트리 identity:system → acr-password 시크릿 삭제 + ACR 관리자 OFF — 리비전 0000008부터 MI 풀 라이브. "
          "Workload Identity(Key Vault 연합 자격증명)는 stdlib 전용 런타임이라 다음 배포 창 과제(docs/AZURE_IDENTITY.md). "
          "배포 4단계: git push → az acr build(46~50s, .dockerignore로 1.9MiB) → az containerapp update --image → scripts/smoke_deployed.py 스모크. 롤백은 리비전 불변성 위 트래픽 전환. "
          "OSV DB 교훈: SMB 공유 위 캐시 쓰기가 잠금 대기로 NodeGoat 780s → 시작 시 시드→로컬 복사로 96s(AC-1226~1227).")

# ---------- 2. update the original slide 11 (stale facts) ----------

s11 = pres.slides[10]
set_box_runs(find_shape(s11, "Azure 앱"), 1,
             [("0.5 vCPU · 1Gi · 스케일 0→1 · 프로브 3종 · 리비전 0000016·ir-20261128b", None)])
acr = find_shape(s11, "Azure ACR")
set_box_runs(acr, 1, [("az acr build 클라우드 빌드 46~50s · 이미지 ir-20261128b", None)])
set_box_runs(find_shape(s11, "TextBox 17"), 2,
             [("공개 인그레스 + 토큰 게이트", True), (" — Easy Auth 인증 벽 라이브 확인(11-28). 사용자별 역할 구분은 다음 단계", None)])
set_box_runs(find_shape(s11, "출처"), 0,
             [("근거: docs/AZURE_DEPLOYMENT.md · AZURE_IDENTITY.md · deploy/azure/README.md · 2026-11-28 az CLI 실측", None)])
set_notes(s11,
          "라이브 조회(2026-11-28): revision bts-sbom--0000016 Running, 이미지 ir-20261128b, 0.5 vCPU/1Gi, scale 0→1. "
          "이미지 풀은 시스템 할당 MI(AcrPull) — acr-password 시크릿은 삭제되었고 ACR 관리자 계정 OFF(리비전 0000008부터). "
          "Easy Auth 인증 벽은 병향 IR 레인 배포 리비전에서 라이브 확인. 자세한 운영 설계는 다음 장(아키텍처 ⑤).")

# ---------- 3. update ⑯ (cost line) — slide 30 → now index 30 (0-based) after insertion ----------

s16 = pres.slides[30]
if find_shape(s16, "Title 1").text_frame.text.strip().startswith("⑯"):
    append_para(find_shape(s16, "Rounded Rectangle 4"),
                [("운영 비용(공개 단가 × 실측): 앱 약 $3·ACR $5·Files $0.4/월 — 무료 대안(ACA 월 100h 공제) 조사 완료", None)])
    old = s16.notes_slide.notes_text_frame.text if s16.has_notes_slide else ""
    set_notes(s16, old + " 라이브 리비전은 2026-11-28 기준 0000016·ir-20261128b(아키텍처 ⑤ 장 참조).")

# ---------- 4. clone ⑰ (now 0-based 31) -> new ⑱ at position 33 ----------

s18 = duplicate_slide(pres, 31)

t = find_shape(s18, "Title 1")
replace_lines(t, [[("⑱ 콘솔 5섹션·A2UI·HITL 라이브: 승인 체인과 운영 계약을 실측했습니다", None)]])

# swap the screenshot: ops-deck UI slide render (콘솔 5섹션 + 하단 dock)
pic = None
for shape in s18.shapes:
    if shape.shape_type == 13 and shape.name == "화면 캡처":
        pic = shape
        break
if pic is None:
    for shape in s18.shapes:
        if shape.shape_type == 13:
            pic = shape
            break
img_part, rId = s18.part.get_or_add_image_part(SHOT)
blip = pic._element.find(qn("p:blipFill") + "/" + qn("a:blip"))
if blip is None:
    blip = pic._element.blipFill.blip
blip.set(qn("r:embed"), rId)

tech = find_shape(s18, "TextBox 8")
replace_lines(tech, [[("콘솔 5섹션 · 하단 dock(A2UI 카드) · HITL 승인 체인 · SSE heartbeat/취소/trace_id · SIGTERM 드레인", None)]])

ll_box = find_shape(s18, "Rounded Rectangle 4")
replace_lines(ll_box, [
    [("하단 대화 dock · A2UI 카드", True)],
    [("모든 탭 상주 · SSE 7종 활동 카드(tool_call/result·승인·handoff·final·error)", None)],
    [("A2UI 카탈로그 19/27 도구를 esc-only 카드로 렌더 — 승인은 인라인 버튼 = 사용자 행위(AC-645/646)", None)],
])

how = find_shape(s18, "TextBox 11")
replace_lines(how, [
    [("콘솔 5섹션(스캔·결과·리포트·지식·운영) — 모든 판은 JSON API 위의 렌더러, 40+ 라우트", None)],
    [("HITL 체인 라이브: 오래된 승인 토큰 거부 · 격리 적용 80.7s · 소스 경계 거부 — 시도 전부 감사 대장 기록(AC-1257/1258)", None)],
    [("SSE heartbeat 15s·리더 퇴장=턴 취소(AC-1254/1256) · trace_id가 잡·SSE·에스컬레이션 관통 · SIGTERM 드레인", None)],
])

set_box_runs(find_shape(s18, "TextBox 14"), 0,
             [("라이브 HITL 실측: 오래된 토큰 거부·격리 적용 80.7s(BTS_SBOM_CHAT_ACTIONS=1 knob)", None)])
set_box_runs(find_shape(s18, "TextBox 14"), 1,
             [("SSE 계약 실측: heartbeat 유출·취소는 cancelled 행으로 정직 기록·X-Correlation-ID = final trace_id", None)])

set_box_runs(find_shape(s18, "출처"), 0,
             [("화면: AZURE_OPERATIONS_OVERVIEW 덱 UI 구성 슬라이드 실렌더 · 근거: AC-1254~1258 · AC-645/646 · evidence/chat_actions", None)])
set_notes(s18,
          "근거: AC-1254(턴 취소)·AC-1256(SSE heartbeat·trace_id)·AC-1257(승인 감사 대장)·AC-1258(처분 정책 오버라이드)·AC-645/646(A2UI 카드, 병행 레인). "
          "라이브 HITL 체인은 Azure 리비전에서 실측: 오래된 승인 토큰 거부, 격리 워크카피 적용 80.7초, 소스 경계 밖 거부. "
          "SSE heartbeat은 HEARTBEAT_SECONDS(기본 15s)마다 코멘트 라인 — 프록시 무음 절단 방지; 리더 퇴장(gone)이 남은 도구 호출을 cancelled 행으로 기록. "
          "X-Correlation-ID 헤더 = final 이벤트 trace_id = 잡 레코드 trace = 에스컬레이션 payload trace_id. "
          "이 장의 스크린샷은 운영 덱(docs/AZURE_OPERATIONS_OVERVIEW.pptx) UI 구성 슬라이드의 PowerPoint 실렌더다.")

# ---------- 5. 성과·한계 (old 32, now 0-based 33) ----------

s_perf = pres.slides[33]
assert find_shape(s_perf, "Title 1").text_frame.text.startswith("성과와 한계")
set_box_runs(find_shape(s_perf, "성과 카드 1"), 0, [("1,254 / 1,270", None)])
set_box_runs(find_shape(s_perf, "성과 카드 1"), 1, [("자동 테스트(0.6.0 실측·단독 실행)", None)])

limit = find_shape(s_perf, "한계 카드")
set_box_runs(limit, 1, [("인증은 Easy Auth 벽 뒤 공유 토큰 — 사용자별 역할 구분은 미적용", None)])
set_box_runs(limit, 4, [("KEV·EUVD 피드 미연동 — 취약점 악용 여부는 not-assessed로 정직 표기", None)])

nxt = find_shape(s_perf, "다음 단계 카드")
set_box_runs(nxt, 1, [("Workload Identity·Key Vault로 시크릿 이관 — stdlib 런타임이라 다음 배포 창", None)])
set_box_runs(nxt, 4, [("라이선스 표 마크업 결함 수정 · v0.6.0 릴리스 완료(태그·readme.txt 평가자 가이드)", None)])
set_box_runs(nxt, 5, [("재배포 경로 확보 — 리비전 0000016·ir-20261128b 라이브(11-28 실측)", None)])
set_notes(s_perf,
          "근거: readme.txt 0.6.0 실측(테스트 1,270 수집 / 1,254 통과 단독 실행, 2026-11-28) · 리비전 0000016(az CLI 11-28). "
          "한계 갱신: 전체 스위트 실패 3건은 해소(0.6.0 릴리스 게이트에서 통과) — 대신 KEV·EUVD 미연동을 정직 한계로 기재. "
          "Easy Auth는 병향 IR 레인이 라이브 적용(인증 벽 유지 실측) — 사용자별 역할은 미적용이므로 한계 문구를 갱신.")

# ---------- 6. 목차 통계 카드 (slide 2) + speclint 문구 (slide 6) ----------

s2 = pres.slides[1]
set_box_runs(find_shape(s2, "통계 카드 1"), 0, [("667", None)])
set_box_runs(find_shape(s2, "통계 카드 2"), 0, [("1,270", None)])
set_box_runs(find_shape(s2, "통계 카드 2"), 2, [("직전 전체 실행: 1,254 통과(단독)", None)])
set_box_runs(find_shape(s2, "출처"), 0,
             [("수치 출처: speclint(667, 2026-11-28) · readme.txt 0.6.0 실측 · docs/LECTURE_MAPPING.md", None)])
set_notes(s2,
          "AC 667은 speclint REQ-KINDS 합계(2026-11-28, SFR=301 DAR=103 PER=8 SIR=165 SECR=79 CONR=11). "
          "테스트 1,270/1,254는 readme.txt 0.6.0 실측(이 트리 f1b49eb 기준 단독 실행). 모듈 93은 bts_sbom_app/*.py 개수(2026-11-28), 교안 18.")
# 통계 카드 3 (91 모듈)
set_box_runs(find_shape(s2, "통계 카드 3"), 0, [("93", None)])

s6 = pres.slides[5]
rr8 = find_shape(s6, "Rounded Rectangle 8")
set_box_runs(rr8, 2,
             [("speclint: 테스트 없는 AC ", None), ("0", True), (" · 미등록 AC 참조 ", None), ("2건(병행 레인 등록 진행)", True)])
set_notes(s6,
          "speclint(2026-11-28): REQ-KINDS total=667, 테스트 없는 AC 0, 미등록 AC 참조 BSA-AC-1264·1265 2건 — 병행 레인이 테스트를 먼저 올리고 명세 등록이 진행 중인 상태. "
          "등록이 완료되면 참조 0으로 복귀.")

# ---------- 7. MECE table (old 33, now 0-based 34) ----------

s_mece = pres.slides[34]
tbl = None
for shape in s_mece.shapes:
    if getattr(shape, "has_table", False):
        tbl = shape.table
        break
assert tbl is not None

def set_cell(cell, lines):
    body = cell.text_frame._txBody
    originals = body.findall(qn("a:p"))
    template = copy.deepcopy(originals[0])
    for p in originals:
        body.remove(p)
    for line in lines:
        p = copy.deepcopy(template)
        set_para_text(p, [(line, None)])
        body.append(p)

set_cell(tbl.cell(5, 6), ["토큰 게이트 · MI 풀 · Git 전략", "레드팀 · 야간 드리프트"])
set_cell(tbl.cell(4, 6), ["영어 질의 · PII 메모리 · A2UI 카드"])

pres.save(PATH)
print("saved:", PATH)
print("slides now:", len(pres.slides._sldIdLst))
