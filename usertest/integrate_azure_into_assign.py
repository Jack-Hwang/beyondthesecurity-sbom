# -*- coding: utf-8 -*-
"""Integrate the Azure operations architecture (squeezed to 10 content slides, built by
`node usertest/build_azure_arch_deck.js --assign`) into the course assignment deck.

For every planned slide: clone a same-deck slide (so title box, section pill, sources line, layout and the
slide-number field are the course deck's own), strip its body, write the chrome texts, then transplant the
content shapes from the built source deck (image relationships re-created in the target package). Then refresh
three numbers that moved while the deck was being written, and run a PowerPoint COM gate (overflow / off-slide)
plus PNG export of every changed slide.

  python -I usertest/build_azure_arch_deck.js --assign   (NODE_PATH=... ; writes evidence/deck_render/assign_v2/)
  python -I usertest/integrate_azure_into_assign.py
"""
import copy
import io
import json
import os
import sys

from pptx import Presentation
from pptx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx.oxml.ns import qn

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DECK = os.path.join(ROOT, "docs", "BTS-SBOM_1-6주차_종합_과제_황병주_20261128.pptx")
WORK = os.path.join(ROOT, "evidence", "deck_render", "assign_v2")
KEEP = ("Title 1", "섹션 태그", "출처")          # the course deck's chrome shapes - kept on every clone

plan = json.load(io.open(os.path.join(WORK, "plan.json"), encoding="utf-8"))
src = Presentation(os.path.join(WORK, "source.pptx"))
src_slides = {p["id"]: s for p, s in zip(plan, src.slides)}
prs = Presentation(DECK)


def title_of(s):
    for sh in s.shapes:
        if sh.name.startswith("Title") or sh.name.startswith("제목"):
            return sh.text_frame.text.replace("\n", " ").replace("\x0b", " ")
    return ""


def find(*subs):
    """first slide whose title contains any of the given substrings (a replaced slide keeps the plan working on a re-run)"""
    for sub in subs:
        for i, s in enumerate(prs.slides):
            if sub in title_of(s):
                return i
    raise SystemExit("anchor not found: " + " | ".join(subs))


def duplicate(index0):
    source = prs.slides[index0]
    dest = prs.slides.add_slide(source.slide_layout)
    for shp in list(dest.shapes):
        shp._element.getparent().remove(shp._element)
    for shp in source.shapes:
        if shp.name in KEEP:
            dest.shapes._spTree.append(copy.deepcopy(shp._element))
    ids = list(prs.slides._sldIdLst)
    new = ids[-1]
    prs.slides._sldIdLst.remove(new)
    prs.slides._sldIdLst.insert(index0 + 1, new)
    return dest


def delete(index0):
    sld = list(prs.slides._sldIdLst)[index0]
    prs.part.drop_rel(sld.rId)
    prs.slides._sldIdLst.remove(sld)


def _put(p, el):
    end = p.find(qn("a:endParaRPr"))
    end.addprevious(el) if end is not None else p.append(el)


def set_paras(shape, lines):
    body = shape.text_frame._txBody
    p0 = body.findall(qn("a:p"))[0]
    runs = p0.findall(qn("a:r"))
    rPr = copy.deepcopy(runs[0].find(qn("a:rPr"))) if runs and runs[0].find(qn("a:rPr")) is not None else None
    for extra in body.findall(qn("a:p"))[1:]:
        body.remove(extra)
    for tag in ("a:r", "a:br", "a:fld"):
        for e in p0.findall(qn(tag)):
            p0.remove(e)
    for i, line in enumerate(lines):
        if i:
            _put(p0, p0.makeelement(qn("a:br"), {}))
        r = p0.makeelement(qn("a:r"), {})
        if rPr is not None:
            r.append(copy.deepcopy(rPr))
        t = r.makeelement(qn("a:t"), {})
        t.text = line
        r.append(t)
        _put(p0, r)


def chrome(slide, sec, title, sources):
    for sh in slide.shapes:
        if sh.name.startswith("Title") or sh.name.startswith("제목"):
            set_paras(sh, title.split("\n"))
        elif sh.name == "섹션 태그":
            set_paras(sh, [sec])
        elif sh.name == "출처":
            set_paras(sh, [sources])


def transplant(dst, ssrc, next_id):
    for el in list(ssrc.shapes._spTree):
        if el.tag in (qn("p:nvGrpSpPr"), qn("p:grpSpPr")):
            continue
        el = copy.deepcopy(el)
        for c in el.iter(qn("p:cNvPr")):
            next_id[0] += 1
            c.set("id", str(next_id[0]))
        for blip in el.iter(qn("a:blip")):
            rid = blip.get(qn("r:embed"))
            part = ssrc.part.related_part(rid)
            _, new_rid = dst.part.get_or_add_image_part(io.BytesIO(part.blob))
            blip.set(qn("r:embed"), new_rid)
        dst.shapes._spTree.append(el)


changed = []
import re  # noqa: E402
AC_COUNT = len(re.findall(r"^- BSA-AC-\d+", io.open(os.path.join(ROOT, "specs", "bts_sbom_app_features.md"), encoding="utf-8").read(), re.M))
for item in plan:
    key = item.get("title", "").splitlines()[0][:14] if item.get("title") else ""
    if item["action"] == "remove":                      # retire a slide an upgraded one supersedes
        try:
            delete(find(item["target"]))
            print("removed:", item["target"])
        except SystemExit:
            pass
        continue
    exist = next((k for k, s in enumerate(prs.slides) if key and key in title_of(s)), None)
    replacing = item["action"] == "replace"
    if item["action"].startswith("insert") and exist is not None:
        if os.environ.get("REFRESH") != "1":          # default: a planned slide that is already present is left alone
            print("skip (already in deck):", item["id"])
            continue
        i = exist                                   # REFRESH=1: regenerate it in place (clone, then delete the old)
        replacing = True
    else:
        i = find(item["target"], key)
    new = duplicate(i)
    template = prs.slides[i]
    max_id = max(int(c.get("id")) for c in new._element.iter(qn("p:cNvPr")))
    chrome(new, item["sec"], item["title"], item["sources"])
    transplant(new, src_slides[item["id"]], [max_id])
    new.notes_slide.notes_text_frame.text = src_slides[item["id"]].notes_slide.notes_text_frame.text
    el = [e for e in prs.slides._sldIdLst if e.id == new.slide_id][0]
    prs.slides._sldIdLst.remove(el)
    pos = i if item["action"] == "insert_before" else i + 1
    prs.slides._sldIdLst.insert(pos, el)
    if replacing:
        delete(i)                     # the old slide now sits right after the new one
        pos = i
    changed.append(pos)

# ---- numbers that moved while the deck was written (speclint re-measured 2026-11-28: 675 ACs, 0 unknown refs) ----
def first_run(shape, new):
    r = shape.text_frame._txBody.findall(qn("a:p"))[0].findall(qn("a:r"))[0]
    r.find(qn("a:t")).text = new


for sh in prs.slides[1].shapes:                       # 목차 stat cards + source line
    if not sh.has_text_frame:
        continue
    txt = sh.text_frame.text
    if txt.startswith("667"):
        first_run(sh, str(AC_COUNT))
    elif txt.startswith("93\n"):
        first_run(sh, "100")
    elif txt.startswith("수치 출처:"):
        set_paras(sh, ["수치 출처: specs/bts_sbom_app_features.md AC %d건(2026-11-28 최종 점검) · readme.txt 0.6.0 실측 · docs/LECTURE_MAPPING.md" % AC_COUNT])
for sh in prs.slides[5].shapes:                       # 요구사항 장: speclint 문구
    if not sh.has_text_frame:
        continue
    for p in sh.text_frame._txBody.findall(qn("a:p")):
        if "미등록 AC 참조" in "".join(t.text or "" for t in p.iter(qn("a:t"))):
            p.findall(qn("a:r"))[-1].find(qn("a:t")).text = "0 (재측정)"

from pptx.opc.packuri import PackURI  # noqa: E402
from pptx.dml.color import RGBColor  # noqa: E402
from pptx.enum.text import PP_ALIGN  # noqa: E402
from pptx.util import Pt  # noqa: E402

GH = "https://github.com/Jack-Hwang/beyondthesecurity-sbom"
LIVE = "https://bts-sbom.wittyforest-2c8fae00.koreacentral.azurecontainerapps.io"
cover = prs.slides[0]
if not any(sh.has_text_frame and "github.com/Jack-Hwang" in sh.text_frame.text for sh in cover.shapes):
    tb = cover.shapes.add_textbox(Pt(128), Pt(378), Pt(612), Pt(54))     # inside the blue title card
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r = p.add_run()
    r.text = "GitHub: " + GH
    r.hyperlink.address = GH
    p2 = tf.add_paragraph()
    p2.alignment = PP_ALIGN.LEFT
    r2 = p2.add_run()
    r2.text = "Azure 라이브: " + LIVE + "  (액세스 토큰 필요 · 없으면 401)"
    r2.hyperlink.address = LIVE
    for r in list(p.runs) + list(p2.runs):
        r.font.size = Pt(10.5)
        r.font.name = "맑은 고딕"
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
# add_slide() numbers a new part from the CURRENT slide count, so a number freed by delete() gets reused and the
# package ends up with two parts of one name (PowerPoint refuses to open it) - renumber every slide part.
for n, s in enumerate(prs.slides, 1):
    s.part.partname = PackURI("/ppt/slides/tmp_%d.xml" % n)
for n, s in enumerate(prs.slides, 1):
    s.part.partname = PackURI("/ppt/slides/slide%d.xml" % n)
prs.save(DECK)
print("saved %s: %d slides (was 35) · changed slides (1-based): %s" % (os.path.relpath(DECK, ROOT), len(prs.slides), [c + 1 for c in changed]))

# ---- gate: PowerPoint's own layout numbers, read-only ----
import win32com.client  # noqa: E402
from PIL import Image  # noqa: E402

app = win32com.client.Dispatch("PowerPoint.Application")
STARTED_EMPTY = app.Presentations.Count == 0          # never quit a PowerPoint the user has open
over, off = [], []
pres = None
try:
    pres = app.Presentations.Open(DECK, WithWindow=False, ReadOnly=True)
    sw, shh = pres.PageSetup.SlideWidth, pres.PageSetup.SlideHeight
    for i in changed:
        pres.Slides(i + 1).Export(os.path.join(WORK, "slide_%02d.png" % (i + 1)), "PNG", 1280, 720)
    for i in range(1, pres.Slides.Count + 1):
        for shape in pres.Slides(i).Shapes:
            if shape.Left < -1 or shape.Top < -1 or shape.Left + shape.Width > sw + 1 or shape.Top + shape.Height > shh + 1:
                off.append((i, shape.Name, round(shape.Left), round(shape.Top), round(shape.Width), round(shape.Height)))
            if shape.HasTextFrame and shape.TextFrame.HasText:
                tr = shape.TextFrame2.TextRange
                if tr.BoundHeight - shape.Height > 2:
                    over.append((i, shape.Name, round(tr.BoundHeight - shape.Height, 1), tr.Text[:26]))
    total = pres.Slides.Count
finally:
    if pres is not None:
        pres.Close()
    if STARTED_EMPTY:
        app.Quit()
names = sorted(n for n in os.listdir(WORK) if n.startswith("slide_") and n.endswith(".png"))
sheet = Image.new("RGB", (960 * 3, 540 * 4), (20, 24, 32))
for j, n in enumerate(names):
    sheet.paste(Image.open(os.path.join(WORK, n)).convert("RGB").resize((960, 540), Image.LANCZOS), ((j % 3) * 960, (j // 3) * 540))
sheet.save(os.path.join(WORK, "sheet_changed.png"), optimize=True)
print("gate: slides %d · off-slide %d %s · overflowing text %d" % (total, len(off), off[:6], len(over)))
for o in over[:25]:
    print("   s%-2d %-16s over %5.1fpt  «%s»" % o)
sys.exit(1 if (over or off) else 0)
