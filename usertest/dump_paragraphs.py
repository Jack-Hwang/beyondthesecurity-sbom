# -*- coding: utf-8 -*-
"""Dump paragraph/run structure of the exact boxes we will edit (read-only)."""
import io
import sys

from pptx import Presentation
from pptx.oxml.ns import qn

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PATH = r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx"
pres = Presentation(PATH)


def show_para(p, prefix=""):
    texts = []
    for r in p.findall(qn("a:r")):
        rPr = r.find(qn("a:rPr"))
        bold = rPr is not None and rPr.get("b") == "1"
        sz = rPr.get("sz") if rPr is not None else None
        t = "".join(n.text or "" for n in r.findall(qn("a:t")))
        texts.append("%s%s[%s]" % ("B" if bold else "", sz or "", t))
    brs = len(p.findall(qn("a:br")))
    return "%s p(runs=%d,br=%d): %s" % (prefix, len(p.findall(qn("a:r"))), brs, " ⏎ ".join(texts)[:200])


targets = {
    2: ["통계 카드 1", "통계 카드 2", "출처"],
    6: None,  # all text shapes (find speclint line)
    11: ["Azure ACR", "TextBox 17", "Azure 앱", "Azure Files", "Azure 로그"],
    30: ["Rounded Rectangle 4"],
    32: ["성과 카드 1", "한계 카드", "다음 단계 카드"],
}
for sidx, names in targets.items():
    slide = pres.slides[sidx - 1]
    print("=" * 12, "slide", sidx)
    for shape in slide.shapes:
        if not shape.has_text_frame:
            continue
        if names is not None and shape.name not in names:
            continue
        txt = shape.text_frame.text.strip()
        if names is None and ("speclint" not in txt and "양방향" not in txt):
            continue
        print(" SHAPE [%d] %s" % (shape.shape_id, shape.name))
        for i, p in enumerate(shape.text_frame._txBody.findall(qn("a:p"))):
            print("   " + show_para(p, "  #%d" % i))
