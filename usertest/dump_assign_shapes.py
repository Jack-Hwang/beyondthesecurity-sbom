# -*- coding: utf-8 -*-
"""Dump per-shape inventory (id, name, pos, size, text) of the assignment deck slides we will clone/update.
Read-only."""
import io
import sys

from pptx import Presentation
from pptx.util import Emu

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PATH = r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx"

pres = Presentation(PATH)
for idx in (2, 11, 30, 31, 32):  # 1-based slide numbers
    slide = pres.slides[idx - 1]
    print("=" * 12, "slide", idx, "layout:", slide.slide_layout.name)
    for shape in slide.shapes:
        try:
            pos = "(%d,%d %dx%d)" % (Emu(shape.left).pt, Emu(shape.top).pt, Emu(shape.width).pt, Emu(shape.height).pt)
        except Exception:
            pos = "(?)"
        txt = ""
        if shape.has_text_frame:
            txt = shape.text_frame.text.strip().replace("\n", " ⏎ ")[:220]
        print("  [%d] %-22s %s %s" % (shape.shape_id, shape.name, pos, txt))
        if getattr(shape, "has_table", False):
            tbl = shape.table
            print("      TABLE %dx%d" % (len(tbl.rows), len(tbl.columns)))
            for r in tbl.rows:
                print("      | " + " | ".join(c.text.strip()[:30] for c in r.cells))
    if slide.has_notes_slide and slide.notes_slide.notes_text_frame is not None:
        print("  NOTES:", slide.notes_slide.notes_text_frame.text.strip()[:200])
