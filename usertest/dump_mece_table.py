# -*- coding: utf-8 -*-
"""Dump the MECE table on slide 33 of the assignment deck (read-only)."""
import io
import sys

from pptx import Presentation

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PATH = r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx"
pres = Presentation(PATH)
slide = pres.slides[32]  # slide 33
for shape in slide.shapes:
    if getattr(shape, "has_table", False):
        tbl = shape.table
        print("TABLE %dx%d" % (len(tbl.rows), len(tbl.columns)))
        for ri, r in enumerate(tbl.rows):
            print("row %d | %s" % (ri, " | ".join(c.text.strip().replace("\n", "⏎")[:60] for c in r.cells)))
