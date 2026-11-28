# -*- coding: utf-8 -*-
"""Export QA PNGs of the updated/new assignment-deck slides via PowerPoint COM."""
import os

import win32com.client

PPTX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "BTS-SBOM_1-6주차_종합_과제.pptx"))
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "deck_render", "assign_qa"))

os.makedirs(OUT, exist_ok=True)
app = win32com.client.Dispatch("PowerPoint.Application")
try:
    pres = app.Presentations.Open(PPTX, WithWindow=False, ReadOnly=True)
    for i in (2, 11, 12, 31, 33, 34, 35):
        pres.Slides(i).Export(os.path.join(OUT, "slide_%02d.png" % i), "PNG", 1280, 720)
    print("exported", pres.Slides.Count, "total slides; QA PNGs for", [2, 11, 12, 31, 33, 34, 35], "->", OUT)
finally:
    pres.Close()
    app.Quit()
