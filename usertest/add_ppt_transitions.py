# -*- coding: utf-8 -*-
"""Add slide transitions (the '동적' part) to the generated deck via PowerPoint COM, then export every slide
as PNG for render QA. pptxgenjs cannot author OOXML transitions; PowerPoint itself can. A fade transition with
a short duration keeps the deck presentable without being gaudy. Advance stays on click (a presenter deck)."""
import os
import sys

import win32com.client

PPTX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "AZURE_OPERATIONS_OVERVIEW.pptx"))
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evidence", "deck_render"))
PP_EFFECT_FADE_SMOOTHLY = 3585

os.makedirs(OUT, exist_ok=True)
app = win32com.client.Dispatch("PowerPoint.Application")
try:
    pres = app.Presentations.Open(PPTX, WithWindow=False)
    n = 0
    for slide in pres.Slides:
        slide.SlideShowTransition.EntryEffect = PP_EFFECT_FADE_SMOOTHLY
        slide.SlideShowTransition.Duration = 0.7
        slide.SlideShowTransition.AdvanceOnClick = True
        slide.SlideShowTransition.AdvanceOnTime = False
        n += 1
    pres.Save()
    for i in range(1, pres.Slides.Count + 1):
        pres.Slides(i).Export(os.path.join(OUT, "slide_%02d.png" % i), "PNG", 1280, 720)
    print("transitions on %d slides; exported %d PNGs to %s" % (n, pres.Slides.Count, OUT))
finally:
    pres.Close()
    app.Quit()
