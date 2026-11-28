# -*- coding: utf-8 -*-
"""Export EVERY slide of the course deck to PNG + 2x3 contact sheets, and run the layout gate (PowerPoint's own
text bounds / off-slide shapes) across the whole deck. Read-only.

If the deck is open in the user's PowerPoint, that open presentation is used and left open; otherwise a
read-only copy is opened and closed, and a PowerPoint started by this script is quit (never the user's).

  python -I usertest/export_deck_sheets.py
"""
import io
import os
import sys

import win32com.client
from PIL import Image

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DECK = os.path.join(ROOT, "docs", "BTS-SBOM_1-6주차_종합_과제.pptx")
OUT = os.path.join(ROOT, "evidence", "deck_render", "assign_v2", "full")
os.makedirs(OUT, exist_ok=True)
for n in os.listdir(OUT):
    if n.endswith(".png"):
        os.remove(os.path.join(OUT, n))

app, pres, mine = win32com.client.Dispatch("PowerPoint.Application"), None, False
was_empty = app.Presentations.Count == 0
try:
    for p in app.Presentations:
        if os.path.abspath(p.FullName) == os.path.abspath(DECK):
            pres = p
    if pres is None:
        pres = app.Presentations.Open(DECK, WithWindow=False, ReadOnly=True)
        mine = True
    sw, sh = pres.PageSetup.SlideWidth, pres.PageSetup.SlideHeight
    over, off, total = [], [], pres.Slides.Count
    for i in range(1, total + 1):
        slide = pres.Slides(i)
        slide.Export(os.path.join(OUT, "slide_%02d.png" % i), "PNG", 1280, 720)
        for shape in slide.Shapes:
            if shape.Left < -1 or shape.Top < -1 or shape.Left + shape.Width > sw + 1 or shape.Top + shape.Height > sh + 1:
                off.append((i, shape.Name))
            if shape.HasTextFrame and shape.TextFrame.HasText and shape.TextFrame2.TextRange.BoundHeight - shape.Height > 2:
                over.append((i, shape.Name, round(shape.TextFrame2.TextRange.BoundHeight - shape.Height, 1), shape.TextFrame2.TextRange.Text[:24]))
finally:
    if mine:
        pres.Close()
    if was_empty and app.Presentations.Count == 0:
        app.Quit()

names = sorted(n for n in os.listdir(OUT) if n.startswith("slide_") and n.endswith(".png"))
cw, ch = 800, 450
for s in range(0, len(names), 6):
    sheet = Image.new("RGB", (cw * 2, ch * 3), (20, 24, 32))
    for j, n in enumerate(names[s:s + 6]):
        sheet.paste(Image.open(os.path.join(OUT, n)).convert("RGB").resize((cw, ch), Image.LANCZOS), ((j % 2) * cw, (j // 2) * ch))
    sheet.save(os.path.join(OUT, "sheet_%02d.png" % (s // 6 + 1)), optimize=True)
print("exported %d slides · %d sheets -> %s" % (len(names), (len(names) + 5) // 6, os.path.relpath(OUT, ROOT)))
print("gate: off-slide %d %s · overflowing text %d" % (len(off), off[:8], len(over)))
for o in over[:30]:
    print("   s%-2d %-16s over %5.1fpt  «%s»" % o)
sys.exit(1 if (over or off) else 0)
