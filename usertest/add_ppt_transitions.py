# -*- coding: utf-8 -*-
"""Post-process the architect deck (docs/AZURE_OPERATIONS_OVERVIEW.pptx) through PowerPoint COM:

1. slide transitions (fade) on every slide                          - the "동적" baseline
2. entrance effects for the build groups in evidence/deck_render/v2/builds.json (written by the build):
   first shape of a group = AfterPrevious (auto-plays after the slide appears), the rest = WithPrevious;
   lines wipe, everything else fades                              - the diagrams build themselves step by step
3. export every slide to PNG (evidence/deck_render/v2/slide_NN.png) + 2x2 contact sheets for visual QA
4. OVERFLOW GATE: for every text shape compare PowerPoint's own laid-out text height (BoundHeight) with the
   shape height; also flag shapes outside the slide. Non-zero exit when anything overflows.

pptxgenjs cannot author OOXML transitions/timelines, so PowerPoint itself does it. Run after the build:
  python -I usertest/add_ppt_transitions.py
"""
import io
import json
import os
import sys

import win32com.client

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PPTX = os.path.join(ROOT, "docs", "AZURE_OPERATIONS_OVERVIEW.pptx")
OUT = os.path.join(ROOT, "evidence", "deck_render", "v2")
MANIFEST = os.path.join(OUT, "builds.json")

PP_EFFECT_FADE_SMOOTHLY = 3585
MSO_ANIM_FADE, MSO_ANIM_WIPE = 10, 22
TRIGGER_ON_CLICK, TRIGGER_WITH_PREVIOUS, TRIGGER_AFTER_PREVIOUS = 1, 2, 3
OVERFLOW_TOL_PT = 2.0

os.makedirs(OUT, exist_ok=True)
with open(MANIFEST, encoding="utf-8") as fh:
    manifest = {rec["slide"]: rec for rec in json.load(fh)}

app = win32com.client.Dispatch("PowerPoint.Application")
STARTED_EMPTY = app.Presentations.Count == 0          # never quit a PowerPoint the user has open
report = {"slides": 0, "transitions": 0, "effects": 0, "overflow": [], "offslide": [], "effect_readback": {}}
try:
    pres = app.Presentations.Open(PPTX, WithWindow=False)
    sw, sh = pres.PageSetup.SlideWidth, pres.PageSetup.SlideHeight
    report["slides"] = pres.Slides.Count
    for i in range(1, pres.Slides.Count + 1):
        slide = pres.Slides(i)
        tr = slide.SlideShowTransition
        tr.EntryEffect = PP_EFFECT_FADE_SMOOTHLY
        tr.Duration = 0.6
        tr.AdvanceOnClick = True
        tr.AdvanceOnTime = False
        report["transitions"] += 1
        rec = manifest.get(i)
        if rec and rec["shapes"]:
            seq = slide.TimeLine.MainSequence
            while seq.Count:  # idempotent: never stack effects on top of an earlier run
                seq(1).Delete()
            groups = {}
            for s in rec["shapes"]:
                groups.setdefault(s["b"], []).append(s)
            for b in sorted(groups):
                for k, s in enumerate(sorted(groups[b], key=lambda x: x["i"])):
                    shape = slide.Shapes(s["i"])
                    trig = TRIGGER_AFTER_PREVIOUS if k == 0 else TRIGGER_WITH_PREVIOUS
                    eff = seq.AddEffect(shape, MSO_ANIM_WIPE if s["line"] else MSO_ANIM_FADE, 0, trig, -1)
                    eff.Timing.Duration = 0.3
                    if k == 0:
                        eff.Timing.TriggerDelayTime = 0.25
                    report["effects"] += 1
            report["effect_readback"][i] = {"expected": len(rec["shapes"]), "count": seq.Count}
    pres.Save()
    # ---- export + overflow gate (re-read after save so the gate sees the saved file) ----
    for i in range(1, pres.Slides.Count + 1):
        slide = pres.Slides(i)
        slide.Export(os.path.join(OUT, "slide_%02d.png" % i), "PNG", 1280, 720)
        for shape in slide.Shapes:
            try:
                if shape.Left < -1 or shape.Top < -1 or shape.Left + shape.Width > sw + 1 or shape.Top + shape.Height > sh + 1:
                    report["offslide"].append({"slide": i, "shape": shape.Name})
                if shape.HasTextFrame and shape.TextFrame.HasText:
                    tr2 = shape.TextFrame2.TextRange
                    over = tr2.BoundHeight - shape.Height
                    if over > OVERFLOW_TOL_PT:
                        report["overflow"].append({"slide": i, "shape": shape.Name, "over_pt": round(over, 1),
                                                   "box_pt": round(shape.Height, 1), "text_pt": round(tr2.BoundHeight, 1),
                                                   "text": tr2.Text[:40]})
            except Exception as exc:  # a shape type that cannot report text bounds
                report.setdefault("errors", []).append({"slide": i, "shape": shape.Name, "err": str(exc)[:80]})
    total = pres.Slides.Count
finally:
    pres.Close()
    if STARTED_EMPTY:
        app.Quit()

# ---- contact sheets (2x2) for visual QA ----
from PIL import Image  # noqa: E402

names = sorted(n for n in os.listdir(OUT) if n.startswith("slide_") and n.endswith(".png"))
cw, chh = 960, 540
sheets = 0
for s in range(0, len(names), 4):
    sheet = Image.new("RGB", (cw * 2, chh * 2), (20, 24, 32))
    for j, n in enumerate(names[s:s + 4]):
        im = Image.open(os.path.join(OUT, n)).convert("RGB").resize((cw, chh), Image.LANCZOS)
        sheet.paste(im, ((j % 2) * cw, (j // 2) * chh))
    sheets += 1
    sheet.save(os.path.join(OUT, "sheet_%02d.png" % sheets), optimize=True)

with open(os.path.join(OUT, "qa_report.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=1)
bad_readback = {k: v for k, v in report["effect_readback"].items() if v["expected"] != v["count"]}
print("slides %d · transitions %d · entrance effects %d (readback mismatch: %s)" % (
    report["slides"], report["transitions"], report["effects"], bad_readback or "none"))
print("exported %d PNGs · %d contact sheets -> %s" % (len(names), sheets, os.path.relpath(OUT, ROOT)))
print("OFF-SLIDE shapes: %d" % len(report["offslide"]))
for o in report["offslide"][:20]:
    print("   s%d %s" % (o["slide"], o["shape"]))
print("OVERFLOWING text shapes: %d" % len(report["overflow"]))
for o in report["overflow"]:
    print("   s%-2d %-14s over %5.1fpt  (box %5.1f / text %5.1f)  «%s»" % (o["slide"], o["shape"], o["over_pt"], o["box_pt"], o["text_pt"], o["text"]))
if "errors" in report:
    print("errors: %d (first: %s)" % (len(report["errors"]), report["errors"][:2]))
sys.exit(1 if (report["overflow"] or report["offslide"] or bad_readback) else 0)
