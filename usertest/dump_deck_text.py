# -*- coding: utf-8 -*-
"""Dump per-slide text of both decks for the coverage gap analysis (read-only)."""
import io
import sys

from pptx import Presentation

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def dump(path, label):
    print("=" * 20, label, path)
    pres = Presentation(path)
    for i, slide in enumerate(pres.slides, 1):
        texts = []
        for shape in slide.shapes:
            if shape.has_text_frame:
                t = shape.text_frame.text.strip()
                if t:
                    texts.append(t.replace("\n", " | ")[:400])
            elif shape.shape_type == 13:  # picture
                texts.append("[그림]")
            elif getattr(shape, "has_table", False):
                texts.append("[표]")
        notes = ""
        if slide.has_notes_slide and slide.notes_slide.notes_text_frame is not None:
            notes = slide.notes_slide.notes_text_frame.text.strip().replace("\n", " ")[:300]
        print("--- slide %d: %s" % (i, "  ///  ".join(texts)[:1200]))
        if notes:
            print("    (notes) %s" % notes)


dump(r"C:\firebaseprojects\beyondthesecurity-sbom\docs\AZURE_OPERATIONS_OVERVIEW.pptx", "AZURE OPS")
dump(r"C:\firebaseprojects\beyondthesecurity-sbom\docs\BTS-SBOM_1-6주차_종합_과제.pptx", "ASSIGN 1-6")
