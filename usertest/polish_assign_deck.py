# -*- coding: utf-8 -*-
"""Refresh the course deck's live numbers and cross-references from their sources (idempotent - run after
usertest/integrate_azure_into_assign.py):

  slide 2  stat cards  AC count (specs/*.md) · module count (git ls-files) · tests (optional result file)
  slide 3  version badge                    pyproject version
  slide 6  requirement-class chart + label  python -m bts_sbom_app.speclint (REQ-KINDS)
  slide 8  CLI subcommand count             python -m bts_sbom_app --help
  slide 10 version-line quote               marked as the value at capture time
  MECE table                               the newest lanes named in the cells they belong to
  성과와 한계 stat card                     tests passed / collected (optional result file)

  python -I usertest/polish_assign_deck.py [tests.json]   # tests.json = {"collected": N, "passed": M, "note": "..."}
"""
import copy
import io
import json
import os
import re
import subprocess
import sys

from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.oxml.ns import qn

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DECK = os.path.join(ROOT, "docs", "BTS-SBOM_1-6주차_종합_과제_황병주_20261128.pptx")
PY = [sys.executable, "-m"]


def run(*args):
    return subprocess.run(list(args), cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def num(v):
    return "{:,}".format(v) if isinstance(v, int) else str(v)


# ---- sources ----
spec = "".join(io.open(os.path.join(ROOT, "specs", f), encoding="utf-8").read() for f in os.listdir(os.path.join(ROOT, "specs")) if f.endswith(".md"))
AC = len(re.findall(r"^- BSA-AC-\d+", spec, re.M))
lint = run(*PY, "bts_sbom_app.speclint")
kinds = dict((k, int(v)) for k, v in re.findall(r"([A-Z]+)=(\d+)", (re.search(r"REQ-KINDS (.+?) sfr_default", lint) or re.search(r"REQ-KINDS (.+)", lint)).group(1).strip()))
unk = (re.search(r"unknown ACs: (.+)", lint) or ["", "[]"])[1].strip()
MODS = len([f for f in run("git", "ls-files", "bts_sbom_app").splitlines() if f.endswith(".py")])
VER = (re.search(r'^version\s*=\s*"([^"]+)"', io.open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read(), re.M) or ["", "?"])[1]
help_out = run(*PY, "bts_sbom_app", "--help")
lines = help_out.splitlines()
start = next((i for i, l in enumerate(lines) if "positional arguments" in l or ("{" in l and "}" in l)), 0)
CLI = len([l for l in lines[start:] if re.match(r"^\s{2,}[a-z][a-z0-9-]*\s{2,}\S", l) and "--" not in l.split()[0] and l.split()[0] not in ("h", "help")])
tests = json.load(io.open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else None
print("sources: AC %d %s | unknown refs %s | modules %d | version %s | CLI %d | tests %s" % (AC, kinds, unk, MODS, VER, CLI, tests))

prs = Presentation(DECK)


def title_of(s):
    for sh in s.shapes:
        if sh.name.startswith("Title") or sh.name.startswith("제목"):
            return sh.text_frame.text.replace("\n", " ").replace("\x0b", " ")
    return ""


def slide(sub):
    for s in prs.slides:
        if sub in title_of(s):
            return s
    raise SystemExit("slide not found: " + sub)


def set_par_text(p, text):
    """set a paragraph's text on its first run (keeps formatting), drop the other runs"""
    runs = p.runs
    if not runs:
        p.add_run().text = text
        return
    runs[0].text = text
    for r in runs[1:]:
        r._r.getparent().remove(r._r)


def set_para_xml(p, text):
    r = p.find(qn("a:r"))
    t = r.find(qn("a:t"))
    t.text = text
    for extra in p.findall(qn("a:r"))[1:]:
        p.remove(extra)


# ---- slide 2: stat cards + source line ----
s2 = prs.slides[1]
for sh in s2.shapes:
    if not sh.has_text_frame:
        continue
    paras = sh.text_frame.paragraphs
    if len(paras) >= 2 and paras[0].text.strip().replace(",", "").isdigit():
        label = paras[1].text
        if "수용 기준" in label:
            set_par_text(paras[0], num(AC))
            set_par_text(paras[2], "EARS 문장 + 측정 수치 · 분류 %s" % " ".join("%s %d" % (k, kinds[k]) for k in ("SFR", "SIR", "DAR", "SECR", "CONR", "PER") if k in kinds))
        elif "파이썬 모듈" in label:
            set_par_text(paras[0], num(MODS))
        elif "자동 테스트" in label and tests:
            set_par_text(paras[0], num(tests["collected"]))
            set_par_text(paras[2], tests.get("note", ""))
    if sh.text_frame.text.startswith("수치 출처:"):
        set_par_text(sh.text_frame.paragraphs[0], "수치 출처: specs AC %d건 · git ls-files 모듈 %d개 · speclint 미등록 참조 %s · 패키지 v%s · 2026-11-28 최종 점검" % (AC, MODS, unk, VER))

# ---- slide 3: version badge ----
for sh in prs.slides[2].shapes:
    if sh.has_text_frame and sh.text_frame.text.strip() == "v0.5.0":
        set_par_text(sh.text_frame.paragraphs[0], "v" + VER)

# ---- slide 6: class chart + label + notes ----
s6 = slide("요구사항은 EARS")
for sh in s6.shapes:
    if sh.has_text_frame and "수용 기준" in sh.text_frame.text and re.search(r"\d{3}개", sh.text_frame.text):
        set_par_text(sh.text_frame.paragraphs[0], re.sub(r"\d{3}개", "%d개" % AC, sh.text_frame.paragraphs[0].text))
    if getattr(sh, "has_chart", False) and sh.has_chart:
        ch = sh.chart
        cats = [str(c) for c in ch.plots[0].categories]
        vals = [kinds.get(c.split()[0], None) for c in cats]
        if None not in vals:
            cd = CategoryChartData()
            cd.categories = cats
            cd.add_series(list(ch.series)[0].name, vals)
            ch.replace_data(cd)
            print("chart %s -> %s" % (cats, vals))
s6.notes_slide.notes_text_frame.text = ("speclint(2026-11-28 최종 점검): REQ-KINDS %s total=%d, 테스트 없는 AC 0, 미등록 AC 참조 %s."
                                        % (" ".join("%s=%d" % kv for kv in kinds.items()), AC, unk))

# ---- slide 8: CLI subcommand count ----
for sh in slide("아키텍처 ①").shapes:
    if sh.has_text_frame and re.search(r"CLI \d+개 명령", sh.text_frame.text):
        for p in sh.text_frame.paragraphs:
            for r in p.runs:
                r.text = re.sub(r"CLI \d+개 명령", "CLI %d개 명령" % CLI, r.text)

# ---- slide 10: the quoted version line is the value at capture time ----
for sh in slide("아키텍처 ③").shapes:
    if sh.has_text_frame and "app 0.5.0" in sh.text_frame.text and "캡처 당시" not in sh.text_frame.text:
        for p in sh.text_frame.paragraphs:                 # the quote is split across runs: mark the run that names it
            for r in p.runs:
                if "버전 표기" in r.text and "캡처 당시" not in r.text:
                    r.text = r.text.replace("버전 표기", "버전 표기(캡처 당시 값 · 현재 v%s)" % VER, 1)

# ---- MECE table: name the newest lanes ----
tbl = [sh for sh in slide("MECE 종합").shapes if getattr(sh, "has_table", False)][0].table
CELLS = {  # (row, col, old substring, new text of that paragraph)
    (3, 5): ("감사 표본", "프롬프트 핀 · 6게이트 · AI 영향 평가"),
    (4, 6): ("A2UI 카드", "영어 질의 · PII 메모리 · A2UI · 하네스·가드레일"),
    (5, 6): ("Git 전략", "토큰 게이트 · MI 풀 · GitOps"),
}
for (r, c), (old, new) in CELLS.items():
    cell = tbl.cell(r, c)
    done = False
    for p in cell.text_frame._txBody.findall(qn("a:p")):
        txt = "".join(t.text or "" for t in p.iter(qn("a:t")))
        if new in txt:
            done = True
        elif old in txt:
            set_para_xml(p, new)
            done = True
    if not done:
        print("MECE cell (%d,%d): neither %r nor the new text found - left as is" % (r, c, old))

# ---- 성과와 한계: test stat ----
if tests:
    for sh in slide("성과와 한계").shapes:
        if sh.has_text_frame and re.match(r"^[\d,]+ / [\d,]+$", sh.text_frame.paragraphs[0].text.strip()):
            set_par_text(sh.text_frame.paragraphs[0], "%s / %s" % (num(tests["passed"]), num(tests["collected"])))
            set_par_text(sh.text_frame.paragraphs[1], tests.get("card", "자동 테스트(최종 점검 실측)"))

prs.save(DECK)
print("polished:", os.path.relpath(DECK, ROOT), "| slides", len(prs.slides))
