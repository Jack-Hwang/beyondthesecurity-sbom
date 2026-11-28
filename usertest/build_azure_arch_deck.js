// build_azure_arch_deck.js — renders the architect deck (v2) from ONE content model into BOTH media:
//   docs/AZURE_OPERATIONS_OVERVIEW.pptx  (pptxgenjs; transitions + entrance effects are added afterwards by
//                                         usertest/add_ppt_transitions.py via PowerPoint COM)
//   docs/AZURE_OPERATIONS_OVERVIEW.html  (self-contained: inline CSS/JS, icons as data URIs, build steps,
//                                         keyboard/click navigation, notes overlay)
//   evidence/deck_render/v2/builds.json  (per-slide shape index -> build group, for the COM effects)
// Run: NODE_PATH="C:\Users\Administrator\.npm-global\node_modules" node usertest/build_azure_arch_deck.js
//
// Design: every slide is a list of primitives (rect / text / line / image) on a 1280x720 px stage. The two
// backends only differ in how a primitive is drawn, so PPT and HTML cannot drift apart in content.
// Line height is exact points in PPT (spcPts) and exact px in HTML, so both wrap almost identically.
// A text-height estimator warns at build time; the COM script is the real overflow gate (BoundHeight).
"use strict";
const pptxgen = require("pptxgenjs");
const fs = require("fs");
const path = require("path");
// --assign : render the content-only slides that get transplanted into the course assignment deck
// (docs/BTS-SBOM_1-6주차_종합_과제.pptx) by usertest/integrate_azure_into_assign.py. Default: the architect deck.
const ASSIGN = process.argv.includes("--assign");
const MODEL = require(ASSIGN ? "./azure_arch_integration.model.js" : "./azure_arch_deck.model.js");

const ROOT = path.join(__dirname, "..");
const ICON_DIR = path.join(__dirname, "azure_icons", "official");
const OUT_PPTX = path.join(ROOT, "docs", "AZURE_OPERATIONS_OVERVIEW.pptx");
const OUT_HTML = path.join(ROOT, "docs", "AZURE_OPERATIONS_OVERVIEW.html");
const OUT_DIR = path.join(ROOT, "evidence", "deck_render", "v2");
const OUT_MANIFEST = path.join(OUT_DIR, "builds.json");

const W = 1280, H = 720, IN = 1 / 96;
const C = { az: "0078D4", azDark: "005A9E", dark: "0F1B2D", ink: "1F2430", sub: "5A6472", line: "D8DEE9",
  panel: "F6F8FB", ok: "107C41", warn: "B36A00", gap: "C50F1F", white: "FFFFFF", hi: "E5F1FB" };
const TAG = { M: { label: "측정", color: "0078D4" }, I: { label: "추론", color: "B36A00" }, G: { label: "갭", color: "C50F1F" } };
const TONE = {
  info: { fill: "F3F8FD", line: "B9D7F0", accent: "0078D4" },
  ok: { fill: "F1F9F3", line: "B7DFC2", accent: "107C41" },
  warn: { fill: "FFF7E8", line: "F0D49A", accent: "B36A00" },
  gap: { fill: "FDF1F0", line: "F2B8B5", accent: "C50F1F" },
  hi: { fill: "E5F1FB", line: "0078D4", accent: "0078D4" },
  outer: { fill: "FFFFFF", line: "9AA4B2", accent: "5A6472" },
  plain: { fill: "F6F8FB", line: "D8DEE9", accent: "5A6472" },
};
const FONT = "Malgun Gothic";
const warnings = [];
const warn = (msg) => warnings.push(msg);

// ---------- layer coverage check: the model's partition must cover the real directory exactly ----------
let realMods = 0;
(function checkLayers() {
  // counted = COMMITTED modules (git ls-files): a parallel lane may have uncommitted modules in the working
  // tree, and a deck must not quote a number that changes with someone else's in-progress work.
  const real = require("child_process").execSync("git ls-files bts_sbom_app", { cwd: ROOT, encoding: "utf8" })
    .split(String.fromCharCode(10)).filter((f) => f.endsWith(".py")).map((f) => f.replace(/^.*\//, "").replace(/\.py$/, ""));
  const seen = new Map();
  for (const L of MODEL.LAYERS) for (const m of L.mods) seen.set(m, (seen.get(m) || 0) + 1);
  const dup = [...seen].filter(([, n]) => n > 1).map(([m]) => m);
  const missing = real.filter((m) => !seen.has(m));
  const ghost = [...seen.keys()].filter((m) => !real.includes(m));
  if (dup.length || missing.length || ghost.length) {
    throw new Error("layer partition mismatch: dup=" + dup + " missing=" + missing + " ghost=" + ghost);
  }
  realMods = real.length;
  console.log("layer check ok: %d tracked modules, every committed .py in exactly one layer", real.length);
})();

// ---------- text estimation ----------
function charW(ch, s) {
  const c = ch.codePointAt(0);
  if (ch === " ") return 0.30 * s;
  if (c >= 0xAC00 && c <= 0xD7A3) return 1.03 * s;                   // Hangul syllable
  if (c >= 0x3000 && c <= 0x303F) return 1.0 * s;                    // CJK punctuation
  if ((c >= 0x2000 && c <= 0x27BF) || c >= 0xFF00) return 0.92 * s;  // arrows, math, fullwidth forms
  if (ch >= "0" && ch <= "9") return 0.60 * s;
  if (ch >= "A" && ch <= "Z") return 0.70 * s;
  return 0.58 * s;
}
// width in PX of a run list at font size s (pt): charW is in em x pt, and 1pt = 4/3 px
const runsW = (runs, s) => runs.reduce((a, r) => a + [...r.t].reduce((b, ch) => b + charW(ch, (r.size || 1) * s) * (r.bold ? 1.06 : 1), 0), 0) * (4 / 3);
function parsePara(str) {
  const m = /^\[(M|I|G)\]\s*(.*)$/.exec(str);
  if (!m) return { runs: [{ t: str }], bullet: false };
  return { runs: [{ t: TAG[m[1]].label + " ", chip: m[1], bold: true, color: TAG[m[1]].color, size: 0.88 }, { t: m[2], bold: false, size: 1 }], bullet: false };
}
function estParas(paras, w, size, lh) {
  let h = 0, lines = 0;
  for (const p of paras) {
    const need = runsW(p.runs, size);
    const n = Math.max(1, Math.ceil(need / Math.max(20, w - 8 - (p.bullet ? 15 : 0)) - 0.03));
    lines += n;
    h += n * lh + (p.gapBefore || 0);
  }
  return { h, lines };
}

// ---------- primitive engine ----------
function newStage(def, n, total) {
  const st = { def, n, total, prims: [], idx: 0, maxBuild: 0 };
  const ox = () => st.ox || 0, oy = () => st.oy || 0;
  st.rect = (x, y, w, h, o = {}) => { st.prims.push({ k: "rect", i: ++st.idx, x: x + ox(), y: y + oy(), w, h, ...o }); };
  st.img = (key, x, y, w, h) => { st.prims.push({ k: "img", i: ++st.idx, key, x: x + ox(), y: y + oy(), w, h }); };
  st.line = (pts, o = {}) => { st.prims.push({ k: "line", i: ++st.idx, pts: pts.map(([x, y]) => [x + ox(), y + oy()]), ...o }); };
  st.text = (x, y, w, h, content, o = {}) => {
    const size = o.size || 10.5;                               // pt
    const lh = o.lh || size * (4 / 3) * 1.2;                   // px per line
    x += ox(); y += oy();
    const arr = Array.isArray(content) ? content : [content];
    const paras = arr.map((c, i) => {
      const p = typeof c === "string" ? parsePara(c) : { ...c };
      if (o.bullet && !("bullet" in c)) p.bullet = true;
      if (o.gap && i > 0) p.gapBefore = o.gap;
      p.runs = p.runs.map((r) => ({ t: r.t, chip: r.chip, bold: !!r.bold || !!o.bold, color: r.color || o.color || C.ink, size: r.size || 1 }));
      return p;
    });
    const e = estParas(paras, w, size, lh);
    const minH = Math.max(e.h, size * 2.6);                         // natural height of ONE tall line
    if (h < minH) { const extra = minH - h; if (o.valign === "middle") y -= extra / 2; h = minH; }
    if (!o.nocheck && e.h > h + 1.5) warn(`s${st.n} text est ${e.h.toFixed(0)}px > box ${h.toFixed(0)}px «${(paras[0].runs[0].t || "").slice(0, 34)}»`);
    st.prims.push({ k: "text", i: ++st.idx, x, y, w, h, paras, size, lh, ...o });
    return e;
  };
  return st;
}
// tag every primitive added inside fn with build group b
function group(st, b, fn) {
  const n0 = st.prims.length;
  fn();
  for (let i = n0; i < st.prims.length; i++) st.prims[i].b = b || 0;
  if (b) st.maxBuild = Math.max(st.maxBuild, b);
}

// ---------- shared chrome ----------
function chrome(st) {
  const d = st.def, dark = d.kind === "cover" || d.kind === "end";
  st.dark = dark;
  if (dark) { st.rect(0, 0, W, H, { fill: C.dark, bg: true }); return; }
  st.rect(0, 0, W, H, { fill: C.white, bg: true });
  st.rect(0, 0, 210, 6, { fill: C.az });
  st.rect(210, 0, W - 210, 6, { fill: "E3EBF4" });
  if (d.sec) {
    const cw = runsW(parsePara(d.sec).runs, 11) + 30;
    st.rect(W - 36 - cw, 16, cw, 28, { fill: C.az, radius: 14 });
    st.text(W - 36 - cw, 16, cw, 28, d.sec, { size: 11, bold: true, color: C.white, align: "center", valign: "middle", lh: 15 });
  }
  let ts = 24;                                                   // title: largest size that fits one line
  for (; ts > 16; ts -= 0.5) if (runsW(parsePara(d.title).runs, ts) <= 985) break;
  st.text(36, 28, 1020, 52, d.title, { size: Math.max(16.5, ts), bold: true, color: C.ink, valign: "middle", lh: Math.max(16.5, ts) * 1.5 });
  if (d.sub) st.text(36, 82, 1160, 28, d.sub, { size: 12.5, color: C.sub, valign: "middle", lh: 17 });
  st.text(36, 690, 700, 18, "BTS-SBOM · Azure 운영 아키텍처 · 아키텍트 에디션 v2 · 2026-11-28 실측 · ■측정 ■추론 ■갭", { size: 8.5, color: "9AA4B2", lh: 12 });
  st.text(560, 690, 440, 18, "← → 키 · 구성도는 단계별 등장 · N 출처(HTML)", { size: 8.5, color: "9AA4B2", align: "center", lh: 12 });
  st.text(W - 36 - 120, 690, 120, 18, `${st.n} / ${st.total}`, { size: 9.5, color: "9AA4B2", align: "right", lh: 12 });
}
function verdictBar(st) {
  const v = st.def.verdict;
  if (!v) return 672;
  const x = 36, y = 646, w = W - 72, h = 40;
  st.rect(x, y, w, h, { fill: "FFF7E8", line: "F0D49A", lw: 1, radius: 8 });
  st.rect(x, y, 6, h, { fill: C.warn });
  st.text(x + 16, y, 96, h, "아키텍트 판단", { size: 10.5, bold: true, color: C.warn, valign: "middle", lh: 14 });
  st.text(x + 118, y, w - 134, h, v, { size: 11, color: "4A3A1A", valign: "middle", lh: 15.5 });
  return y - 6;
}
function kpiStrip(st, kpis, y) {
  const n = kpis.length, gap = 12, w = (W - 72 - gap * (n - 1)) / n;
  kpis.forEach((k, i) => {
    const x = 36 + i * (w + gap), tone = TONE[k.tone || "info"];
    st.rect(x, y, w, 58, { fill: tone.fill, line: tone.line, lw: 1, radius: 8 });
    const vs = String(k.v).length >= 5 ? 19 : 23;
    st.text(x + 12, y + 4, w * 0.40, 32, [{ runs: [{ t: k.v, bold: true, size: 1 }, { t: k.u ? " " + k.u : "", bold: true, size: 0.55, color: C.sub }] }],
      { size: vs, color: tone.accent, valign: "bottom", lh: vs * 1.3 });
    st.text(x + 14 + w * 0.40, y + 5, w * 0.58 - 14, 22, k.label, { size: 10.5, bold: true, color: C.ink, valign: "middle", lh: 14 });
    st.text(x + 14 + w * 0.40, y + 27, w * 0.58 - 14, 29, k.note, { size: 8.5, color: C.sub, lh: 11.5 });
  });
  return y + 58;
}
const P = (arr) => arr.map((s) => (typeof s === "string" ? parsePara(s) : s));
function card(st, x, y, w, h, c) {
  const tone = TONE[c.tone || "plain"];
  group(st, c.b, () => {
    st.rect(x, y, w, h, { fill: tone.fill, line: tone.line, lw: 1.25, radius: 10 });
    st.rect(x, y, 5, h, { fill: tone.accent });
    let tx = x + 18;
    if (c.icon) { st.img(c.icon, x + 14, y + 12, 26, 26); tx = x + 48; }
    st.text(tx, y + 10, w - (tx - x) - 14, 28, c.title, { size: 13, bold: true, color: C.ink, valign: "middle", lh: 17.5 });
    st.text(x + 18, y + 42, w - 30, h - 52, P(c.lines), { size: 10.5, bullet: true, lh: 16 });
  });
}
const cardNeed = (c, w) => 54 + estParas(P(c.lines).map((p) => ({ ...p, bullet: true })), w - 30, 10.5, 16).h;
// a two-column "measured facts" block: label | value(s). Fills a slide's lower half with substance
// (SLO proposals, scenario comparison, cost of fixes) instead of decoration.
function factsTable(st, y, y1, rows, title) {
  const lw = 250, x = 36, w = W - 72, fs = 10.5, lh = 16.5;
  let yy = y;
  if (title) { st.text(x, yy, w, 24, title, { size: 11.5, bold: true, color: C.ink, valign: "middle", lh: 15.5 }); yy += 28; }
  rows.forEach((r, i) => {
    const vals = (Array.isArray(r[1]) ? r[1] : [r[1]]).map((s) => parsePara(s));
    const rh = Math.max(34, estParas(vals, w - lw - 28, fs, lh).h + 14);
    if (yy + rh > y1 + 1) warn(`s${st.n} facts row ${i + 1}: bottom ${(yy + rh).toFixed(0)} > ${y1}`);
    st.rect(x, yy, w, rh, { fill: i % 2 ? "F7F9FC" : "EEF3F9", radius: 6 });
    st.rect(x, yy, 4, rh, { fill: i % 2 ? "B9D7F0" : C.az });
    st.text(x + 14, yy, lw - 18, rh, r[0], { size: 10.5, bold: true, color: C.ink, valign: "middle", lh });
    st.text(x + lw, yy, w - lw - 16, rh, vals, { size: fs, valign: "middle", lh, color: "2E3440" });
    yy += rh + 4;
  });
  return yy;
}

// ---------- renderers ----------
const R = {};

R.cover = (st) => {
  const d = st.def, icons = d.icons || [], iw = 64, gap = 40, total = icons.length * iw + (icons.length - 1) * gap;
  icons.forEach((k, i) => st.img(k, (W - total) / 2 + i * (iw + gap), 92, iw, iw));
  st.text(0, 212, W, 70, d.title, { size: 40, bold: true, color: C.white, align: "center", valign: "middle", lh: 54 });
  st.text(0, 290, W, 50, d.big, { size: 27, bold: true, color: "7FC4F5", align: "center", valign: "middle", lh: 36 });
  st.text(120, 352, W - 240, 60, d.sub, { size: 14.5, color: "C9D4E3", align: "center", lh: 20 });
  st.rect(W / 2 - 60, 430, 120, 3, { fill: C.az });
  d.meta.forEach((m, i) => st.text(120, 452 + i * 26, W - 240, 24, m, { size: 11, color: "8E9AB0", align: "center", lh: 16 }));
  st.text(0, 668, W, 20, "아이콘: Microsoft Azure 아키텍처 아이콘(V25) · 모든 수치는 2026-11-28 실측 · 판단은 추론 태그", { size: 8.5, color: "5D6A80", align: "center", lh: 12 });
};

R.cards = (st, y0, y1, colsIn) => {
  const d = st.def, cards = d.cards, cols = colsIn || d.cols || (cards.length <= 4 ? cards.length : 3), gap = 14;
  let stripH = 0;
  if (d.strip) stripH = 20 + d.strip.reduce((a, s) => a + estParas([parsePara(s)], W - 72 - 60, 10.5, 17.5).h + 3, 0);
  const avail = y1 - y0 - (d.strip ? stripH + 12 : 0);
  const rows = Math.ceil(cards.length / cols), rowMax = (avail - gap * (rows - 1)) / rows;
  const cw0 = (W - 72 - gap * (cols - 1)) / cols;
  const meas = cards.map((c) => cardNeed(c, cw0));
  let y = y0;
  for (let r = 0; r < rows; r++) {
    const inRow = cards.slice(r * cols, r * cols + cols), count = inRow.length;
    const cw = (W - 72 - gap * (count - 1)) / count;
    const need = Math.max(...meas.slice(r * cols, r * cols + count));
    const ch = Math.min(rowMax, Math.max(need, 84));
    if (need > rowMax + 1) warn(`s${st.n} cards row ${r + 1}: need ${need.toFixed(0)} > ${rowMax.toFixed(0)}`);
    const x0 = 36 + (W - 72 - (count * cw + gap * (count - 1))) / 2;
    inRow.forEach((c, j) => card(st, x0 + j * (cw + gap), y, cw, ch, c));
    y += ch + gap;
  }
  if (d.facts) factsTable(st, y + 8, d.strip ? y1 - stripH - 12 : y1, d.facts, d.factsTitle);
  if (d.strip) {
    const sy = y1 - stripH;
    st.rect(36, sy, W - 72, stripH, { fill: "EEF4FB", line: "B9D7F0", lw: 1, radius: 8 });
    st.text(56, sy + 8, W - 72 - 40, stripH - 12, P(d.strip), { size: 10.5, bullet: true, lh: 17.5, gap: 3 });
  }
};

R.legend = (st, y0, y1) => {
  const d = st.def, lw = 548, lh = y1 - y0;
  st.rect(36, y0, lw, lh, { fill: C.panel, line: C.line, lw: 1, radius: 10 });
  st.text(56, y0 + 14, lw - 40, 30, "세 가지 표기 — 이 덱의 읽기 계약", { size: 14, bold: true, color: C.ink, lh: 19 });
  const rh = (lh - 64) / 3;
  d.legend.forEach((l, i) => {
    const t = TAG[l.tag], y = y0 + 54 + i * rh;
    st.rect(56, y, 74, 28, { fill: t.color, radius: 14 });
    st.text(56, y, 74, 28, l.t, { size: 12, bold: true, color: C.white, align: "center", valign: "middle", lh: 16 });
    st.text(144, y - 2, lw - 100, rh - 6, l.d, { size: 11, color: C.ink, lh: 16 });
  });
  const mx = 36 + lw + 16, mw = W - 36 - mx;
  st.rect(mx, y0, mw, lh, { fill: C.white, line: C.line, lw: 1, radius: 10 });
  st.text(mx + 20, y0 + 12, mw - 40, 28, `덱 지도 — ${st.total}장, 6개 섹션`, { size: 14, bold: true, color: C.ink, lh: 19 });
  const mrh = (lh - 56) / d.map.length;
  d.map.forEach((r, i) => {
    const y = y0 + 48 + i * mrh;
    if (i) st.line([[mx + 16, y], [mx + mw - 16, y]], { color: C.line, lw: 0.75 });
    st.rect(mx + 20, y + 8, 26, 26, { fill: C.az, radius: 13 });
    st.text(mx + 20, y + 8, 26, 26, r[0], { size: 11.5, bold: true, color: C.white, align: "center", valign: "middle", lh: 15 });
    st.text(mx + 56, y + 6, 250, 20, r[1], { size: 11.5, bold: true, color: C.ink, valign: "middle", lh: 15 });
    st.text(mx + 306, y + 6, 74, 20, r[2] + "장", { size: 10, bold: true, color: C.az, valign: "middle", lh: 14 });
    st.text(mx + 56, y + 27, mw - 76, mrh - 28, r[3], { size: 9.5, color: C.sub, lh: 13 });
  });
};

R.table = (st, y0, y1, dIn, noFacts) => {
  const d = dIn || st.def, fs = d.fs || 10.5, lh = fs * (4 / 3) * 1.2 + 1.5;
  const tx = d.x != null ? d.x : 36, tw = d.w != null ? d.w : W - 72, tr = tx + tw;
  const cols = d.cols, sum = cols.reduce((acc, c) => acc + c.w, 0);
  const ws = cols.map((c) => tw * c.w / sum);
  const xs = [tx, ...ws.slice(0, -1)].map((_, j, arr) => arr.slice(0, j + 1).reduce((s, w) => s + w, 0));   // column left edges
  const hh = 28;
  st.rect(tx, y0, tw, hh, { fill: C.az });
  cols.forEach((c, j) => st.text(xs[j] + 10, y0, ws[j] - 20, hh, c.t, { size: fs + 0.5, bold: true, color: C.white, valign: "middle", lh }));
  let y = y0 + hh;
  d.rows.forEach((row, i) => {
    const cells = Array.isArray(row) ? row : row.row;
    let icon = null;
    const parsed = cells.map((s, j) => {
      const im = /^\[icon:([a-z_]+)]\s*/.exec(s);
      if (im && j === 0 && d.icons !== false) { icon = im[1]; s = s.slice(im[0].length); }
      return { p: parsePara(s), w: ws[j] - 20 - (j === 0 && icon ? 30 : 0) };
    });
    const rh = Math.max(fs * 2.75, Math.max(...parsed.map((c) => estParas([c.p], c.w, fs, lh).h)) + 11);
    if (icon) st.img(icon, xs[0] + 10, y + (rh - 22) / 2, 22, 22);
    if (y + rh > y1 + 1) warn(`s${st.n} table «${(d.title || st.def.title || "").slice(0, 22)}» row ${i + 1}: bottom ${(y + rh).toFixed(0)} > ${y1}`);
    if (!Array.isArray(row) && row.gapRow) st.rect(tx, y, tw, rh, { fill: "FDF1F0" });
    else if (i % 2 === 1) st.rect(tx, y, tw, rh, { fill: "F7F9FC" });
    st.line([[tx, y + rh], [tr, y + rh]], { color: C.line, lw: 0.75 });
    parsed.forEach((c, j) => {
      const isTag = /^\[(M|I|G)\]/.test(cells[j]);
      st.text(xs[j] + 10 + (j === 0 && icon ? 30 : 0), y, c.w, rh, [c.p], { size: fs, valign: "middle", lh, color: j === 0 ? C.ink : "2E3440", bold: j === 0 && !isTag });
    });
    y += rh;
  });
  if (d.facts && !noFacts) factsTable(st, y + 12, y1, d.facts, d.factsTitle);
};

R.diagram = (st, y0, y1) => {
  const d = st.def;
  const legendH = d.legend ? d.legend.length * 20 + 4 : 0;
  for (const z of d.zones || []) {
    const tone = z.tone === "vnet" ? { fill: "F0F7FF", line: "0078D4" } : z.tone === "tenant" ? { fill: "F7FAFD", line: "9CC3E8" } : z.tone === "inner" ? { fill: "F4F8FC", line: "6B8DB5" } : { fill: "FFFFFF", line: "C5CDD9" };
    group(st, z.b, () => {
      st.rect(z.x, z.y, z.w, z.h, { fill: tone.fill, line: tone.line, lw: z.tone === "inner" ? 1.5 : 1.25, radius: 12, dash: true });
      const ly = z.labelBottom ? z.y + z.h - 24 : z.y + 6;
      st.text(z.x + 12, ly, z.w - 24, 18, z.label, { size: 9.5, bold: true, color: z.tone === "inner" ? "005A9E" : C.sub, valign: "middle", lh: 13 });
    });
  }
  const nodes = new Map(d.nodes.map((n) => [n.id, n]));
  const anchor = (n, side, off = 0) => {
    const cx = n.x + n.w / 2, cy = n.y + n.h / 2;
    if (side === "l") return [n.x, cy + off];
    if (side === "r") return [n.x + n.w, cy + off];
    if (side === "t") return [cx + off, n.y];
    return [cx + off, n.y + n.h];
  };
  const off = new Map();
  for (const e of d.edges || []) {                                   // edges under the nodes
    const a = nodes.get(e.from), b = nodes.get(e.to);
    if (!a || !b) throw new Error(`diagram edge ${e.from}->${e.to} has no node (slide ${st.n})`);
    const o = e.off != null ? e.off : (off.get(a.id) || 0); off.set(a.id, o + 1);
    let pts;
    if (e.via) pts = e.via.reduce((acc, v, i, arr) => (i % 2 === 0 ? [...acc, [arr[i], arr[i + 1]]] : acc), []);
    else {
      const fs = e.fromSide || (b.x >= a.x + a.w ? "r" : b.x + b.w <= a.x ? "l" : b.y >= a.y + a.h ? "b" : "t");
      const ts = e.toSide || (fs === "r" ? "l" : fs === "l" ? "r" : fs === "b" ? "t" : "b");
      const p1 = anchor(a, fs, o * 12), p2 = anchor(b, ts, e.toOff || 0);
      if (fs === "r" || fs === "l") {
        const mx = e.mx != null ? e.mx : (p1[0] + p2[0]) / 2;
        pts = Math.abs(p1[1] - p2[1]) < 1 ? [p1, p2] : [p1, [mx, p1[1]], [mx, p2[1]], p2];
      } else {
        const my = e.my != null ? e.my : (p1[1] + p2[1]) / 2;
        pts = Math.abs(p1[0] - p2[0]) < 1 ? [p1, p2] : [p1, [p1[0], my], [p2[0], my], p2];
      }
    }
    group(st, e.b, () => {
      st.line(pts, { color: e.dash ? "7A8AA0" : C.azDark, lw: e.dash ? 1.25 : 1.75, dash: !!e.dash, arrow: true });
      if (e.label) {
        let best = 0, bl = -1;
        for (let i = 0; i < pts.length - 1; i++) { const l = Math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1]); if (l > bl) { bl = l; best = i; } }
        const p = pts[best], q = pts[best + 1], mx = (p[0] + q[0]) / 2, my = (p[1] + q[1]) / 2;
        const horiz = Math.abs(q[0] - p[0]) >= Math.abs(q[1] - p[1]);
        const lw2 = runsW(parsePara(e.label).runs, 8.5) + 12;
        const lx = e.lx != null ? e.lx : (horiz ? mx - lw2 / 2 : Math.min(p[0], q[0]) + 7);
        const ly = e.ly != null ? e.ly : (horiz ? my - 19 : my - 8);
        st.rect(lx, ly - 4, lw2, 22, { fill: C.white, radius: 4, line: "DCE4EE", lw: 0.5 });
        st.text(lx, ly - 4, lw2, 22, e.label, { size: 8.5, color: "3A4658", align: "center", valign: "middle", lh: 11 });
      }
    });
  }
  for (const n of d.nodes) {
    const tone = TONE[n.tone || "plain"];
    group(st, n.b, () => {
      st.rect(n.x, n.y, n.w, n.h, { fill: n.tone === "hi" ? C.hi : tone.fill, line: tone.line, lw: n.tone === "hi" ? 2 : 1.25, radius: 10, dash: n.tone === "outer" });
      const sub = P(n.sub || []);
      const ssz = n.w < 190 ? 8.5 : 9.5;
      if (n.w >= 120) for (const s of n.sub || []) if (runsW(parsePara(s).runs, ssz) > n.w - 26) warn(`s${st.n} node «${n.title}» sub too wide: «${s}»`);
      if (n.w < 120) {
        if (n.icon) st.img(n.icon, n.x + n.w / 2 - 14, n.y + 8, 28, 28);
        st.text(n.x + 4, n.y + 40, n.w - 8, 22, n.title, { size: 10, bold: true, color: C.ink, align: "center", valign: "middle", lh: 13 });
        st.text(n.x + 4, n.y + 64, n.w - 8, n.h - 70, sub, { size: 8.5, color: C.sub, align: "center", lh: 11.5 });
      } else {
        const tx = n.icon ? n.x + 48 : n.x + 12;
        if (n.icon) st.img(n.icon, n.x + 12, n.y + 10, 30, 30);
        st.text(tx, n.y + 8, n.w - (tx - n.x) - 10, 32, n.title, { size: 12, bold: true, color: C.ink, valign: "middle", lh: 16 });
        st.text(n.x + 12, n.y + 44, n.w - 24, n.h - 50, sub, { size: ssz, color: "3A4658", lh: 14.5 });
      }
    });
  }
  if (d.facts) {                                       // optional facts block under the zones
    const zb = Math.max(...d.zones.map((z) => z.y + z.h));
    factsTable(st, zb + 16, y1, d.facts, d.factsTitle);
  }
  if (d.legend) {                                    // the legend is placed against y1 already: no slide offset
    const ox0 = st.ox, oy0 = st.oy; st.ox = 0; st.oy = 0;
    st.text(36, y1 - legendH, W - 72, legendH, P(d.legend), { size: 9.5, color: C.sub, lh: 19 });
    st.ox = ox0; st.oy = oy0;
  }
};

R.pipeline = (st, y0, y1) => {
  const d = st.def, n = d.steps.length, gap = 26, w = (W - 72 - gap * (n - 1)) / n, h = 104;
  d.steps.forEach((s, i) => {
    const x = 36 + i * (w + gap);
    group(st, s.b, () => {
      st.rect(x, y0, w, h, { fill: i % 2 ? "F3F8FD" : "EEF5FC", line: "9CC3E8", lw: 1.25, radius: 10 });
      st.rect(x + 10, y0 + 10, 24, 24, { fill: C.az, radius: 12 });
      st.text(x + 10, y0 + 10, 24, 24, String(i + 1), { size: 10.5, bold: true, color: C.white, align: "center", valign: "middle", lh: 14 });
      st.text(x + 40, y0 + 8, w - 50, 28, s.t, { size: 11.5, bold: true, color: C.ink, valign: "middle", lh: 15 });
      st.text(x + 12, y0 + 42, w - 24, h - 50, s.d, { size: 9.5, color: "3A4658", lh: 13.5 });
    });
    if (i < n - 1) group(st, s.b, () => st.line([[x + w, y0 + h / 2], [x + w + gap - 2, y0 + h / 2]], { color: C.az, lw: 2, arrow: true }));
  });
  const ly = y0 + h + 18, lw = (W - 72 - 28) / 3, lh2 = y1 - ly;
  d.lanes.forEach((l, i) => {
    const x = 36 + i * (lw + 14), tone = TONE[l.tone || "info"];
    st.rect(x, ly, lw, lh2, { fill: tone.fill, line: tone.line, lw: 1, radius: 10 });
    st.text(x + 16, ly + 10, lw - 32, 26, l.title, { size: 12.5, bold: true, color: tone.accent, lh: 17 });
    st.text(x + 16, ly + 40, lw - 32, lh2 - 50, P(l.lines), { size: 10.5, bullet: true, lh: 16.5 });
  });
};

R.flow = (st, y0, y1) => {
  const d = st.def, n = d.steps.length, gap = 22, w = (W - 72 - gap * (n - 1)) / n, h = d.facts ? 150 : 172;
  d.steps.forEach((s, i) => {
    const x = 36 + i * (w + gap), last = i === n - 1;
    group(st, i + 1, () => {
      st.rect(x, y0, w, h, { fill: last ? "FFF7E8" : "F3F8FD", line: last ? "F0D49A" : "9CC3E8", lw: 1.25, radius: 10 });
      st.rect(x, y0, w, 6, { fill: last ? C.warn : C.az });
      st.text(x + 12, y0 + 12, w - 24, 30, s.t, { size: 12.5, bold: true, color: C.ink, lh: 17 });
      st.text(x + 12, y0 + 46, w - 24, h - 54, s.d.split("\n"), { size: 9.5, color: "3A4658", lh: 15.5 });
    });
    if (!last) group(st, i + 1, () => st.line([[x + w, y0 + h / 2], [x + w + gap - 2, y0 + h / 2]], { color: C.az, lw: 2, arrow: true }));
  });
  const cy = y0 + h + 16, rest = y1 - cy;
  if (d.facts) factsTable(st, cy, y1 - (d.strip ? 90 : 0), d.facts, d.factsTitle);
  if (d.cards) {
    const cw = (W - 72 - 14) / 2;
    d.cards.forEach((c, i) => card(st, 36 + i * (cw + 14), cy, cw, rest, c));
  }
  if (d.strip) {
    const sh = Math.min(rest, 78), sy = y1 - sh;
    st.rect(36, sy, W - 72, sh, { fill: "EEF4FB", line: "B9D7F0", lw: 1, radius: 8 });
    st.text(56, sy + 8, W - 112, sh - 14, P(d.strip), { size: 10.5, bullet: true, lh: 17.5 });
  }
};

R.coldstart = (st, y0, y1) => {
  const d = st.def, bx = 60, bw = W - 120, by = y0 + 40, bh = 56;
  const tones = { a: "9CC3E8", b: "0078D4", c: "FFB900", d: "107C41" }, txtc = { a: "0B2A4A", b: "FFFFFF", c: "3A2A00", d: "FFFFFF" };
  st.text(bx, y0 + 4, bw, 26, `총 ${d.total}초 — 레플리카 0 → 첫 응답 (구간 폭 = 시간 비율, 0.22초 구간만 최소 폭으로 확대)`, { size: 11, color: C.sub, lh: 15 });
  let x = bx;
  const centers = [];
  d.segs.forEach((s) => {
    const w = Math.max(18, bw * s.s / d.total);
    st.rect(x, by, w, bh, { fill: tones[s.tone] });
    if (w > 60) st.text(x, by + 6, w, 24, `${s.s}s`, { size: 12, bold: true, color: txtc[s.tone], align: "center", lh: 16 });
    if (w > 60) st.text(x, by + 30, w, 20, `${Math.round(100 * s.s / d.total)}%`, { size: 9, color: txtc[s.tone], align: "center", lh: 12 });
    centers.push(x + w / 2);
    x += w;
  });
  const ly = by + bh + 26, lh = 66, lw = (W - 72 - 36) / 4;
  d.segs.forEach((s, i) => {
    const lx = 36 + i * (lw + 12);
    st.line([[centers[i], by + bh], [lx + lw / 2, ly]], { color: "9AA4B2", lw: 0.75 });
    st.rect(lx, ly, lw, lh, { fill: C.panel, line: C.line, lw: 1, radius: 8 });
    st.rect(lx, ly, lw, 5, { fill: tones[s.tone] });
    st.text(lx + 12, ly + 8, lw - 24, 22, `${s.s}초 · ${Math.round(100 * s.s / d.total)}%`, { size: 11, bold: true, color: C.ink, lh: 15 });
    st.text(lx + 12, ly + 30, lw - 24, 34, parsePara(`[${s.tag}] ${s.t}`), { size: 9.5, color: "3A4658", lh: 13 });
  });
  const cy = ly + lh + 16, cw = (W - 72 - 28) / 3, ch = y1 - cy;
  d.cards.forEach((c, i) => card(st, 36 + i * (cw + 14), cy, cw, ch, c));
};

R.layers = (st, y0, y1) => {
  const d = st.def, L = d.layers, total = L.reduce((a, l) => a + l.mods.length, 0);
  const lw = 736, rh = Math.min(84, (y1 - y0) / L.length - 8), tones = ["E1EEFA", "E9F2FC", "F0F6FD", "F5F9FE", "FAFCFF"];
  L.forEach((l, i) => {
    const y = y0 + i * (rh + 8), pct = Math.round(100 * l.mods.length / total);
    st.rect(36, y, lw, rh, { fill: tones[i], line: "B9D7F0", lw: 1, radius: 10 });
    st.rect(36, y, 6, rh, { fill: C.az });
    st.text(52, y + 8, 84, 36, String(l.mods.length), { size: 24, bold: true, color: C.az, valign: "middle", lh: 30 });
    st.text(52, y + 44, 84, 20, `${pct}%`, { size: 10, color: C.sub, lh: 13 });
    st.text(146, y + 8, lw - 160, 26, l.n, { size: 13, bold: true, color: C.ink, lh: 17.5 });
    st.text(146, y + 38, 196, rh - 40, l.why, { size: 9.5, color: C.sub, lh: 13 });
    const ex = l.mods.slice(0, 10).join(" · ") + (l.mods.length > 10 ? `  ·  +${l.mods.length - 10}` : "");
    st.text(350, y + 36, lw - 366, rh - 40, ex, { size: 9, color: "3A4658", lh: 13 });
  });
  const fx = 36 + lw + 16, fw = W - 36 - fx;
  st.rect(fx, y0, fw, y1 - y0, { fill: "FFF7E8", line: "F0D49A", lw: 1.25, radius: 10 });
  st.text(fx + 16, y0 + 12, fw - 32, 26, "읽는 법", { size: 13, bold: true, color: C.ink, lh: 17.5 });
  st.text(fx + 16, y0 + 46, fw - 32, y1 - y0 - 56, P(d.facts), { size: 11, bullet: true, lh: 17.5 });
};

R.bars = (st, y0, y1) => {
  const d = st.def, n = d.bars.length, rowH = 44, barH = 16;
  d.bars.forEach((b, i) => {
    const y = y0 + i * rowH, tone = TONE[b.tone || "info"];
    st.text(36, y, 262, rowH, b.label, { size: 11, color: C.ink, valign: "middle", lh: 15 });
    st.rect(306, y + (rowH - barH) / 2, 520, barH, { fill: "E9EEF5", radius: 8 });
    if (b.tone !== "gap") st.rect(306, y + (rowH - barH) / 2, Math.max(10, 520 * b.value / b.max), barH, { fill: tone.accent, radius: 8 });
    st.text(836, y, 190, rowH, b.display, { size: 10.5, bold: true, color: tone.accent, valign: "middle", lh: 14 });
    st.text(1032, y, W - 36 - 1032, rowH, b.note, { size: 9.5, color: C.sub, valign: "middle", lh: 13 });
    if (i) st.line([[36, y], [W - 36, y]], { color: "EEF1F5", lw: 0.75 });
  });
  const cy = y0 + n * rowH + 14, cw = (W - 72 - 14) / 2, ch = y1 - cy;
  d.cards.forEach((c, i) => card(st, 36 + i * (cw + 14), cy, cw, ch, c));
};

R.matrix = (st, y0, y1) => {
  const d = st.def, cell = 92, gx = 96, gy = y0 + 4;
  const color = (s) => (s >= 6 ? "F8D7DA" : s >= 3 ? "FDE9CD" : "DFF0E2");
  for (let sev = 3; sev >= 1; sev--) for (let lik = 1; lik <= 3; lik++) {
    const x = gx + (lik - 1) * cell, y = gy + (3 - sev) * cell;
    st.rect(x + 2, y + 2, cell - 4, cell - 4, { fill: color(sev * lik), line: C.white, lw: 1, radius: 6 });
    st.text(x + 6, y + 4, 30, 14, `${sev}×${lik}`, { size: 7.5, color: "8A94A6", lh: 10 });
    d.risks.filter((r) => r.sev === sev && r.lik === lik).forEach((r, i) => {
      const cx = x + 10 + (i % 3) * 32, cy = y + 26 + (i >> 2) * 30;
      st.rect(cx, cy, 28, 24, { fill: sev * lik >= 6 ? "C0392B" : sev * lik >= 3 ? "D68910" : "1E8449", radius: 12 });
      st.text(cx, cy, 28, 24, r.id, { size: 9, bold: true, color: C.white, align: "center", valign: "middle", lh: 12 });
    });
  }
  ["가능도 낮음", "가능도 중간", "가능도 높음"].forEach((t, i) => st.text(gx + i * cell, gy + 3 * cell + 2, cell, 16, t, { size: 8.5, color: C.sub, align: "center", lh: 11 }));
  ["중요도 높음", "중요도 중간", "중요도 낮음"].forEach((t, i) => st.text(36, gy + i * cell, 56, cell, t, { size: 8.5, color: C.sub, align: "center", valign: "middle", lh: 11 }));
  const lx = gx + 3 * cell + 26, lwid = W - 36 - lx, rh = (y1 - y0) / d.risks.length;
  d.risks.forEach((r, i) => {
    const y = y0 + i * rh, tone = TONE[r.sev === 3 ? "gap" : r.sev === 2 ? "warn" : "ok"];
    st.rect(lx, y + 3, lwid, rh - 5, { fill: i % 2 ? "F7F9FC" : "FFFFFF", radius: 6 });
    st.rect(lx, y + 3, 4, rh - 5, { fill: tone.accent });
    st.text(lx + 12, y + 3, 34, rh - 5, r.id, { size: 10.5, bold: true, color: tone.accent, valign: "middle", lh: 14 });
    st.text(lx + 48, y + 3, lwid - 60, rh - 5, [{ runs: [{ t: r.t, bold: true, size: 1 }] }, { runs: [{ t: "완화 — " + r.mit + "   ·   트리거 — " + r.trig, size: 0.9, color: C.sub }] }],
      { size: 10, color: C.ink, valign: "middle", lh: 13.5 });
  });
};

R.phases = (st, y0, y1) => {
  const d = st.def, n = d.phases.length, gap = 16, w = (W - 72 - gap * (n - 1)) / n, h = y1 - y0;
  d.phases.forEach((p, i) => {
    const x = 36 + i * (w + gap), tone = TONE[p.tone || "info"];
    group(st, i + 1, () => {
      st.rect(x, y0, w, h, { fill: C.white, line: tone.line, lw: 1.25, radius: 12 });
      st.rect(x, y0, w, 66, { fill: tone.accent });
      st.text(x + 16, y0 + 8, w - 32, 20, p.n, { size: 11.5, bold: true, color: "EAF2FB", lh: 15 });
      st.text(x + 16, y0 + 28, w - 32, 30, p.t, { size: 13.5, bold: true, color: C.white, valign: "middle", lh: 18.5 });
      st.text(x + 16, y0 + 74, w - 32, 36, p.trig, { size: 10.5, bold: true, color: tone.accent, lh: 15 });
      st.text(x + 16, y0 + 114, w - 32, h - 124, P(p.items), { size: 10.5, bullet: true, lh: 17.5 });
    });
    if (i < n - 1) group(st, i + 1, () => st.line([[x + w + 2, y0 + 33], [x + w + gap - 2, y0 + 33]], { color: C.az, lw: 2, arrow: true }));
  });
};

R.end = (st) => {
  const d = st.def;
  st.text(0, 58, W, 50, d.title, { size: 26, bold: true, color: "7FC4F5", align: "center", valign: "middle", lh: 34 });
  st.text(80, 122, W - 160, 100, d.lines.map((s, i) => ({ runs: [{ t: s, bold: i === 2, size: i === 2 ? 1.06 : 1 }] })), { size: 15, color: "E3EAF4", align: "center", lh: 31 });
  const n = d.blocks.length, gap = 16, w = (W - 120 - gap * (n - 1)) / n, y = 236, h = 214;
  const head = { ok: "8FD6A4", warn: "F5CF7A", info: "8CC4F0" };
  d.blocks.forEach((b, i) => {
    const x = 60 + i * (w + gap), tone = TONE[b.tone || "info"];
    st.rect(x, y, w, h, { fill: "17263D", line: "2B3D57", lw: 1, radius: 12 });
    st.rect(x, y, w, 6, { fill: tone.accent });
    st.text(x + 18, y + 18, w - 36, 30, b.t, { size: 15, bold: true, color: head[b.tone] || "8CC4F0", lh: 20 });
    st.text(x + 18, y + 64, w - 36, h - 76, b.items.map((s) => ({ runs: [{ t: "• " + s }] })), { size: 12, color: "D5DEEB", lh: 21, gap: 7 });
  });
  if (d.todo) {
    const ty = y + h + 16, tw = (W - 120 - 2 * 14) / 3;
    st.text(60, ty, W - 120, 26, d.todo.title, { size: 14, bold: true, color: "F5CF7A", align: "center", valign: "middle", lh: 19 });
    d.todo.items.forEach((it, i) => {
      const tx = 60 + i * (tw + 14);
      st.rect(tx, ty + 32, tw, 50, { fill: "1B2B45", line: "33507A", lw: 1, radius: 10 });
      st.rect(tx, ty + 32, 4, 50, { fill: "F5CF7A" });
      st.text(tx + 14, ty + 32, tw - 24, 50, it, { size: 11, color: "E3EAF4", valign: "middle", lh: 15.5 });
    });
  }
  st.text(60, 628, W - 120, 40, d.docs, { size: 9, color: "8E9AB0", align: "center", lh: 13.5 });
  st.text(0, 680, W, 20, `${st.n} / ${st.total} · BTS-SBOM · Azure 운영 아키텍처 · 아키텍트 에디션 v2 · 2026-11-28`, { size: 8.5, color: "5D6A80", align: "center", lh: 12 });
};

// ---------- snapshot pins: the deck quotes the commit and module count it was built from ----------
const COMMIT = require("child_process").execSync("git rev-parse --short HEAD", { cwd: ROOT, encoding: "utf8" }).trim();
(function pin() {
  const walk = (v) => (typeof v === "string" ? v.replace("{commit}", COMMIT).replace("{mods}", String(realMods)) : Array.isArray(v) ? v.map(walk) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)])) : v);
  for (const s of MODEL.S) for (const k of Object.keys(s)) s[k] = walk(s[k]);
  if (MODEL.PLAN) for (const s of MODEL.PLAN) for (const k of Object.keys(s)) s[k] = walk(s[k]);
})();

// ---- assignment-deck composites: two visuals that each carry what were two slides in the architect deck ----
R.coldcap = (st, y0, y1) => {                   // cold-start anatomy on top, resource headroom bars below
  const d = st.def, bx = 60, bw = W - 120, by = y0 + 30, bh = 48;
  const tones = { a: "9CC3E8", b: "0078D4", c: "FFB900", d: "107C41" }, txtc = { a: "0B2A4A", b: "FFFFFF", c: "3A2A00", d: "FFFFFF" };
  st.text(bx, y0, bw, 24, `콜드 스타트 총 ${d.total}초 — 레플리카 0 → 첫 응답 (구간 폭 = 시간 비율, 0.22초 구간만 최소 폭으로 확대)`, { size: 11, bold: true, color: C.ink, valign: "middle", lh: 15 });
  let x = bx; const centers = [];
  d.segs.forEach((s) => {
    const w = Math.max(18, bw * s.s / d.total);
    st.rect(x, by, w, bh, { fill: tones[s.tone] });
    if (w > 60) st.text(x, by + 2, w, 22, `${s.s}s`, { size: 12, bold: true, color: txtc[s.tone], align: "center", lh: 16 });
    if (w > 60) st.text(x, by + 24, w, 20, `${Math.round(100 * s.s / d.total)}%`, { size: 9, color: txtc[s.tone], align: "center", lh: 12 });
    centers.push(x + w / 2); x += w;
  });
  const ly = by + bh + 14, lh = 40, lw = (W - 72 - 36) / 4;
  d.segs.forEach((s, i) => {
    const lx = 36 + i * (lw + 12);
    st.line([[centers[i], by + bh], [lx + lw / 2, ly]], { color: "9AA4B2", lw: 0.75 });
    st.rect(lx, ly, lw, lh, { fill: C.panel, line: C.line, lw: 1, radius: 8 });
    st.rect(lx, ly, 5, lh, { fill: tones[s.tone] });
    st.text(lx + 12, ly + 3, lw - 24, 18, `${s.s}초 · ${Math.round(100 * s.s / d.total)}%`, { size: 10.5, bold: true, color: C.ink, lh: 14 });
    st.text(lx + 12, ly + 21, lw - 24, 17, parsePara(`[${s.tag}] ${s.t}`), { size: 9, color: "3A4658", lh: 12.5 });
  });
  const cy = ly + lh + 16;
  st.text(36, cy, W - 72, 22, "자원의 여유 — Azure Monitor 앱 메트릭 · 최근 72시간 · 시간별 최대값", { size: 11, bold: true, color: C.ink, valign: "middle", lh: 15 });
  const rowH = 34, barH = 14;
  d.bars.forEach((b, i) => {
    const y = cy + 26 + i * rowH, tone = TONE[b.tone || "info"];
    st.text(36, y, 250, rowH, b.label, { size: 10, color: C.ink, valign: "middle", lh: 14 });
    st.rect(292, y + (rowH - barH) / 2, 470, barH, { fill: "E9EEF5", radius: 7 });
    if (b.tone !== "gap") st.rect(292, y + (rowH - barH) / 2, Math.max(10, 470 * b.value / b.max), barH, { fill: tone.accent, radius: 7 });
    st.text(770, y, 190, rowH, b.display, { size: 10, bold: true, color: tone.accent, valign: "middle", lh: 13.5 });
    st.text(964, y, W - 36 - 964, rowH, b.note, { size: 9, color: C.sub, valign: "middle", lh: 12.5 });
    if (i) st.line([[36, y], [W - 36, y]], { color: "EEF1F5", lw: 0.75 });
  });
  const ny = cy + 26 + d.bars.length * rowH + 8;
  st.text(36, ny, W - 72, Math.max(20, y1 - ny), P(d.notes), { size: 10, bullet: true, lh: 15 });
};

R.strideRisk = (st, y0, y1) => {                // STRIDE table (left) + risk register list (right)
  const d = st.def, half = (W - 72 - 16) / 2;
  R.table(st, y0, y1, { ...d.stride, x: 36, w: half, icons: false, facts: null }, true);
  const risks = d.risks, lx = 36 + half + 16, lw = half, rh = (y1 - y0) / risks.length;
  st.rect(lx, y0, lw, 28, { fill: C.az });
  st.text(lx + 10, y0, lw - 20, 28, "운영 리스크 레지스터 — 중요도 × 가능도 (위치는 판단, 상태는 측정)", { size: 9, bold: true, color: C.white, valign: "middle", lh: 12 });
  risks.forEach((r, i) => {
    const y = y0 + 28 + i * rh, tone = TONE[r.sev === 3 ? "gap" : r.sev === 2 ? "warn" : "ok"];
    st.rect(lx, y + 2, lw, rh - 4, { fill: i % 2 ? "F7F9FC" : "FFFFFF", radius: 5 });
    st.rect(lx, y + 2, 4, rh - 4, { fill: tone.accent });
    st.text(lx + 10, y + 2, 30, rh - 4, r.id, { size: 9.5, bold: true, color: tone.accent, valign: "middle", lh: 13 });
    st.text(lx + 42, y + 2, lw - 52, rh - 4, [{ runs: [{ t: `${r.sev}×${r.lik}  `, bold: true, size: 0.9, color: tone.accent }, { t: r.t, bold: true, size: 1 }] }, { runs: [{ t: "완화 — " + r.mit + " · 트리거 — " + r.trig, size: 0.9, color: C.sub }] }],
      { size: 9, color: C.ink, valign: "middle", lh: 12.5 });
  });
};

// ---------- build stages ----------
const stages = MODEL.S.map((def, i) => {
  const st = newStage(def, i + 1, MODEL.S.length);
  if (ASSIGN) {
    st.rect(0, 0, W, H, { fill: C.white, bg: true });
    if (def.kind === "diagram") { st.ox = 4; st.oy = def.dy != null ? def.dy : 50; }
    const y1 = 660, y0 = 178;
    if (def.then === "table2") { R.table(st, y0, y0 + def.split, def.t1, true); R.table(st, y0 + def.split + 12, y1, def.t2, true); }
    else R[def.kind](st, y0, y1);
    return st;
    for (const q of st.prims) if (q.k !== "line" && [q.x, q.y].some((v) => v < 0) || (q.k !== 'line' && (q.x + q.w > W + 0.5 || q.y + q.h > H + 0.5))) warn(`s${st.n} primitive #${q.i} outside stage: ${JSON.stringify([q.x, q.y, q.w, q.h])}`);
  }
  chrome(st);
  if (def.kind !== "cover" && def.kind !== "end") {
    const y1 = verdictBar(st);
    const y0 = def.kpi ? kpiStrip(st, def.kpi, 110) + 12 : 118;
    if (def.then === "cards") {                       // two-part slide: table on top, cards below
      const split = Math.round(y0 + (y1 - y0) * 0.56);
      R.table(st, y0, split);
      R.cards(st, split + 8, y1, def.thenCols);
    } else R[def.kind](st, y0, y1);
  } else R[def.kind](st);
  return st;
});
// PPT shape indices for the animation manifest: one shape per primitive, one per LINE SEGMENT, none for the
// background (PowerPoint's Shapes collection = creation order).
for (const st of stages) {
  let c = 0;
  for (const p of st.prims) {
    if (p.k === "rect" && p.bg) { p.i = 0; continue; }
    p.i = ++c;
    if (p.k === "line") c += p.pts.length - 2;
  }
}

// ---------- PPTX backend ----------
const pptx = new pptxgen();
pptx.defineLayout({ name: "STAGE", width: W * IN, height: H * IN });
pptx.layout = "STAGE";
pptx.author = "bts-sbom";
pptx.title = "BTS-SBOM × Azure 운영 아키텍처 — 아키텍트 에디션 v2";
pptx.subject = "Azure 리소스 · 전체 구성도 · UI 구성요소 기능 · 설계 판단 · 리스크 · 진화 로드맵 (2026-11-28 실측)";

const manifest = [];
for (const st of stages) {
  const s = pptx.addSlide();
  const rec = { slide: st.n, title: st.def.title, shapes: [], builds: st.def.builds || null };
  for (const p of st.prims) {
    const geo = { x: p.x * IN, y: p.y * IN, w: p.w * IN, h: p.h * IN };
    const name = `s${st.n}_p${p.i}`;
    if (p.k === "rect") {
      if (p.bg) { s.background = { color: p.fill }; continue; }
      const o = { ...geo, fill: { color: p.fill }, line: p.line ? { color: p.line, width: p.lw || 1, dashType: p.dash ? "dash" : "solid" } : { color: p.fill, width: 0 }, objectName: name };
      if (p.radius) { o.rectRadius = p.radius * IN; s.addShape("roundRect", o); } else s.addShape("rect", o);
      if (p.b) rec.shapes.push({ i: p.i, b: p.b, line: false });
    } else if (p.k === "img") {
      s.addImage({ path: path.join(ICON_DIR, p.key + ".png"), ...geo, objectName: name });
      if (p.b) rec.shapes.push({ i: p.i, b: p.b, line: false });
    } else if (p.k === "line") {
      const nseg = p.pts.length - 1;
      for (let i = 0; i < nseg; i++) {               // one PPT shape per segment: shape index = p.i + i
        const [x1, y1] = p.pts[i], [x2, y2] = p.pts[i + 1];
        s.addShape("line", { x: Math.min(x1, x2) * IN, y: Math.min(y1, y2) * IN, w: Math.max(0.0003, Math.abs(x2 - x1) * IN), h: Math.max(0.0003, Math.abs(y2 - y1) * IN),
          flipH: x2 < x1, flipV: y2 < y1, line: { color: p.color, width: p.lw, dashType: p.dash ? "dash" : "solid", endArrowType: i === nseg - 1 && p.arrow ? "triangle" : "none" }, objectName: name });
        if (p.b) rec.shapes.push({ i: p.i + i, b: p.b, line: true });
      }
    } else if (p.k === "text") {
      const runs = [];
      p.paras.forEach((pa, pi) => pa.runs.forEach((r, ri) => {
        const o = { bold: !!r.bold, color: r.color, fontSize: Math.round(p.size * r.size * 10) / 10 };
        if (ri === 0 && pa.bullet) o.bullet = { code: "2022", indent: 11 };
        if (ri === 0 && pa.gapBefore) o.paraSpaceBefore = pa.gapBefore * 0.75;
        if (ri === pa.runs.length - 1 && pi < p.paras.length - 1) o.breakLine = true;
        runs.push({ text: r.t, options: o });
      }));
      s.addText(runs, { ...geo, fontFace: FONT, fontSize: p.size, color: p.paras[0].runs[0].color, align: p.align || "left", valign: p.valign || "top",
        margin: 0, lineSpacing: p.lh * 0.75, wrap: true, isTextBox: true, objectName: name });
      if (p.b) rec.shapes.push({ i: p.i, b: p.b, line: false });
    }
  }
  const notes = [st.def.notes, st.def.verdict ? "아키텍트 판단: " + st.def.verdict.replace(/^\[(M|I|G)\]\s*/, "") : ""].filter(Boolean).join("\n\n");
  if (notes) s.addNotes(notes);
  manifest.push(rec);
}

// ---------- HTML backend ----------
const iconCache = new Map();
const iconUri = (k) => {
  if (!iconCache.has(k)) iconCache.set(k, "data:image/png;base64," + fs.readFileSync(path.join(ICON_DIR, k + ".png")).toString("base64"));
  return iconCache.get(k);
};
const esc = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const pt = (v) => +(v * 4 / 3).toFixed(2), px = (v) => +v.toFixed(2);
const runsHtml = (runs) => runs.map((r) => (r.chip
  ? `<span class="chip" style="background:#${TAG[r.chip].color}">${TAG[r.chip].label}</span>`
    + `<span style="color:#${r.color}">${esc(r.t.replace(TAG[r.chip].label + " ", ""))}</span>`
  : `<span style="color:#${r.color};font-weight:${r.bold ? 700 : 400}">${esc(r.t)}</span>`)).join("");

function buildHtml() {
  const h = [];
  h.push(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BTS-SBOM × Azure 운영 아키텍처 — 아키텍트 에디션 v2</title><style>
html,body{margin:0;height:100%;background:#0B1422;overflow:hidden;font-family:"Malgun Gothic","Apple SD Gothic Neo","Noto Sans CJK KR","Noto Sans KR",sans-serif;-webkit-font-smoothing:antialiased}
#wrap{position:fixed;left:0;right:0;top:0;bottom:44px;display:flex;align-items:center;justify-content:center}
#stage{position:relative;width:1280px;height:720px;transform-origin:center center;box-shadow:0 10px 60px rgba(0,0,0,.5)}
.slide{position:absolute;inset:0;display:none;overflow:hidden;background:#fff}.slide.active{display:block}
.el{position:absolute;box-sizing:border-box}
.t{padding:0;word-break:keep-all;overflow-wrap:break-word}
.t p{margin:0}.t p.b{padding-left:.95em;text-indent:-.95em}
.chip{display:inline-block;padding:0 6px;margin-right:4px;border-radius:9px;color:#fff;font-size:.88em;font-weight:700;line-height:1.45;vertical-align:1px}
svg.lines{position:absolute;inset:0;width:1280px;height:720px;overflow:visible;pointer-events:none}
svg .el{position:static}
.el[data-b]:not(.on){opacity:0}
.el.on{transition:opacity .45s ease,transform .45s ease}
.el[data-b]{transform:translateY(6px)}.el[data-b].on{transform:none}
svg .el[data-b]{transform:none}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.slide.active .el[data-b="0"]{animation:fadeUp .5s ease both}
#bar{position:fixed;left:0;bottom:40px;height:4px;width:100%;background:rgba(255,255,255,.08)}
#bar i{display:block;height:100%;width:0;background:#4CC2FF;transition:width .3s}
#hud,#tag{position:fixed;bottom:12px;color:#8E9AB0;font-size:12px;z-index:9}
#hud{left:14px}#tag{right:14px;font-weight:700;color:#B8C4D6}
#notes{position:fixed;left:0;right:0;bottom:0;max-height:40%;overflow:auto;background:rgba(10,18,32,.97);color:#D5DEEB;font-size:13px;line-height:1.65;padding:16px 28px;display:none;z-index:10;border-top:1px solid #2B3D57;white-space:pre-wrap}
#notes.on{display:block}
</style></head><body><div id="wrap"><div id="stage">
<svg width="0" height="0" style="position:absolute"><defs><marker id="arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#005A9E"/></marker><marker id="arwd" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#7A8AA0"/></marker></defs></svg>`);
  for (const st of stages) {
    const bgc = (st.prims.find((p) => p.k === "rect" && p.bg) || {}).fill || "FFFFFF";   // the dark slides
    h.push(`<section class="slide" style="background:#${bgc}" data-n="${st.n}" data-max="${st.maxBuild}" data-builds='${JSON.stringify(st.def.builds || {}).replace(/'/g, "&#39;")}'>`);
    const svg = [];
    for (const p of st.prims) {
      if (p.k !== "line" && [p.x, p.y, p.w, p.h].some((v) => typeof v !== "number" || !isFinite(v))) {
        throw new Error(`bad geometry on slide ${st.n}: ${p.k} #${p.i} ${JSON.stringify([p.x, p.y, p.w, p.h])} «${(p.paras && p.paras[0].runs[0].t) || p.fill || ""}»`);
      }
      const b = ` data-b="${p.b || 0}"`;
      const geo = p.k === "line" ? "" : `left:${px(p.x)}px;top:${px(p.y)}px;width:${px(p.w)}px;height:${px(p.h)}px;`;
      if (p.k === "rect") {
        if (p.bg) continue;                               // already applied to the <section>
        h.push(`<div class="el r"${b} style="${geo}background:#${p.fill};${p.line ? `border:${p.lw || 1}px ${p.dash ? "dashed " : "solid "}#${p.line};` : ""}border-radius:${p.radius || 0}px"></div>`);
      } else if (p.k === "img") h.push(`<div class="el i"${b} style="${geo}background:url(${iconUri(p.key)}) center/contain no-repeat"></div>`);
      else if (p.k === "line") {
        const pts = p.pts.map((q) => `${px(q[0])},${px(q[1])}`).join(" ");
        svg.push(`<g class="el"${b}><polyline points="${pts}" fill="none" stroke="#${p.color}" stroke-width="${p.lw}"${p.dash ? ' stroke-dasharray="6 4"' : ""}${p.arrow ? ` marker-end="url(#${p.dash ? "arwd" : "arw"})"` : ""}/></g>`);
      } else {
        const paras = p.paras.map((pa) => `<p${pa.bullet ? ' class="b"' : ""}${pa.gapBefore ? ` style="margin-top:${px(pa.gapBefore)}px"` : ""}>${pa.bullet ? "• " : ""}${runsHtml(pa.runs)}</p>`).join("");
        const va = p.valign === "middle" ? "display:flex;flex-direction:column;justify-content:center;" : "";
        h.push(`<div class="el t"${b} style="${geo}${va}font-size:${pt(p.size)}px;line-height:${px(p.lh)}px;text-align:${p.align || "left"}">${paras}</div>`);
      }
    }
    h.push(`<svg class="lines" viewBox="0 0 1280 720">${svg.join("")}</svg>`);
    const notes = [st.def.notes, st.def.verdict ? "아키텍트 판단: " + st.def.verdict.replace(/^\[(M|I|G)\]\s*/, "") : ""].filter(Boolean).join("\n\n");
    h.push(`<div class="notes" style="display:none">${esc(notes)}</div></section>`);
  }
  h.push(`</div></div><div id="bar"><i></i></div><div id="hud">← → · Space · Home/End · N 출처 · F 전체화면</div><div id="tag"></div><div id="notes"></div>
<script>
(function(){
var slides=[].slice.call(document.querySelectorAll('.slide')),N=slides.length,cur=0,build=0,timers=[];
function clearT(){timers.forEach(clearTimeout);timers=[];}
function maxOf(s){return +s.dataset.max||0;}
function reveal(s,b){[].slice.call(s.querySelectorAll('[data-b="'+b+'"]')).forEach(function(e){e.classList.add('on');});}
function hide(s,b){[].slice.call(s.querySelectorAll('[data-b="'+b+'"]')).forEach(function(e){e.classList.remove('on');});}
function tag(){var s=slides[cur],m=maxOf(s),t='';if(m&&build>0){var bs=JSON.parse(s.dataset.builds||'{}');t=bs[String(build)]||('단계 '+build);}document.getElementById('tag').textContent=t;}
function bar(){var m=maxOf(slides[cur]),f=N>1?(cur+(m?build/m*0.9:0))/(N-1):1;document.querySelector('#bar i').style.width=(100*Math.min(1,f))+'%';}
function show(n,keep){cur=Math.max(0,Math.min(N-1,n));if(!keep)build=0;clearT();
 slides.forEach(function(s,i){s.classList.toggle('active',i===cur);if(i!==cur){for(var b=1;b<=12;b++)hide(s,b);}});
 var s=slides[cur];for(var k=1;k<=build;k++)reveal(s,k);tag();bar();
 var m=maxOf(s);if(m>build&&!keep){for(var j=build+1;j<=m;j++){(function(jj){timers.push(setTimeout(function(){reveal(slides[cur],jj);build=Math.max(build,jj);tag();bar();},900*(jj-build)));})(j);}}}
function next(){var m=maxOf(slides[cur]);if(build<m){clearT();for(var k=1;k<=m;k++)reveal(slides[cur],k);build=m;tag();bar();return;}show(cur+1,false);}
function prev(){if(build>0){clearT();hide(slides[cur],build);build--;tag();bar();return;}var p=cur-1;build=p>=0?maxOf(slides[p]):0;show(p,true);}
/* 44px chrome strip: the HUD never covers the slide footer */
function fit(){var s=Math.min(innerWidth/1280,(innerHeight-44)/720);document.getElementById('stage').style.transform='scale('+s+')';}
function notes(){var el=document.getElementById('notes');if(el.classList.contains('on')){el.classList.remove('on');return;}el.textContent=slides[cur].querySelector('.notes').textContent;el.classList.add('on');}
document.addEventListener('keydown',function(e){var k=e.key;
 if(['ArrowRight',' ','PageDown','Enter'].indexOf(k)>=0){e.preventDefault();next();}
 else if(['ArrowLeft','PageUp','Backspace'].indexOf(k)>=0){e.preventDefault();prev();}
 else if(k==='Home'){e.preventDefault();show(0,false);}else if(k==='End'){e.preventDefault();show(N-1,false);}
 else if(k==='n'||k==='N'){notes();}else if(k==='f'||k==='F'){document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen();}});
document.getElementById('stage').addEventListener('click',function(e){var r=this.getBoundingClientRect();(e.clientX-r.left)/r.width<0.3?prev():next();});
addEventListener('resize',fit);fit();show(0,false);
})();
</script></body></html>`);
  return h.join("\n");
}

(async () => {
  if (ASSIGN) {
    const dir = path.join(ROOT, "evidence", "deck_render", "assign_v2");
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "source.pptx");
    await pptx.writeFile({ fileName: file });
    fs.writeFileSync(path.join(dir, "plan.json"), JSON.stringify(MODEL.PLAN, null, 1), "utf8");
    console.log("assign mode: %d content slides -> %s (%d KB) + plan.json", stages.length, path.relative(ROOT, file), Math.round(fs.statSync(file).size / 1024));
    if (warnings.length) { console.log("BUILD WARNINGS (%d):", warnings.length); warnings.forEach((w) => console.log("  - " + w)); }
    else console.log("build estimator: no overflow warnings");
    return;
  }
  await pptx.writeFile({ fileName: OUT_PPTX });
  const htmlOut = buildHtml();
  const script = htmlOut.slice(htmlOut.lastIndexOf("<script>") + 8, htmlOut.lastIndexOf("</script>"));
  new (require("vm").Script)(script);                 // a script that does not parse = a deck that does not run
  if (/<section class="slide"/.test(htmlOut) === false) throw new Error("html has no slides");
  fs.writeFileSync(OUT_HTML, htmlOut, "utf8");
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_MANIFEST, JSON.stringify(manifest, null, 1), "utf8");
  const eff = manifest.reduce((a, r) => a + r.shapes.length, 0);
  console.log("wrote %s (%d KB)", path.relative(ROOT, OUT_PPTX), Math.round(fs.statSync(OUT_PPTX).size / 1024));
  console.log("wrote %s (%d KB)", path.relative(ROOT, OUT_HTML), Math.round(fs.statSync(OUT_HTML).size / 1024));
  console.log("manifest: %d slides, %d build-animated shapes on %d slides", manifest.length, eff, manifest.filter((r) => r.shapes.length).length);
  if (warnings.length) { console.log("\nBUILD WARNINGS (%d):", warnings.length); warnings.forEach((w) => console.log("  - " + w)); }
  else console.log("build estimator: no overflow warnings");
})().catch((e) => { console.error(e); process.exit(1); });
