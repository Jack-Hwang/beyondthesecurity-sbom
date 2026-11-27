"""Eval-set integrity: segments, a pinned eval-set version, and a leak / composition check.

An aggregate metric can stay flat while one slice of the traffic gets worse (a gain on one topic pays for a loss on
another), and a comparison is only valid when both measurements used the SAME evaluation set. Three guards, all pure
and offline:

* **segments** - every golden item belongs to a segment (``ood``, ``area:<topic>``, ``lang:<ko|en>``); the loop gate
  blocks a candidate whose segment dropped more than ``SEGMENT_DELTA`` even when the total did not move;
* **pin** - an eval set has a content fingerprint; a baseline measured on another version of a set cannot be compared
  with a candidate measured on this one (the pass is undecidable until the baseline is deliberately re-created);
* **leak** - the holdout (``rag_test``) must not repeat a query of the sets that were tuned on, must not be copied into
  the corpus it is meant to test, and every expectation must be reachable.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

MIN_SEGMENT_N = 2          # a segment with fewer items is reported but never gated (one item is not a trend)
SEGMENT_DELTA = 0.10       # segments are small, so wider than the 0.02 on totals; exact per-query losses are caught by the case-regression gate
NEAR_DUP = 0.8             # character-trigram Jaccard at or above this between two queries is one query for leak purposes
MIN_CORPUS_Q = 12          # a shorter query is too generic to call "copied into the corpus"
TUNED = ("rag_golden", "rag_dev")          # sets that were looked at while tuning
HOLDOUT = "rag_test"                       # written before tuning, never tuned on
_HANGUL = re.compile("[가-힣]")
_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)


def norm(q: Any) -> str:
    """Comparable form of a query: lower-case, punctuation stripped, whitespace collapsed."""
    return " ".join(_PUNCT.sub(" ", str(q or "").lower()).split())


def lang_of(q: Any) -> str:
    return "ko" if _HANGUL.search(str(q or "")) else "en"


def area_of(item: Dict[str, Any]) -> str:
    """The topic a query is about = the first expected source ('domain/licenses.md' -> 'licenses', 'lecture/' -> 'lecture')."""
    exp = item.get("expect") or []
    if not exp:
        return "none"
    first = str(exp[0]).replace("\\", "/").strip("/")
    stem = first.rsplit("/", 1)[-1]
    return (stem[:-3] if stem.endswith(".md") else stem) or first.split("/", 1)[0] or "none"


def segment_names(item: Dict[str, Any]) -> List[str]:
    if item.get("ood"):
        return ["ood"]
    return ["area:" + area_of(item), "lang:" + lang_of(item.get("q"))]


def fingerprint(items: Optional[Iterable[Dict[str, Any]]]) -> str:
    """Content hash of an eval set (query, expectation, ood flag), insensitive to item order and to cosmetic spacing."""
    rows = sorted((norm(g.get("q")), sorted(str(e) for e in (g.get("expect") or [])), bool(g.get("ood"))) for g in (items or []))
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:12]


def pin_check(base_pins: Optional[Dict[str, str]], cand_pins: Optional[Dict[str, str]]) -> Tuple[List[str], List[str], List[str]]:
    """(undecidable, warnings, changed_sets): the same eval-set version on both sides, or the comparison is invalid."""
    undecidable: List[str] = []
    warnings: List[str] = []
    changed: List[str] = []
    cand_pins = cand_pins or {}
    if not base_pins:
        if cand_pins:
            warnings.append("baseline predates eval-set pinning: its eval sets cannot be verified; the next re-baseline pins them")
        return undecidable, warnings, changed
    for name, fp in sorted(base_pins.items()):
        now = cand_pins.get(name)
        if now is None:
            continue                                      # a vanished set is already undecidable through its missing metrics
        if now != fp:
            changed.append(name)
            undecidable.append("%s: eval set changed since the baseline (%s -> %s); a comparison across different holdout versions is invalid - "
                               "re-baseline on purpose or revert the set" % (name, fp, now))
    for name in sorted(set(cand_pins) - set(base_pins)):
        warnings.append("%s: eval set is new since the baseline (not compared)" % name)
    return undecidable, warnings, changed


def segment_gate(base: Optional[Dict[str, Dict[str, Any]]], cand: Optional[Dict[str, Dict[str, Any]]], delta: float = SEGMENT_DELTA,
                 min_n: int = MIN_SEGMENT_N) -> Tuple[List[str], List[str], List[str]]:
    """(failed, undecidable, thin) over ``{set: {segment: {n, recall|ood_rate, mrr}}}``.

    A segment present in the baseline with at least ``min_n`` items must keep each of its metrics within ``delta``;
    a vanished segment is undecidable (absent evidence is not a pass); thinner segments are only reported."""
    failed: List[str] = []
    undecidable: List[str] = []
    thin: List[str] = []
    cand = cand or {}
    for sname, segs in sorted((base or {}).items()):
        csegs = cand.get(sname)
        if csegs is None:
            continue                                      # the whole set vanished: undecidable through the set-level metrics
        for seg, bm in sorted((segs or {}).items()):
            if not isinstance(bm, dict):
                continue
            if int(bm.get("n") or 0) < min_n:
                thin.append("%s/%s (n=%s)" % (sname, seg, bm.get("n")))
                continue
            cm = csegs.get(seg)
            if cm is None:
                undecidable.append("%s/%s: the baseline has %s item(s) in this segment, the candidate has none" % (sname, seg, bm.get("n")))
                continue
            for k in ("recall", "mrr", "ood_rate"):
                b, c = bm.get(k), cm.get(k)
                if b is None:
                    continue
                if c is None:
                    undecidable.append("%s/%s %s: baseline %.3f, candidate has no value" % (sname, seg, k, b))
                elif c - b < -delta - 1e-9:
                    failed.append("segment %s/%s %s: %.3f -> %.3f (n=%s)" % (sname, seg, k, b, c, cm.get("n")))
    return failed, undecidable, thin


def composition(sets: Dict[str, Sequence[Dict[str, Any]]], min_n: int = MIN_SEGMENT_N) -> Dict[str, Dict[str, Any]]:
    """What each eval set is made of: size, out-of-domain share, topic and language mix, segments too thin to gate."""
    out: Dict[str, Dict[str, Any]] = {}
    for name, items in sets.items():
        segs: Dict[str, int] = {}
        for g in items:
            for s in segment_names(g):
                segs[s] = segs.get(s, 0) + 1
        n = len(items)
        ood = segs.get("ood", 0)
        langs = {s for s in segs if s.startswith("lang:")}
        out[name] = {"n": n, "in_domain": n - ood, "ood": ood, "ood_share": round(ood / n, 3) if n else None, "segments": dict(sorted(segs.items())),
                     "thin": sorted(s for s, c in segs.items() if c < min_n), "fingerprint": fingerprint(items),
                     "missing": sorted({"lang:ko", "lang:en"} - langs) if n - ood else []}       # a language with no in-domain query is not measured at all
    return out


def _grams(q: str) -> set:
    """Character trigrams of the normalised query: a Korean particle change (찾아 / 찾아요) keeps most of them, a whole-token overlap would lose them all."""
    n = norm(q)
    return {n[i:i + 3] for i in range(max(1, len(n) - 2))} if n else set()


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def leak_check(sets: Dict[str, Sequence[Dict[str, Any]]], chunks: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Findings that make an eval measurement untrustworthy (``blocking``) or wasteful (``warning``).

    * duplicate / near_duplicate - the same query in two sets (or twice in one); blocking when the holdout repeats a tuned-on set
    * in_corpus - the query text is copied verbatim into the corpus (trivially retrievable); blocking for the holdout
    * dangling_expectation - an expected source that matches no chunk: the item can never pass (blocking)
    """
    findings: List[Dict[str, Any]] = []
    entries: List[Tuple[str, str, str, set]] = [(name, g.get("q") or "", norm(g.get("q")), _grams(g.get("q"))) for name, items in sets.items() for g in items]

    def sev(a: str, b: str) -> str:
        return "blocking" if HOLDOUT in (a, b) and (a in TUNED or b in TUNED) else "warning"

    for i, (sa, qa, na, ta) in enumerate(entries):
        for sb, qb, nb, tb in entries[i + 1:]:
            if na == nb:
                findings.append({"kind": "duplicate", "sets": sorted({sa, sb}), "q": qa, "other": qb, "severity": sev(sa, sb) if sa != sb else "warning"})
            elif sa != sb and _jaccard(ta, tb) >= NEAR_DUP:
                findings.append({"kind": "near_duplicate", "sets": sorted({sa, sb}), "q": qa, "other": qb, "severity": sev(sa, sb)})
    if chunks is not None:
        texts = [norm(c.get("text")) + " " + norm(c.get("heading")) for c in chunks]
        sources = [str(c.get("source") or "") for c in chunks]
        for name, items in sets.items():
            for g in items:
                q = norm(g.get("q"))
                if len(q) >= MIN_CORPUS_Q and any(q in t for t in texts):
                    findings.append({"kind": "in_corpus", "sets": [name], "q": g.get("q"), "severity": "blocking" if name == HOLDOUT else "warning"})
                if g.get("ood"):
                    continue
                for e in g.get("expect") or []:
                    if not any(s.startswith(str(e)) for s in sources):
                        findings.append({"kind": "dangling_expectation", "sets": [name], "q": g.get("q"), "expect": e, "severity": "blocking"})
    blocking = [f for f in findings if f["severity"] == "blocking"]
    return {"findings": findings, "blocking": len(blocking), "warnings": len(findings) - len(blocking), "clean": not findings}


def injection_eval(samples: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Measured attack recall / benign precision of the product's context-layer injection guard
    (``conversation.scan_injection``) over a labelled attack/benign corpus (evals/injection_samples.jsonl,
    convention: {id, label: attack|benign, lang: en|ko|mixed, text}).

    A sample is "caught" when ``scan_injection`` reports at least one pattern hit on its text - the same
    detector the product runs on tool/retrieval output, read-only here. Honest by construction: if recall is
    below 1.0 the misses are returned, never hidden, and nothing about the guard itself is touched or loosened
    to make the number look better."""
    from . import conversation
    tp = fp = tn = fn = 0
    misses: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []
    by_lang: Dict[str, Dict[str, int]] = {}
    for s in samples or []:
        label = s.get("label")
        text = s.get("text") or ""
        sid = s.get("id")
        lang = s.get("lang") or lang_of(text)
        flagged = bool(conversation.scan_injection({"sample": text})["attempts"])
        bl = by_lang.setdefault(lang, {"attack_n": 0, "attack_hit": 0, "benign_n": 0, "benign_fp": 0})
        if label == "attack":
            bl["attack_n"] += 1
            if flagged:
                tp += 1
                bl["attack_hit"] += 1
            else:
                fn += 1
                misses.append({"id": sid, "lang": lang, "text": text})
        elif label == "benign":
            bl["benign_n"] += 1
            if flagged:
                fp += 1
                bl["benign_fp"] += 1
                false_positives.append({"id": sid, "lang": lang, "text": text})
            else:
                tn += 1
    attack_n, benign_n = tp + fn, tn + fp
    return {
        "attack_n": attack_n, "benign_n": benign_n,
        "recall": round(tp / attack_n, 3) if attack_n else None,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "benign_false_positive_rate": round(fp / benign_n, 3) if benign_n else None,
        "by_lang": {lg: dict(b, recall=round(b["attack_hit"] / b["attack_n"], 3) if b["attack_n"] else None,
                              false_positive_rate=round(b["benign_fp"] / b["benign_n"], 3) if b["benign_n"] else None)
                    for lg, b in sorted(by_lang.items())},
        "misses": misses, "false_positives": false_positives,
    }


def describe(f: Dict[str, Any]) -> str:
    """One line for a leak finding."""
    where = "/".join(f["sets"])
    if f["kind"] in ("duplicate", "near_duplicate"):
        return "%s [%s] %r ~ %r" % (f["kind"], where, f["q"][:50], f["other"][:50])
    if f["kind"] == "dangling_expectation":
        return "dangling_expectation [%s] %r expects %s, which matches no chunk" % (where, f["q"][:50], f["expect"])
    return "%s [%s] %r" % (f["kind"], where, str(f["q"])[:60])
