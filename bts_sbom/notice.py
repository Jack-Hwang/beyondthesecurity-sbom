"""OSS notice (고지문) generator: the document that lists the open source used, its copyright holders and licenses,
how to obtain the source code where a license requires it, and the full license texts.

Formats follow the FOSSLight Hub guide's notice types:
    html         OSS name, version, license, copyright, homepage, FULL license texts (each license printed once)
    text         the same content as plain text
    simple-html  like html, but license texts are replaced by links to the SPDX license page
    simple-text  like simple-html, as plain text
(SPDX / CycloneDX renderings of the same data are produced by ``ossreport.write_report``.)

What it will NOT do - the honesty contract of this project applies to legal text too:
  * it never writes a license text it does not have.  Texts are taken, in this order, from the item itself, from
    license files the source scanner found in the component's own tree, from ``license_dirs`` (<SPDX-ID>.txt), from the
    cache of previously fetched SPDX texts, and - only when ``fetch_license_texts`` is set - from the SPDX license list
    over the network.  A license without text is listed, flagged in the audit, and (in ``strict`` mode) fails the run.
  * it never invents a copyright holder.  Missing copyright is reported, not filled.
  * the written-offer paragraph is a TEMPLATE based on the common GPL-2.0 s.3(b) / GPL-3.0 s.6(b) wording; it is only
    emitted with a contact the caller supplies and is flagged in the audit as needing legal review.
This module produces documents from data; it gives no legal advice.
"""
from __future__ import annotations

import html
import os
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from bts_sbom import __version__
from bts_sbom.ossreport import OssItem, OssReport

FORMATS = ("html", "text", "simple-html", "simple-text")
_SPDX_PAGE = "https://spdx.org/licenses/%s.html"
_SPDX_TEXT_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/text/%s.txt"
_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,80}$")
MAX_LICENSE_TEXT = 1_000_000

_S = {
    "en": {
        "title": "Open Source Software Notice",
        "intro": "This product includes open source software. The software, its copyright notices and the licenses "
                 "under which it is distributed are listed below.",
        "used": "Open source software used", "name": "Name", "version": "Version", "license": "License",
        "copyright": "Copyright", "homepage": "Homepage", "source": "Source code availability",
        "texts": "License texts", "used_by": "Used by", "missing": "The text of this license is not included in this "
        "document (not available when it was generated).", "see": "Full text", "notices": "Additional notices",
        "unidentified": "(unidentified component)", "no_copyright": "(no copyright notice recorded)",
        "unverified": "license NOT verified - check before distribution",
        "download": "Source code / download location", "no_dl": "(not recorded)",
        "offer": "Written offer: for the software marked above, the corresponding source code is available on request. "
                 "Contact: {contact}. This offer is valid for {years} years from the date you received this "
                 "product; the source code will be provided on a physical medium for a charge not exceeding the cost "
                 "of physically performing the distribution.",
    },
    "ko": {
        "title": "오픈소스 소프트웨어 고지문",
        "intro": "본 제품은 오픈소스 소프트웨어를 포함하고 있습니다. 해당 소프트웨어와 저작권 고지, 배포 라이선스는 아래와 같습니다.",
        "used": "사용된 오픈소스 소프트웨어", "name": "이름", "version": "버전", "license": "라이선스",
        "copyright": "저작권", "homepage": "홈페이지", "source": "소스코드 제공",
        "texts": "라이선스 전문", "used_by": "사용처", "missing": "이 라이선스의 전문은 문서 생성 시점에 확보되지 않아 포함되어 있지 않습니다.",
        "see": "전문 보기", "notices": "추가 고지", "unidentified": "(출처 미확인 구성요소)",
        "unverified": "라이선스 미검증 - 배포 전 확인 필요",
        "no_copyright": "(기록된 저작권 고지 없음)", "download": "소스코드 / 다운로드 위치", "no_dl": "(기록 없음)",
        "offer": "서면 제안: 위에 표시된 소프트웨어에 대응하는 소스코드는 요청 시 제공됩니다. 문의처: {contact}. "
                 "본 제안은 제품을 수령한 날부터 {years}년간 유효하며, 소스코드는 물리적 배포에 소요되는 실비를 "
                 "초과하지 않는 금액으로 물리 매체에 담아 제공됩니다.",
    },
}


@dataclass
class NoticeOptions:
    fmt: str = "html"
    title: str = ""
    product: str = ""
    lang: str = "en"
    show_version: bool = True
    license_dirs: List[str] = field(default_factory=list)
    fetch_license_texts: bool = False
    cache_dir: str = ""
    contact: str = ""                  # enables the written-offer paragraph for source-disclosure licenses
    offer_years: int = 3
    include_excluded: bool = False
    include_dependencies: bool = True
    strict: bool = False
    fetcher: Any = None                # test hook: callable(url) -> str | None


@dataclass
class NoticeResult:
    text: str
    audit: Dict[str, Any]
    ok: bool


# ------------------------------------------------------------------------------------------ license text lookup
def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read(MAX_LICENSE_TEXT + 1)
    except OSError:
        return None
    if len(data) > MAX_LICENSE_TEXT:
        data = data[:MAX_LICENSE_TEXT] + "\n[... truncated ...]"
    return data.strip("\n") or None


def _from_dirs(lic: str, dirs: Iterable[str]) -> Optional[Tuple[str, str]]:
    want = lic.lower()
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in sorted(names):
            stem = os.path.splitext(n)[0].lower()
            if stem == want or n.lower() == want:
                t = _read_text(os.path.join(d, n))
                if t:
                    return t, "file:" + os.path.join(d, n)
    return None


def _http_fetch(url: str) -> Optional[str]:
    if not url.startswith("https://"):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom-notice/" + __version__})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read(MAX_LICENSE_TEXT + 1).decode("utf-8", "replace")
    except Exception:
        return None


class _TextResolver:
    def __init__(self, opts: NoticeOptions) -> None:
        self.opts = opts
        self.memo: Dict[str, Optional[Tuple[str, str]]] = {}

    def resolve(self, lic: str, items: List[OssItem]) -> Optional[Tuple[str, str]]:
        key = lic.lower()
        if key in self.memo and self.memo[key] is not None:
            return self.memo[key]
        found: Optional[Tuple[str, str]] = None
        for it in items:                                           # 1. text carried by the item / its own tree
            lt = (it.extra.get("license_texts") or {}) if isinstance(it.extra, dict) else {}
            for k, v in lt.items():
                if k.lower() == key and v:
                    found = (str(v).strip("\n"), "component license file")
                    break
            if found is None and it.license_text and len(it.licenses) == 1 and it.licenses[0].lower() == key:
                found = (it.license_text.strip("\n"), "report")
            if found:
                break
        if found is None:                                          # 2. user-supplied directory
            found = _from_dirs(lic, self.opts.license_dirs)
        if found is None and self.opts.cache_dir:                  # 3. cache of SPDX texts
            found = _from_dirs(lic, [self.opts.cache_dir])
        if found is None and self.opts.fetch_license_texts and _ID_OK.match(lic):   # 4. SPDX list, opt-in network
            fetcher = self.opts.fetcher or _http_fetch
            t = fetcher(_SPDX_TEXT_URL % lic)
            if t and t.strip():
                found = (t.strip("\n"), "spdx license list (fetched)")
                if self.opts.cache_dir:
                    try:
                        os.makedirs(self.opts.cache_dir, exist_ok=True)
                        with open(os.path.join(self.opts.cache_dir, lic + ".txt"), "w", encoding="utf-8") as fh:
                            fh.write(t)
                    except OSError:
                        pass
        self.memo[key] = found
        return found


# ------------------------------------------------------------------------------------------- model building
@dataclass
class _Entry:
    name: str
    version: str
    licenses: List[str]
    copyright: str
    homepage: str
    download: str
    paths: List[str]
    items: List[OssItem]
    source_code: bool = False
    notices: List[str] = field(default_factory=list)
    needs_check: bool = False                  # at least one sighting's license/identity is a guess, not a finding
    check_comments: List[str] = field(default_factory=list)


def _license_ids(expr: str) -> List[Tuple[str, bool]]:
    """[(license id as written, is_spdx_expression_member)] for one license string (exceptions included)."""
    from bts_sbom._internal import license_spdx
    expr = (expr or "").strip()
    if not expr:
        return []
    try:
        node = license_spdx.parse_expression(expr)
    except Exception:
        return [(expr, False)]
    out: List[Tuple[str, bool]] = []
    for a in license_spdx.iter_atoms(node):
        for ident in (a.raw or a.ident, a.raw_exception or a.exception):
            if ident and (ident, True) not in out:
                out.append((ident, True))
    return out


_EXPR_SPLIT = re.compile(r"(\s+|[()])")


def _expr_html(lic: str) -> str:
    """One license string as HTML: every license/exception id is a link to its text, the AND / OR / WITH operators and
    parentheses stay - ``(MIT OR GPL-2.0-only)`` must not be flattened to a list that reads as 'all of them'."""
    ids = {i for i, _s in _license_ids(lic)}
    h = html.escape
    if len(ids) <= 1 and (not ids or next(iter(ids)) == lic.strip()):
        return '<a href="#%s">%s</a>' % (h(_anchor(lic.strip())), h(lic.strip())) if ids else h(lic)
    out = []
    for tok in _EXPR_SPLIT.split(lic):
        if tok in ids:
            out.append('<a href="#%s">%s</a>' % (h(_anchor(tok)), h(tok)))
        else:
            out.append(h(tok))
    return "".join(out)


def _safe_url(u: str) -> str:
    u = (u or "").strip()
    return u if re.match(r"^https?://", u, re.I) and " " not in u else ""


def _is_proprietary(lic: str) -> bool:
    return bool(re.search(r"proprietary|commercial|all rights reserved", lic or "", re.I))


def _build_entries(report: OssReport, opts: NoticeOptions, audit: Dict[str, Any]) -> List[_Entry]:
    from bts_sbom._internal.license_utils import get_license_obligations
    merged: Dict[Tuple, _Entry] = {}
    skipped_inhouse = 0
    # the same package seen in several manifests (package.json without a license, package-lock.json with one): the licensed
    # sighting is the component; the licence-less duplicate is not a second component
    licensed = {((i.oss_name or "").lower(), i.version) for i in report.items if i.oss_name and i.oss_name != "-" and i.licenses}
    for it in report.items:
        if it.exclude and not opts.include_excluded:
            audit["excluded_items"] += 1
            continue
        if it.kind == "dep" and not opts.include_dependencies:
            continue
        lic_list = [lic for lic in it.licenses if lic and lic.strip() and lic.strip() != "-"]
        if not lic_list and it.oss_name and (it.oss_name.lower(), it.version) in licensed:
            audit["duplicate_sightings_without_license_merged"] = audit.get("duplicate_sightings_without_license_merged", 0) + 1
            continue
        if it.kind == "src" and not lic_list:
            audit["source_files_without_license_not_listed"] = audit.get("source_files_without_license_not_listed", 0) + 1
            continue                            # a source file with no detected license is not an attributable component
        if (it.oss_name or "") == "-" and (not lic_list or all(_is_proprietary(lic) for lic in lic_list)):
            skipped_inhouse += 1
            continue
        if all(_is_proprietary(lic) for lic in lic_list) and lic_list:
            skipped_inhouse += 1
            continue
        name = it.oss_name if it.oss_name and it.oss_name != "-" else ""
        key = (name.lower(), it.version, tuple(sorted(lic.lower() for lic in lic_list)), it.copyright.strip(),
               "" if name else it.source_path)
        e = merged.get(key)
        if e is None:
            e = merged[key] = _Entry(name=name, version=it.version, licenses=list(lic_list), copyright=it.copyright.strip(),
                                     homepage=_safe_url(it.homepage), download=_safe_url(it.download_location),
                                     paths=[], items=[])
        if it.source_path and it.source_path not in e.paths:
            e.paths.append(it.source_path)
        e.items.append(it)
        e.homepage = e.homepage or _safe_url(it.homepage)
        e.download = e.download or _safe_url(it.download_location)
        if it.needs_check:
            e.needs_check = True
            c = (it.comment or "").strip()
            if c and c not in e.check_comments:
                e.check_comments.append(c)
        nf = (it.extra or {}).get("notice_file") if isinstance(it.extra, dict) else None
        if nf and nf not in e.notices:
            e.notices.append(str(nf).strip("\n"))
    audit["in_house_or_proprietary_skipped"] = skipped_inhouse
    entries = sorted(merged.values(), key=lambda e: ((e.name or "~").lower(), e.version, e.paths[:1]))
    for e in entries:
        if e.licenses:
            expr = " AND ".join("(%s)" % lic if re.search(r"\s(AND|OR|WITH)\s", lic) else lic for lic in e.licenses)
            try:
                e.source_code = bool(get_license_obligations(expr).get("source_code"))
            except Exception:
                e.source_code = False
    return entries


def _license_index(entries: List[_Entry]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        for lic in e.licenses:
            for ident, is_spdx in _license_ids(lic):
                rec = idx.setdefault(ident.lower(), {"id": ident, "spdx": is_spdx, "entries": [], "items": []})
                if e not in rec["entries"]:
                    rec["entries"].append(e)
                    rec["items"].extend(e.items)
    return idx


def _anchor(s: str) -> str:
    return "lic-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip("-")


def _label(e: _Entry, lang: str) -> str:
    return e.name or ("%s %s" % (_S[lang]["unidentified"], e.paths[0] if e.paths else "")).strip()


# --------------------------------------------------------------------------------------------------- renderers
_CSS = ("body{font-family:Arial,Helvetica,sans-serif;max-width:980px;margin:2em auto;padding:0 1em;color:#222}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:6px 8px;text-align:left;"
        "vertical-align:top;font-size:14px}th{background:#f0f0f0}pre{white-space:pre-wrap;background:#f7f7f7;"
        "border:1px solid #ddd;padding:10px;font-size:13px}h2{margin-top:2em}.warn{color:#a00}")


def _render_html(entries: List[_Entry], idx: Dict[str, Dict[str, Any]], texts: Dict[str, Optional[Tuple[str, str]]],
                 opts: NoticeOptions, offer: Optional[str], simple: bool) -> str:
    L = _S[opts.lang]
    h = html.escape
    out = ['<!DOCTYPE html>', '<html lang="%s"><head><meta charset="utf-8">' % opts.lang,
           "<title>%s</title><style>%s</style></head><body>" % (h(opts.title or L["title"]), _CSS),
           "<h1>%s</h1>" % h(opts.title or L["title"])]
    if opts.product:
        out.append("<p><strong>%s</strong></p>" % h(opts.product))
    out.append("<p>%s</p>" % h(L["intro"]))
    out.append("<h2>%s</h2><table><tr><th>%s</th>%s<th>%s</th><th>%s</th><th>%s</th></tr>" % (
        h(L["used"]), h(L["name"]), "<th>%s</th>" % h(L["version"]) if opts.show_version else "", h(L["license"]),
        h(L["copyright"]), h(L["homepage"])))
    for e in entries:
        links = [_expr_html(lic) for lic in e.licenses]
        if e.needs_check:
            links.append('<span class="warn">%s</span>' % h(L["unverified"]))
            links.extend('<span class="warn">%s</span>' % h(c) for c in e.check_comments)
        cr = h(e.copyright).replace("\n", "<br>") if e.copyright else '<span class="warn">%s</span>' % h(L["no_copyright"])
        home = '<a href="%s">%s</a>' % (h(e.homepage, quote=True), h(e.homepage)) if e.homepage else ""
        out.append("<tr><td>%s</td>%s<td>%s</td><td>%s</td><td>%s</td></tr>" % (
            h(_label(e, opts.lang)), "<td>%s</td>" % h(e.version) if opts.show_version else "",
            "<br>".join(links) or "&nbsp;", cr, home))
    out.append("</table>")
    src = [e for e in entries if e.source_code]
    if src:
        out.append("<h2>%s</h2><ul>" % h(L["source"]))
        for e in src:
            dl = ('<a href="%s">%s</a>' % (h(e.download, quote=True), h(e.download))) if e.download else h(L["no_dl"])
            out.append("<li>%s %s &mdash; %s: %s</li>" % (h(_label(e, opts.lang)), h(e.version if opts.show_version else ""), h(L["download"]), dl))
        out.append("</ul>")
        if offer:
            out.append("<p>%s</p>" % h(offer))
    notices = [(e, n) for e in entries for n in e.notices]
    if notices:
        out.append("<h2>%s</h2>" % h(L["notices"]))
        for e, n in notices:
            out.append("<h3>%s</h3><pre>%s</pre>" % (h(_label(e, opts.lang)), h(n)))
    out.append("<h2>%s</h2>" % h(L["texts"]))
    for key in sorted(idx):
        rec = idx[key]
        ident = rec["id"]
        users = ", ".join(_label(e, opts.lang) for e in rec["entries"])
        out.append('<h3 id="%s">%s</h3><p>%s: %s</p>' % (h(_anchor(ident)), h(ident), h(L["used_by"]), h(users)))
        if simple and rec["spdx"] and _ID_OK.match(ident):
            url = _SPDX_PAGE % ident
            out.append('<p>%s: <a href="%s">%s</a></p>' % (h(L["see"]), h(url), h(url)))
        elif texts.get(key):
            out.append("<pre>%s</pre>" % h(texts[key][0]))
        else:
            out.append('<p class="warn">%s</p>' % h(L["missing"]))
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def _render_text(entries: List[_Entry], idx: Dict[str, Dict[str, Any]], texts: Dict[str, Optional[Tuple[str, str]]],
                 opts: NoticeOptions, offer: Optional[str], simple: bool) -> str:
    L = _S[opts.lang]
    bar = "=" * 78
    out = [bar, opts.title or L["title"], bar, ""]
    if opts.product:
        out += [opts.product, ""]
    out += [L["intro"], "", L["used"], "-" * 78]
    for e in entries:
        head = _label(e, opts.lang) + ((" " + e.version) if opts.show_version and e.version else "")
        out.append(head)
        out.append("  %s: %s" % (L["license"], ", ".join(e.licenses) or "-"))
        if e.needs_check:
            out.append("  ! %s" % L["unverified"])
            out.extend("    %s" % c for c in e.check_comments)
        out.append("  %s: %s" % (L["copyright"], (e.copyright.replace("\n", "\n    ") if e.copyright else L["no_copyright"])))
        if e.homepage:
            out.append("  %s: %s" % (L["homepage"], e.homepage))
        out.append("")
    src = [e for e in entries if e.source_code]
    if src:
        out += [L["source"], "-" * 78]
        for e in src:
            out.append("%s %s - %s: %s" % (_label(e, opts.lang), e.version if opts.show_version else "", L["download"], e.download or L["no_dl"]))
        out.append("")
        if offer:
            out += [offer, ""]
    for e in entries:
        for n in e.notices:
            out += [L["notices"] + ": " + _label(e, opts.lang), "-" * 78, n, ""]
    out += [L["texts"], bar, ""]
    for key in sorted(idx):
        rec = idx[key]
        ident = rec["id"]
        out += [ident, "-" * len(ident), "%s: %s" % (L["used_by"], ", ".join(_label(e, opts.lang) for e in rec["entries"])), ""]
        if simple and rec["spdx"] and _ID_OK.match(ident):
            out += ["%s: %s" % (L["see"], _SPDX_PAGE % ident), ""]
        elif texts.get(key):
            out += [texts[key][0], ""]
        else:
            out += [L["missing"], ""]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------------- public API
def build_notice(report: OssReport, opts: Optional[NoticeOptions] = None) -> NoticeResult:
    opts = opts or NoticeOptions()
    if opts.fmt not in FORMATS:
        raise ValueError("unknown notice format %r (choose from %s)" % (opts.fmt, ", ".join(FORMATS)))
    if opts.lang not in _S:
        raise ValueError("unknown language %r (choose from %s)" % (opts.lang, ", ".join(_S)))
    audit: Dict[str, Any] = {"generator": "bts-sbom %s" % __version__, "format": opts.fmt, "excluded_items": 0}
    entries = _build_entries(report, opts, audit)
    idx = _license_index(entries)
    resolver = _TextResolver(opts)
    simple = opts.fmt.startswith("simple")
    texts: Dict[str, Optional[Tuple[str, str]]] = {}
    for key, rec in idx.items():
        texts[key] = resolver.resolve(rec["id"], rec["items"])
    missing_text = sorted(rec["id"] for key, rec in idx.items()
                          if not texts.get(key) and not (simple and rec["spdx"] and _ID_OK.match(rec["id"])))
    no_license = sorted(_label(e, opts.lang) for e in entries if not e.licenses)
    unverified = sorted(_label(e, opts.lang) for e in entries if e.needs_check)
    no_copyright = sorted(_label(e, opts.lang) for e in entries if not e.copyright)
    multi = sorted(_label(e, opts.lang) for e in entries if len(e.licenses) > 1)
    or_choice = sorted(_label(e, opts.lang) for e in entries if any(re.search(r"\sOR\s", lic) for lic in e.licenses))
    src_items = [e for e in entries if e.source_code]
    offer = None
    if src_items and opts.contact:
        offer = _S[opts.lang]["offer"].format(contact=opts.contact, years=int(opts.offer_years))
    no_download = sorted(_label(e, opts.lang) for e in src_items if not e.download)
    audit.update({
        "components": len(entries),
        "licenses": sorted(rec["id"] for rec in idx.values()),
        "license_text_sources": {rec["id"]: (texts[k][1] if texts.get(k) else None) for k, rec in sorted(idx.items())},
        "missing_license_text": missing_text,
        "components_without_license": no_license,
        "components_with_unverified_license": unverified,
        "components_without_copyright": no_copyright,
        "components_with_multiple_licenses_treated_as_AND": multi,
        "components_with_OR_choice_not_recorded": or_choice,
        "source_disclosure_components": [_label(e, opts.lang) for e in src_items],
        "source_disclosure_without_download_location": no_download,
        "written_offer": ("included (TEMPLATE - have legal counsel review the wording)" if offer else
                          ("NOT included: source-disclosure licenses present but no --contact was given" if src_items else
                           "not needed (no source-disclosure license)")),
    })
    problems = []
    if missing_text:
        problems.append("%d license text(s) missing" % len(missing_text))
    if no_license:
        problems.append("%d component(s) without a license" % len(no_license))
    if unverified:
        problems.append("%d component(s) whose license/identity is unverified (needs check)" % len(unverified))
    if src_items and not offer:
        problems.append("source-disclosure license without a written-offer contact")
    if no_download:
        problems.append("%d source-disclosure component(s) without a download location" % len(no_download))
    audit["problems"] = problems
    audit["complete"] = not problems
    renderer = _render_html if opts.fmt.endswith("html") else _render_text
    text = renderer(entries, idx, texts, opts, offer, simple)
    return NoticeResult(text=text, audit=audit, ok=(not problems) or not opts.strict)


def write_notice(result: NoticeResult, dest: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(result.text)
    return dest
