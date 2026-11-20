"""Minimal XLSX writer/reader (stdlib: zipfile + xml.etree) for OSS reports.

Writer: text cells only (inline strings), a bold header row, optional hidden columns and column widths.  Because every
cell is a string cell, text that begins with '=' is never evaluated as a formula by a spreadsheet.
Reader: shared strings, inline strings and numbers; formulas are NOT evaluated (cached values are read as-is).
Bounds: the reader refuses archives with too many entries / too large uncompressed content (zip bombs) and never
resolves external entities (ElementTree on a closed-DTD-free tree; DOCTYPE is rejected).
"""
from __future__ import annotations

import re
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from xml.etree import ElementTree as ET

MAX_ENTRIES = 200
MAX_UNCOMPRESSED = 128 * 1024 * 1024
MAX_CELL = 32000
_ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")
_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
       "pr": "http://schemas.openxmlformats.org/package/2006/relationships"}


class XlsxError(ValueError):
    pass


def _esc(s: str) -> str:
    s = _ILLEGAL_XML.sub("", s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def _col_letter(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def safe_sheet_name(name: str, used: Set[str]) -> str:
    n = re.sub(r"[\[\]:*?/\\]", "_", name)[:31] or "Sheet"
    base, k = n, 2
    while n.lower() in used:
        suffix = "_%d" % k
        n = base[:31 - len(suffix)] + suffix
        k += 1
    used.add(n.lower())
    return n


class Sheet:
    def __init__(self, name: str, headers: Sequence[str], rows: Iterable[Sequence[Any]],
                 hidden: Iterable[int] = (), widths: Optional[Dict[int, int]] = None) -> None:
        self.name = name
        self.headers = list(headers)
        self.rows = [list(r) for r in rows]
        self.hidden = set(hidden)
        self.widths = dict(widths or {})


def _sheet_xml(sh: Sheet) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="%s">' % _NS["m"]]
    ncols = max([len(sh.headers)] + [len(r) for r in sh.rows] or [1])
    cols = []
    for i in range(ncols):
        w = sh.widths.get(i, 24 if i < len(sh.headers) else 14)
        hid = ' hidden="1"' if i in sh.hidden else ""
        cols.append('<col min="%d" max="%d" width="%d" customWidth="1"%s/>' % (i + 1, i + 1, w, hid))
    out.append("<cols>%s</cols>" % "".join(cols))
    out.append("<sheetData>")

    def cell(ref: str, v: Any, style: int = 0) -> str:
        if v is None or v == "":
            return ""
        if isinstance(v, bool):
            v = "True" if v else "False"
        s = str(v)
        if len(s) > MAX_CELL:
            s = s[:MAX_CELL - 20] + " ...[truncated]"
        return '<c r="%s" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>' % (
            ref, ' s="1"' if style else "", _esc(s))

    r = 1
    if sh.headers:
        out.append('<row r="1">%s</row>' % "".join(cell("%s1" % _col_letter(i), h, 1) for i, h in enumerate(sh.headers)))
        r = 2
    for row in sh.rows:
        cells = "".join(cell("%s%d" % (_col_letter(i), r), v) for i, v in enumerate(row))
        out.append('<row r="%d">%s</row>' % (r, cells))
        r += 1
    out.append("</sheetData></worksheet>")
    return "".join(out)


def write_xlsx(dest: Any, sheets: Sequence[Sheet]) -> None:
    """``dest`` is a path or a binary file object."""
    if not sheets:
        raise XlsxError("a workbook needs at least one sheet")
    used: Set[str] = set()
    names = [safe_sheet_name(s.name, used) for s in sheets]
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
          '<Default Extension="xml" ContentType="application/xml"/>',
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    for i in range(len(sheets)):
        ct.append('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % (i + 1))
    ct.append("</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>")
    wb = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
          '<workbook xmlns="%s" xmlns:r="%s"><sheets>' % (_NS["m"], _NS["r"])]
    wbrels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i, n in enumerate(names):
        wb.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (_esc(n), i + 1, i + 1))
        wbrels.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1))
    wb.append("</sheets></workbook>")
    wbrels.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (len(names) + 1))
    wbrels.append("</Relationships>")
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<styleSheet xmlns="%s"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
              '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
              '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
              '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
              '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>' % _NS["m"])
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "".join(ct))
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", "".join(wb))
        zf.writestr("xl/_rels/workbook.xml.rels", "".join(wbrels))
        zf.writestr("xl/styles.xml", styles)
        for i, sh in enumerate(sheets):
            zf.writestr("xl/worksheets/sheet%d.xml" % (i + 1), _sheet_xml(sh))


# ---------------------------------------------------------------------------------------------------- reader
def _parse(data: bytes) -> ET.Element:
    from bts_sbom._internal import safe_xml
    try:
        return safe_xml.fromstring(data)           # DTD / ENTITY refused wherever it sits, in any encoding
    except safe_xml.DtdNotAllowed:
        raise XlsxError("DOCTYPE/ENTITY declarations are not allowed in workbook XML")
    except ET.ParseError as exc:
        raise XlsxError("malformed workbook XML: %s" % exc)


def _text_of(si: ET.Element) -> str:
    return "".join(t.text or "" for t in si.iter("{%s}t" % _NS["m"]))


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref or "")
    if not letters:
        return 0
    n = 0
    for ch in letters.group(0):
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def read_xlsx(src: Any) -> Dict[str, List[List[str]]]:
    """{sheet name: rows of text}; empty trailing cells are kept as '' so columns line up."""
    try:
        zf = zipfile.ZipFile(src)
    except zipfile.BadZipFile as exc:
        raise XlsxError("not an XLSX file: %s" % exc)
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise XlsxError("workbook has %d parts (limit %d)" % (len(infos), MAX_ENTRIES))
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
            raise XlsxError("workbook expands beyond %d bytes" % MAX_UNCOMPRESSED)
        names = set(zf.namelist())
        if "xl/workbook.xml" not in names:
            raise XlsxError("xl/workbook.xml missing - not a spreadsheet workbook")
        wb = _parse(zf.read("xl/workbook.xml"))
        rels = {}
        if "xl/_rels/workbook.xml.rels" in names:
            for rel in _parse(zf.read("xl/_rels/workbook.xml.rels")):
                rels[rel.get("Id")] = rel.get("Target", "")
        shared: List[str] = []
        if "xl/sharedStrings.xml" in names:
            shared = [_text_of(si) for si in _parse(zf.read("xl/sharedStrings.xml")).findall("m:si", _NS)]
        out: Dict[str, List[List[str]]] = {}
        for sh in wb.findall("m:sheets/m:sheet", _NS):
            rid = sh.get("{%s}id" % _NS["r"])
            target = rels.get(rid, "")
            path = target.lstrip("/") if target.startswith("/") else "xl/" + target
            if path not in names:
                continue
            root = _parse(zf.read(path))
            rows: List[List[str]] = []
            for row in root.findall("m:sheetData/m:row", _NS):
                vals: List[str] = []
                for c in row.findall("m:c", _NS):
                    idx = _col_index(c.get("r", ""))
                    while len(vals) < idx:
                        vals.append("")
                    t = c.get("t")
                    v = c.find("m:v", _NS)
                    if t == "inlineStr":
                        text = _text_of(c.find("m:is", _NS)) if c.find("m:is", _NS) is not None else ""
                    elif t == "s" and v is not None and (v.text or "").isdigit() and int(v.text) < len(shared):
                        text = shared[int(v.text)]
                    else:
                        text = (v.text or "") if v is not None else ""
                    vals.append(text)
                rows.append(vals)
            out[sh.get("name", "Sheet")] = rows
        return out
