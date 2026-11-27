"""Clean-room lane for C / C++ (reimpl_c.py, reached through reimpl.reimpl by file extension).

The generator is a scripted fake client; everything else is real: the parser, the rendered header, gcc, nm, the generated driver. Tests that need
a compiler skip when none is on PATH. The u-boot cases (real GPL code) skip when the checkout is absent.
"""
from __future__ import annotations

import json
import os
import shutil
import textwrap
from typing import Any, Dict, List

import pytest

from bts_sbom_app import cparse, reimpl, reimpl_c

UBOOT = os.environ.get("BTS_SBOM_UBOOT", "C:/firebaseprojects/usertest/u-boot")
TC = reimpl_c.toolchain()
needs_cc = pytest.mark.skipif(not TC["cc"], reason="no C compiler on PATH")


def _d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


HEADER = _d('''
    /* SPDX-License-Identifier: GPL-2.0-or-later */
    #ifndef MYLIB_CRC_H
    #define MYLIB_CRC_H
    #include <stddef.h>
    #include <stdint.h>
    #define MYLIB_CRC_INIT 0xFFu
    typedef struct mylib_cfg { int width; unsigned char poly; } mylib_cfg;
    /**
     * my_crc8() - CRC-8 (polynomial x^8 + x^2 + x + 1, MSB first) of a buffer
     * @crc: starting value, chain calls by passing the previous result
     * @buf: data
     * @len: number of bytes
     * Return: the updated 8-bit CRC
     */
    unsigned int my_crc8(unsigned int crc, const unsigned char *buf, int len);
    /** my_hex() - convert bytes to lower-case hex text; returns characters written, output is NUL terminated */
    int my_hex(char *out, const unsigned char *in, size_t len);
    /** my_clamp() - limit @v to the closed range [@lo, @hi] */
    int my_clamp(int v, int lo, int hi);
    /** my_cfg_width() - the configured width */
    int my_cfg_width(const mylib_cfg *c);
    extern const unsigned char my_tbl[4];
    #endif
''')
ORIGINAL = _d('''
    // SPDX-License-Identifier: GPL-2.0-or-later
    /* Copyright (c) 2020 Example Authors */
    #include <mylib/crc.h>

    const unsigned char my_tbl[4] = { 0x10, 0x20, 0x30, 0x40 };

    static unsigned char step(unsigned int v)
    {
        int i;
        for (i = 0; i < 8; i++)
            v = (v & 0x80) ? ((v << 1) ^ 0x07) : (v << 1);
        return (unsigned char)v;
    }

    unsigned int my_crc8(unsigned int crc, const unsigned char *buf, int len)
    {
        int i;
        crc &= 0xFF;
        for (i = 0; i < len; i++)
            crc = step(crc ^ buf[i]);
        return crc;
    }

    int my_hex(char *out, const unsigned char *in, size_t len)
    {
        static const char digits[] = "0123456789abcdef";
        size_t i;
        for (i = 0; i < len; i++) {
            out[2 * i] = digits[in[i] >> 4];
            out[2 * i + 1] = digits[in[i] & 15];
        }
        out[2 * len] = '\\0';
        return (int)(2 * len);
    }

    int my_clamp(int v, int lo, int hi)
    {
        if (v < lo)
            return lo;
        if (v > hi)
            return hi;
        return v;
    }

    int my_cfg_width(const mylib_cfg *c)
    {
        return c->width;
    }
''')
UPSTREAM_TEST = _d('''
    #include <stdio.h>
    #include <mylib/crc.h>
    int main(void) {
        unsigned char d[] = {'1','2','3','4','5','6','7','8','9'};
        if (my_crc8(0, d, 9) != 0xF4) { printf("crc mismatch\\n"); return 1; }
        if (my_clamp(5, 0, 3) != 3) return 1;
        return 0;
    }
''')
GOOD = _d('''
    #include "mycrc_cr.h"

    const unsigned char my_tbl[4] = { 0x10, 0x20, 0x30, 0x40 };
    static unsigned char table[256];
    static int ready;

    static void build(void)
    {
        for (unsigned i = 0; i < 256; i++) {
            unsigned r = i;
            for (int k = 0; k < 8; k++)
                r = (r & 0x80u) ? (((r << 1) ^ 0x07u) & 0xFFu) : ((r << 1) & 0xFFu);
            table[i] = (unsigned char)r;
        }
        ready = 1;
    }

    unsigned int my_crc8(unsigned int crc, const unsigned char *buf, int len)
    {
        unsigned c = crc & 0xFFu;
        if (!ready)
            build();
        while (len-- > 0)
            c = table[(c ^ *buf++) & 0xFFu];
        return c;
    }

    int my_hex(char *out, const unsigned char *in, size_t len)
    {
        const char *hex = "0123456789abcdef";
        char *p = out;
        for (size_t i = 0; i < len; i++) {
            *p++ = hex[(in[i] >> 4) & 0xF];
            *p++ = hex[in[i] & 0xF];
        }
        *p = 0;
        return (int)(p - out);
    }

    int my_clamp(int v, int lo, int hi)
    {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    int my_cfg_width(const mylib_cfg *c)
    {
        return c ? c->width : 0;
    }
''')
BAD_POLY = GOOD.replace("0x07u", "0x31u")
BAD_TABLE = GOOD.replace("0x30, 0x40", "0x30, 0x41")


class Fake:
    """Scripted generator: returns the queued code per call (the last one repeats) and records every system prompt."""
    available = True

    def __init__(self, *codes: str) -> None:
        self.codes, self.systems = list(codes), []

    def complete(self, system: str, user: str, max_tokens: int = 0, json_mode: bool = False) -> str:
        self.systems.append(system)
        return json.dumps({"code": self.codes.pop(0) if len(self.codes) > 1 else self.codes[0]})


def _project(tmp_path, files: Dict[str, str] = None, name: str = "proj") -> str:
    root = tmp_path / name
    for rel, txt in {"include/mylib/crc.h": HEADER, "src/mycrc.c": ORIGINAL, "tests/test_mycrc.c": UPSTREAM_TEST, **(files or {})}.items():
        fp = root / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(txt, encoding="utf-8", newline="\n")
    return str(root)


def _run(root: str, tmp_path, client: Any, component: str = "src/mycrc.c", attempts: int = 2, **kw: Any):
    events: List[str] = []
    out = str(tmp_path / ("out_%d" % len(os.listdir(str(tmp_path)))))
    r = reimpl.reimpl(root, component, out, client=client, attempts=attempts, progress=lambda e: events.append(e["event"]), **kw)
    return r, events, out


# ============================================================================================ wall 1: the interface
def test_interface_is_read_from_the_header_and_the_component_without_any_body(tmp_path):
    """AC: BSA-AC-638. The reader exports prototypes, the doc contracts, the types/macros/constants/data the API needs and the paired header, and nothing of
    the bodies: no body statement of the original appears in the interface, in the spec or in the rendered header (5 of 5 artefacts checked)."""
    root = _project(tmp_path)
    iface = reimpl_c.extract_interface_c(root, "src/mycrc.c")
    assert iface["module"] == "mycrc" and iface["language"] == "c" and iface["paired_headers"] == ["include/mylib/crc.h"]
    assert [f["name"] for f in iface["functions"]] == ["my_crc8", "my_hex", "my_clamp", "my_cfg_width"]                # `step` is static: private, not exported
    f0 = iface["functions"][0]
    assert f0["proto"] == "unsigned int my_crc8(unsigned int crc, const unsigned char *buf, int len)" and "polynomial x^8 + x^2 + x + 1" in f0["doc"]
    assert [m["name"] for m in iface["macros"]] == ["MYLIB_CRC_INIT"]
    assert [(t["kind"], t["name"]) for t in iface["types"]] == [("struct", "mylib_cfg"), ("typedef", "mylib_cfg")]     # the struct tag AND its typedef alias
    assert [(v["name"], v["array"]) for v in iface["variables"]] == [("my_tbl", "[4]")]
    spec = reimpl_c.spec_document_c(iface, "test", "mycrc_cr.h")
    header = reimpl_c.render_header(iface)
    blob = json.dumps(iface) + spec + header
    for body_text in ("0x07", "digits[in[i]", "crc &= 0xFF", "(v & 0x80)", "Copyright (c) 2020 Example", "return c->width"):
        assert body_text not in blob
    assert "my_crc8" in spec and "SPDX" not in spec and "Clean-room rule" in spec


@needs_cc
def test_rendered_header_is_self_contained_and_compiles_alone_in_c_and_cpp(tmp_path):
    """AC: BSA-AC-638. The deterministic header (types in dependency order, forward declarations, kernel-style integer typedefs defined when used, extern C guard)
    compiles by itself as C and as C++ - for a header with a struct, an anonymous typedef struct, an enum and a u16 prototype (4 of 4 constructs)."""
    src = _d('''
        typedef struct { u32 total[2]; u8 buf[64]; } hctx;
        typedef enum { E_A, E_B = 4 } emode;
        struct node { struct node *next; hctx *ctx; };
        u16 sum16(u16 crc, const u8 *p, size_t n);
        int walk(struct node *n, emode m);
    ''')
    iface = {"module": "m", "language": "c", "functions": [], "variables": [], "macros": [], "kernel_types": [], "types": []}
    model = cparse.parse(src, "x.h")
    iface["functions"] = [dict(f) for f in model["functions"]]
    iface["types"] = model["types"]
    text = reimpl_c.render_header(iface)
    assert "typedef uint16_t u16;" in text and "typedef struct {" in text and text.index("struct node;") < text.index("typedef struct {")
    d = str(tmp_path)
    open(os.path.join(d, "h.h"), "w").write(text)
    open(os.path.join(d, "h.c"), "w").write('#include "h.h"\nint main(void){return 0;}\n')
    assert reimpl_c.compile_object(TC, os.path.join(d, "h.c"), os.path.join(d, "h.o"), [d], [])["ok"]
    if TC["cxx"]:
        open(os.path.join(d, "h.cpp"), "w").write('#include "h.h"\nint main(){return 0;}\n')
        assert reimpl_c.compile_object(TC, os.path.join(d, "h.cpp"), os.path.join(d, "h2.o"), [d], [])["ok"]


# ============================================================================================ the copy gate
def test_copy_gate_catches_a_renamed_copy_ignores_forced_signatures_tables_and_flags_tiny_bodies(tmp_path):
    """AC: BSA-AC-638. 5 of 5 gate behaviours: a renamed copy of the original (every identifier changed) is caught by the identifier-normalised token overlap
    (1.0) where line shingles alone would see 0; an independent implementation passes (<0.30); the API prototypes and numeric table rows are not evidence
    of copying; a tiny body is reported unreliable instead of silently passing; license strings fail the gate."""
    protos = {f["proto"] for f in cparse.parse(HEADER, "h.h")["functions"]}
    renamed = ORIGINAL
    for a, b in (("step", "advance"), ("crc", "acc"), ("digits", "alphabet"), ("buf", "data"), ("out", "dst"), ("len", "n"), ("lo", "low"), ("hi", "high")):
        renamed = renamed.replace(a, b)
    g = reimpl_c.copy_gate(renamed, ORIGINAL, ignore_lines=protos)
    assert g["token_overlap"] >= 0.9 and not g["passed"] and g["reliable"]
    g2 = reimpl_c.copy_gate(GOOD, ORIGINAL, ignore_lines=protos)
    assert g2["passed"] and g2["token_overlap"] < 0.30 and g2["line_overlap"] <= 0.05
    # forced prototype lines / numeric rows alone never fail an implementation
    table_a = "const unsigned short t[8] = {\n" + "".join("    0x%04X, 0x%04X, 0x%04X, 0x%04X,\n" % (i, i + 1, i + 2, i + 3) for i in range(0, 32, 4)) + "};\n"
    assert reimpl_c.line_overlap(table_a + "int f(int a)\n{\n return a;\n}\n", table_a + "int f(int a)\n{\n return a + 1;\n}\n", ignore={"int f(int a)"}) == 0.0
    tiny = "int f(int a)\n{\n    return a + 1;\n}\n"
    assert reimpl_c.token_overlap(tiny, tiny)["reliable"] is False
    assert reimpl_c.copy_gate("/* Licensed under the GNU General Public License */\nint f(void){return 0;}\n", ORIGINAL)["passed"] is False


def test_numeric_tables_are_facts_for_both_overlap_measures():
    """AC: BSA-AC-638. A CRC lookup table is mathematics, not expression: a generated table identical to the original's does not raise the token overlap (tables are
    cut out of the token stream) nor the line overlap (numeric rows are dropped) - 2 of 2 measures."""
    rows = "".join("    " + ", ".join("0x%04X" % (i * 8 + k) for k in range(8)) + ",\n" for i in range(32))
    a = "const unsigned short tab[256] = {\n" + rows + "};\nunsigned short f(unsigned short c, const unsigned char *p, unsigned n) {\n  while (n--) c = (unsigned short)((c >> 8) ^ tab[(c ^ *p++) & 0xFF]);\n  return c;\n}\n"
    b = a.replace("(c >> 8) ^ tab[(c ^ *p++) & 0xFF]", "tab[(c ^ *p++) & 0xFF] ^ (c >> 8)")
    assert reimpl_c.line_overlap(a, b, ignore=set()) < 0.5
    assert reimpl_c.body_tokens(a).count("{TABLE}") == 0 and "{TABLE}" not in reimpl_c.body_tokens(a)          # bodies only: the table sits outside every body
    assert reimpl_c._strip_tables(cparse.tokenize(a)[0]).__len__() < len(cparse.tokenize(a)[0]) / 2


# ============================================================================================ compile + oracle
@needs_cc
def test_independent_implementation_passes_every_gate_and_the_differential_oracle(tmp_path):
    """AC: BSA-AC-639. The full lane on real gcc: copy gate passes, the code compiles warning-free, nm proves the 4 functions + the data table are exported, the
    upstream test main runs against the NEW module, and the generated differential driver compares the ORIGINAL (built here, symbols renamed) with the new
    code on 4 compared items (3 functions + the table; the struct-pointer function is reported as skipped) / >= 100 sampled cases with 0 mismatches -> verdict ok."""
    root = _project(tmp_path)
    r, events, out = _run(root, tmp_path, Fake(GOOD))
    assert r["verdict"] == "ok" and r["language"] == "c" and r["generated_by"] == "llm" and r["attempts"] == 1
    assert r["copy_gate"]["passed"] and r["compile"]["ok"] and r["compile"]["warnings"] == 0
    assert r["export"]["ok"] and r["export"]["missing"] == [] and r["export"]["wanted"] == 5
    d = r["oracle"]["differential"]
    assert d["ran"] and d["ok"] and d["functions"] == 4 and d["total_cases"] >= 100 and d["mismatches"] == 0
    assert [s["function"] for s in d["skipped"]] == ["my_cfg_width"] and "pointer to mylib_cfg" in d["skipped"][0]["why"]     # a struct pointer is not comparable by the driver
    assert r["oracle"]["original_build"]["ok"] and r["oracle"]["adopted"]["ran"] == 1 and r["oracle"]["adopted"]["ok"]
    assert events[:3] == ["interface_ready", "spec_ready", "diagram_ready"] and events[-1] == "adopted_tests_passed"
    assert os.path.exists(os.path.join(out, "mycrc.c")) and os.path.exists(os.path.join(out, "mycrc_cr.h"))


@needs_cc
def test_a_wrong_polynomial_is_caught_and_the_observed_facts_ride_back_to_the_generator(tmp_path):
    """AC: BSA-AC-639. Attempt 1 uses polynomial 0x31 instead of 0x07: the oracle finds mismatches (naming call, original value and new value), the lane regenerates
    ONCE with those observed facts in the prompt and the second attempt passes - the retry prompt carries `MISMATCH my_crc8(` (3 of 3)."""
    root = _project(tmp_path)
    client = Fake(BAD_POLY, GOOD)
    r, events, _ = _run(root, tmp_path, client)
    assert r["verdict"] == "ok" and r["attempts"] == 2 and "regenerating" in events
    assert len(client.systems) == 2 and "MISMATCH" not in client.systems[0] and "my_crc8(" in client.systems[1] and "orig=" in client.systems[1]
    assert "reference" in client.systems[1]
    bad_only, _, _ = _run(root, tmp_path, Fake(BAD_POLY), attempts=1)
    assert bad_only["verdict"] == "compatibility_failed" and bad_only["oracle"]["differential"]["mismatches"] > 0
    assert any("my_crc8" in e for e in bad_only["oracle"]["differential"]["examples"])


@needs_cc
def test_published_data_tables_are_compared_byte_for_byte(tmp_path):
    """AC: BSA-AC-639. A lookup table the API exports is part of the contract: one wrong byte in `my_tbl` is a behavioural difference (the function results are
    all identical), reported as `MISMATCH my_tbl: the published data differs` -> compatibility_failed (1 of 1)."""
    root = _project(tmp_path)
    r, _, _ = _run(root, tmp_path, Fake(BAD_TABLE), attempts=1)
    d = r["oracle"]["differential"]
    assert r["verdict"] == "compatibility_failed" and d["mismatches"] == 1
    assert d["examples"] == ["MISMATCH my_tbl: the published data differs from the reference"]


@needs_cc
def test_scaffold_without_a_model_compiles_but_is_honestly_not_compatible(tmp_path):
    """AC: BSA-AC-639. No LLM client: the deterministic scaffold compiles and exports the API (contract tests pass) but the oracle exposes it - a large share of sampled
    cases differ and the verdict is compatibility_failed, never ok."""
    root = _project(tmp_path)
    r, _, _ = _run(root, tmp_path, None)
    assert r["generated_by"] == "scaffold" and r["compile"]["ok"] and r["export"]["ok"]
    assert r["verdict"] == "compatibility_failed" and r["oracle"]["differential"]["mismatches"] > 100


def test_renamed_copy_is_rejected_before_any_compilation(tmp_path):
    """AC: BSA-AC-639. The gate runs first: a renamed copy of the original is rejected with the measured overlap and no compiler/oracle stage runs (events end at copy_gate_failed)."""
    root = _project(tmp_path)
    renamed = ORIGINAL
    for a, b in (("step", "advance"), ("crc", "acc"), ("digits", "alphabet"), ("buf", "data")):
        renamed = renamed.replace(a, b)
    r, events, _ = _run(root, tmp_path, Fake(renamed))
    assert r["verdict"] == "rejected" and "token overlap" in r["reason"] and events[-1] == "copy_gate_failed" and "tests_running" not in events


@needs_cc
def test_without_a_buildable_original_the_verdict_is_contract_only_never_ok(tmp_path):
    """AC: BSA-AC-639. The original needs a configuration header that does not exist and a macro-sized array that cannot be repaired: the original cannot be built,
    so there is NO differential oracle; the generated code still compiles and exports its API, and the verdict is `contract_only` with the reason - never `ok`."""
    unbuildable = ORIGINAL.replace("#include <mylib/crc.h>", '#include <mylib/crc.h>\n#include "board_config.h"\nstatic char scratch[BOARD_BUF_SIZE];')
    root = _project(tmp_path, {"src/mycrc.c": unbuildable, "tests/test_mycrc.c": "int main(void){return 0;}\n"}, "nobuild")
    os.remove(os.path.join(root, "tests", "test_mycrc.c"))                                                 # and no upstream test either
    r, _, _ = _run(root, tmp_path, Fake(GOOD))
    assert r["verdict"] == "contract_only" and r["compile"]["ok"] and r["export"]["ok"]
    assert r["oracle"]["original_build"]["ok"] is False and r["oracle"]["differential"]["ran"] is False
    assert "behaviour is NOT verified" in r["reason"]


def test_missing_toolchain_is_reported_not_faked(tmp_path):
    """AC: BSA-AC-639. No compiler: verdict toolchain_missing with the install hint; the generated source and header are still delivered as artefacts, nothing is claimed verified."""
    root = _project(tmp_path)
    out = str(tmp_path / "o_tc")
    r = reimpl_c.run(root, "src/mycrc.c", out, client=Fake(GOOD), toolchain_override={"cc": None, "cxx": None, "nm": None})
    assert r["verdict"] == "toolchain_missing" and "install gcc/clang" in r["reason"] and os.path.exists(os.path.join(out, "mycrc.c"))


@needs_cc
def test_publish_copies_only_a_fully_passing_lane_and_never_overwrites_the_source(tmp_path):
    """AC: BSA-AC-639. publish_dest receives the .c, the rendered header and the contract test only when the verdict is ok; the analysed tree is never the target
    without allow_inplace (2 of 2)."""
    root = _project(tmp_path)
    dest = str(tmp_path / "published")
    r, events, _ = _run(root, tmp_path, Fake(GOOD), publish_dest=dest)
    assert r["verdict"] == "ok" and sorted(os.listdir(dest)) == ["mycrc.c", "mycrc_cr.h", "test_mycrc.c"] and events[-1] == "published"
    r2, _, _ = _run(root, tmp_path, Fake(GOOD), publish_dest=root)
    assert r2["verdict"] == "publish_refused"


# ============================================================================================ building the original on a foreign host
def test_repair_rules_tell_typedefs_from_marker_words_and_feature_macros(tmp_path):
    """AC: BSA-AC-640. The error-driven repair of a kernel-style original: an unknown name in a `typedef` line becomes an integer typedef, `u16` its kernel meaning, a
    marker word in front of a declaration (`__rcode static ...`) an empty macro, `#if CONFIG_IS_ENABLED(X)` a function-like macro returning 0 (4 of 4 rules)."""
    f = tmp_path / "k.h"
    f.write_text("typedef __kernel_dev_t dev_t;\n__rcode static int g(void);\nu16 h(void);\n#if CONFIG_IS_ENABLED(FOO)\n#endif\n", encoding="utf-8")
    p = str(f).replace("\\", "/")
    err = ("%s:1:9: error: unknown type name '__kernel_dev_t'\n%s:3:1: error: unknown type name 'u16'\n%s:2:8: error: expected ';' before 'static'\n"
           "%s:4:5: error: missing binary operator before token '('\n" % (p, p, p, p))
    pre: Dict[str, Any] = {"typedefs": {}, "empty": set(), "fnmacros": set()}
    assert reimpl_c._repair_prelude(err, pre)
    assert pre["typedefs"]["__kernel_dev_t"] == "unsigned long" and pre["typedefs"]["u16"] == "uint16_t"
    assert "__rcode" in pre["empty"] and "CONFIG_IS_ENABLED" in pre["fnmacros"]
    text = reimpl_c._prelude_text(pre)
    assert "#define __rcode" in text and "#define CONFIG_IS_ENABLED(...) 0" in text and "#define BITS_PER_LONG" in text


def test_a_conflicting_project_header_is_stubbed_under_its_most_specific_include_spelling(tmp_path):
    """AC: BSA-AC-640. A project header that re-typedefs a HOST type (linux/types.h: size_t) is replaced by an empty stub at `linux/types.h`, not `include/linux/types.h`
    (the include directory that makes the spelling shortest wins) - 2 of 2 spellings."""
    root = str(tmp_path / "p")
    p = os.path.join(root, "include", "linux", "types.h")
    assert reimpl_c._spelling_under(p, [root, os.path.join(root, "include")]) == "linux/types.h"
    assert reimpl_c._spelling_under(os.path.join(root, "src", "a.h"), [root, os.path.join(root, "include")]) == "src/a.h"


@needs_cc
def test_a_freestanding_original_with_its_own_libc_headers_is_built_standalone(tmp_path):
    """AC: BSA-AC-640. An original whose project ships kernel-style headers that shadow libc (string.h, linux/types.h typedef'ing size_t) and an unknown marker word before a
    declaration is built standalone: project dirs go after the system headers, the conflicting header is stubbed, the marker repaired - the differential then runs and passes."""
    files = {
        "include/linux/types.h": "typedef unsigned long __kernel_size_t;\ntypedef __kernel_size_t size_t;\ntypedef unsigned short u16;\n",
        "include/string.h": "#include <linux/types.h>\nvoid *memcpy(void *d, const void *s, size_t n);\n",
        "include/lib/sum.h": "#include <linux/types.h>\nu16 sum16(u16 init, const unsigned char *p, size_t n);\n",
        "src/sum.c": "#include <lib/sum.h>\n__rcode static unsigned short add1(unsigned short a, unsigned char b) { return (unsigned short)(a + b); }\n"
                     "u16 sum16(u16 init, const unsigned char *p, size_t n)\n{\n    u16 s = init;\n    while (n--)\n        s = add1(s, *p++);\n    return s;\n}\n",
    }
    root = _project(tmp_path, files, "freestanding")
    for rel in ("include/mylib/crc.h", "src/mycrc.c", "tests/test_mycrc.c"):
        os.remove(os.path.join(root, rel))
    good = ('#include "sum_cr.h"\nu16 sum16(u16 init, const unsigned char *p, size_t n)\n{\n    unsigned int acc = init;\n    for (size_t i = 0; i < n; i++)\n        acc = (acc + p[i]) & 0xFFFFu;\n'
            '    return (u16)acc;\n}\n')
    r, _, _ = _run(root, tmp_path, Fake(good), component="src/sum.c")
    assert r["verdict"] == "ok", r.get("reason")
    ob = r["oracle"]["original_build"]
    assert ob["ok"] and r["oracle"]["differential"]["functions"] == 1 and r["oracle"]["differential"]["mismatches"] == 0


# ============================================================================================ real GPL code (u-boot)
@pytest.mark.skipif(not (TC["cc"] and os.path.isfile(UBOOT + "/lib/crc8.c")), reason="needs a C compiler and the u-boot checkout")
def test_real_u_boot_crc8_is_reimplemented_and_verified_against_the_real_original(tmp_path):
    """AC: BSA-AC-640. REAL GPL-2.0+ code (u-boot lib/crc8.c, kernel-style headers, `__rcode` marker, asm/ headers that do not exist here): the interface is read from
    include/u-boot/crc.h, an independent CRC-8 is generated, and the ORIGINAL u-boot file is built standalone on this host (header shadowing + repairs) so the
    differential oracle compares 2 functions on >= 100 cases with 0 mismatches against the real implementation -> verdict ok, not contract_only."""
    good = _d('''
        #include "crc8_cr.h"
        unsigned int crc8(unsigned int crc, const unsigned char *vptr, int len)
        {
            unsigned int c = crc & 0xFFu;
            for (int i = 0; i < len; i++) {
                c ^= vptr[i];
                for (int b = 0; b < 8; b++)
                    c = (c & 0x80u) ? (((c << 1) ^ 0x07u) & 0xFFu) : ((c << 1) & 0xFFu);
            }
            return c;
        }
        void crc8_wd_buf(const unsigned char *input, unsigned int len, unsigned char output[1], unsigned int chunk_sz)
        {
            (void)chunk_sz;
            output[0] = (unsigned char)crc8(0, input, (int)len);
        }
    ''')
    r, _, _ = _run(UBOOT, tmp_path, Fake(good), component="lib/crc8.c")
    assert r["verdict"] == "ok", (r.get("reason"), (r.get("oracle") or {}).get("original_build"))
    assert r["interface"]["functions"] == ["crc8", "crc8_wd_buf"] and r["interface"]["paired_headers"] == ["include/u-boot/crc.h"]
    d = r["oracle"]["differential"]
    assert r["oracle"]["original_build"]["ok"] and d["ran"] and d["ok"] and d["functions"] == 2 and d["total_cases"] >= 100 and d["mismatches"] == 0
    assert r["copy_gate"]["passed"] and r["copy_gate"]["token_overlap"] < 0.30


@pytest.mark.skipif(not (TC["cc"] and os.path.isfile(UBOOT + "/lib/crc16.c")), reason="needs a C compiler and the u-boot checkout")
def test_real_u_boot_crc16_table_and_function_are_verified_and_a_wrong_table_entry_is_caught(tmp_path):
    """AC: BSA-AC-640. u-boot lib/crc16.c exports a 256-entry data table next to the function: the generated table (a computed fact, so the copy gate must not call it
    copying) is compared byte for byte with the real one; a single wrong entry is caught by the oracle and fixed on the retry (2 of 2 runs)."""
    def table() -> str:
        rows = []
        for k in range(0, 256, 8):
            vals = []
            for i in range(k, k + 8):
                c = i
                for _ in range(8):
                    c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
                vals.append("0x%04X" % c)
            rows.append("    " + ", ".join(vals) + ",")
        return "\n".join(rows)
    good = ('#include "crc16_cr.h"\n\nu16 const crc16_table[256] = {\n%s\n};\n\nu16 crc16(u16 crc, const u8 *buffer, size_t len)\n{\n    while (len--)\n'
            '        crc = (u16)((crc >> 8) ^ crc16_table[(crc ^ *buffer++) & 0xFF]);\n    return crc;\n}\n' % table())
    r, _, _ = _run(UBOOT, tmp_path, Fake(good), component="lib/crc16.c")
    assert r["verdict"] == "ok" and r["copy_gate"]["passed"] and r["oracle"]["differential"]["functions"] == 2
    r2, _, _ = _run(UBOOT, tmp_path, Fake(good.replace("0xC0C1", "0xC0C0", 1), good), component="lib/crc16.c")
    assert r2["verdict"] == "ok" and r2["attempts"] == 2
