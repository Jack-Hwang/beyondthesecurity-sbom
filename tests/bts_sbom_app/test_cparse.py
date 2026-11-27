"""C / C++ declaration reader (cparse.py): the facts both the compatibility gate and the clean-room lane stand on.

Synthetic headers pin every construct; one cross-check runs the reader against Universal Ctags on a real code base (skipped when
ctags or the u-boot checkout used for the measurement is absent).
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess

import pytest

from bts_sbom_app import cparse

UBOOT = os.environ.get("BTS_SBOM_UBOOT", "C:/firebaseprojects/usertest/u-boot")

HEADER = r'''
#ifndef FOO_H
#define FOO_H
#include <stdint.h>
#include "local.h"
#define FOO_VERSION 0x0102
#define FOO_MAX (FOO_VERSION << 2)
#define FOO_MIN(a,b) ((a)<(b)?(a):(b))
#ifdef __cplusplus
extern "C" {
#endif
#if 0
int dead_function(int x);
#endif
/**
 * foo_add() - add two numbers
 * @a: first
 * Return: the sum
 */
int foo_add(int a, int b);
static inline unsigned int foo_hash(const unsigned char *buf, size_t len) { return len * 31337u; }
FOO_API void foo_free(struct foo *f, ...);
typedef struct foo { int x; unsigned char name[16]; struct { int a; int b; } inner; void (*cb)(int, void *); unsigned flag : 3; } foo_t, *foo_p;
typedef enum { FOO_A, FOO_B = 5, FOO_C, FOO_D = FOO_B << 1 } foo_kind;
typedef unsigned int uint;
typedef int (*foo_cb)(int, char *);
extern const char *foo_names[];
int foo_counter;
EXPORT_SYMBOL(foo_add);
__attribute__((deprecated)) int foo_old(void);
int foo_reg(int (*fn)(int), void *ctx);
ZEXTERN int ZEXPORT deflate OF((z_streamp strm, int flush));
#ifdef __cplusplus
}
#endif
#endif
'''


def test_c_header_functions_types_macros_enums_and_docs_are_read():
    """AC: BSA-AC-637. A realistic C header: 8 constructs - prototypes (+ variadic, static inline, export macro, deprecated attribute, function-pointer
    parameter, the zlib OF() wrapper), struct with nested/anonymous members and bit-fields, typedefs (struct, enum, funcptr), evaluated enum values,
    object/function-like macros, globals - all read; #if 0 code and non-declarations are not API."""
    m = cparse.parse(HEADER, "foo.h")
    fn = {f["name"]: f for f in m["functions"]}
    assert set(fn) == {"foo_add", "foo_hash", "foo_free", "foo_old", "foo_reg", "deflate"}          # dead_function (#if 0) and EXPORT_SYMBOL(...) are not API
    assert fn["foo_add"]["proto"] == "int foo_add(int a, int b)" and fn["foo_add"]["doc"].startswith("foo_add() - add two numbers")
    assert "Return: the sum" in fn["foo_add"]["doc"]
    assert fn["foo_hash"]["static"] and fn["foo_hash"]["defined"] and fn["foo_hash"]["ret"] == "unsigned int"
    assert fn["foo_free"]["variadic"] and fn["foo_free"]["ret"] == "void" and fn["foo_free"]["params"][0]["type"].startswith("struct foo")
    assert fn["foo_old"]["deprecated"] is True and fn["foo_add"]["deprecated"] is False
    assert fn["foo_reg"]["params"][0]["funcptr"] is True and fn["foo_reg"]["params"][1]["name"] == "ctx"
    assert fn["deflate"]["ret"] == "int" and [p["name"] for p in fn["deflate"]["params"]] == ["strm", "flush"]
    types = {t["name"]: t for t in m["types"]}
    st = types["foo"]
    assert [(f["name"], f.get("bits"), f.get("array")) for f in st["fields"]] == [("x", None, None), ("name", None, "[16]"), ("inner", None, None), ("cb", None, None), ("flag", 3, None)]
    assert {t["name"] for t in m["types"] if t["kind"] == "typedef"} >= {"foo_t", "foo_p", "uint", "foo_cb"}
    assert types["foo_kind"]["kind"] == "enum" and [(e["name"], e["value"]) for e in types["foo_kind"]["enumerators"]] == [("FOO_A", 0), ("FOO_B", 5), ("FOO_C", 6), ("FOO_D", 10)]
    mac = {x["name"]: x for x in m["macros"]}
    assert mac["FOO_H"]["guard"] and mac["FOO_VERSION"]["value"] == 258 and mac["FOO_MAX"]["value"] == 1032
    assert mac["FOO_MIN"]["params"] == ["a", "b"] and mac["FOO_MIN"]["value"] is None
    assert {v["name"] for v in m["variables"]} == {"foo_names", "foo_counter"}
    assert [i["path"] for i in m["includes"]] == ["stdint.h", "local.h"] and m["skipped"] >= 1


def test_function_bodies_never_enter_the_model():
    """AC: BSA-AC-637. Clean-room wall 1 at the parser: a distinctive body string appears nowhere in the JSON of the model (functions record only
    `defined: True`); macro bodies are the only text kept and are bounded."""
    src = "int secret_algo(int a)\n{\n    return a * 0x5EC12E7 + 'S3CR3T_BODY_MARKER';\n}\nstatic int helper(void) { return 0xBADC0DE; }\n"
    m = cparse.parse(src, "x.c")
    blob = json.dumps(m)
    assert "S3CR3T_BODY_MARKER" not in blob and "5EC12E7" not in blob and "BADC0DE" not in blob
    assert [(f["name"], f["defined"], f["static"]) for f in m["functions"]] == [("secret_algo", True, False), ("helper", True, True)]


def test_cplusplus_classes_namespaces_templates_operators_and_default_arguments():
    """AC: BSA-AC-637. C++: namespace/class scopes, constructors/destructors, virtual and pure methods, const methods, default arguments (not mistaken for an
    initializer), operator=/operator()/conversion operators, template flags, access sections - 11 of 11 declarations."""
    src = r'''
    template <class T> struct Ptr { T* p; bool operator()(const T& a) const; Ptr& operator=(const Ptr&); explicit operator bool() const noexcept; ~Ptr(); Ptr(int x = 0); int count = 3; };
    namespace ns { class Foo : public Bar { public: Foo(); virtual int run(int a, double b = 1.0) const = 0; static void make(); private: int hidden; }; int helper(int x); }
    '''
    m = cparse.parse(src, "x.hpp")
    assert m["language"] == "c++"
    fn = {f["qualified"]: f for f in m["functions"]}
    assert set(fn) == {"Ptr::operator()", "Ptr::operator=", "Ptr::operator bool", "Ptr::~Ptr", "Ptr::Ptr", "ns::Foo::Foo", "ns::Foo::run", "ns::Foo::make", "ns::helper"}
    assert fn["Ptr::operator="]["ret_norm"] == "Ptr&" and fn["Ptr::operator()"]["const"] and fn["Ptr::~Ptr"]["kind"] == "dtor" and fn["ns::Foo::Foo"]["kind"] == "ctor"
    run = fn["ns::Foo::run"]
    assert run["virtual"] and run["pure"] and run["const"] and [(p["name"], p["default"]) for p in run["params"]] == [("a", False), ("b", True)]
    types = {t["qualified"]: t for t in m["types"]}
    assert types["Ptr"]["template"] and [f["name"] for f in types["Ptr"]["fields"]] == ["p", "count"]
    assert types["ns::Foo"]["bases"] == ["Bar"] and types["ns::Foo"]["fields"][0]["access"] == "private"


def test_export_macros_attribute_prefixes_and_kernel_marker_words_do_not_pollute_types():
    """AC: BSA-AC-637. ALL-CAPS export/linkage macros (ZEXTERN, EFIAPI), leading attribute macros with arguments, and kernel marker words (__rcode, __init)
    are not part of the return type; a real ALL-CAPS type (FILE, DWORD) is kept (5 of 5)."""
    src = ("ZEXTERN uLong ZEXPORT adler32 OF((uLong adler, const Bytef *buf, uInt len));\n"
           "EFIAPI efi_status_t efi_run(void *h);\n"
           "__rcode static unsigned char crc_step(unsigned short d);\n"
           "FILE *open_it(const char *p);\n"
           "DWORD get_flags(void);\n")
    fn = {f["name"]: f for f in cparse.parse(src, "x.h")["functions"]}
    assert fn["adler32"]["ret"] == "uLong" and fn["efi_run"]["ret"] == "efi_status_t" and fn["crc_step"]["ret"] == "unsigned char" and fn["crc_step"]["static"]
    assert fn["open_it"]["ret_norm"] == "FILE*" and fn["get_flags"]["ret"] == "DWORD"


def test_constant_folding_of_macros_and_enumerators():
    """AC: BSA-AC-637. Integer constants fold (shifts, suffixes, hex, references to earlier names, casts); anything else stays unevaluated (None) instead of guessed."""
    f = cparse._eval_int
    assert f("1UL << 4") == 16 and f("0x10U | 0x01") == 17 and f("(unsigned)3 + 4") == 7 and f("A + 2", {"A": 5}) == 7
    assert f("sizeof(int)") is None and f("foo(1)") is None and f("1 / 0") is None


def test_usage_scan_counts_call_arguments_shadows_local_definitions_and_matches_fields():
    """AC: BSA-AC-637. What a project uses of a library: call sites with their argument count (nested commas/calls/casts counted right), macro and
    enumerator references, struct-field accesses by name; a function the project DEFINES itself shadows the library name and a re-declaration is not a call."""
    api = cparse.parse("int lib_read(void *c, char *b, int n);\nint lib_old(int x);\n#define LIB_MAX 7\nenum m { LIB_A, LIB_B };\n"
                       "typedef struct lib_ctx { int refs; int legacy; } lib_ctx;\n", "lib.h")
    interest = cparse.interest_set(api)
    src = ('#include <lib.h>\nint lib_old(int x);\nstatic int lib_read2(void);\n'
           'int f(lib_ctx *c) {\n  char b[8];\n  lib_read(c, b, g(1, 2));\n  lib_read(c, (char *)b, sizeof(b));\n  x = lib_old(3, 4);\n'
           '  if (c->legacy && LIB_B == LIB_MAX) return c->refs;\n  return lib_read();\n}\n')
    u = cparse.scan_usage(src, "a.c", interest)
    calls = {k: [c["npos"] for c in v["calls"]] for k, v in u["symbols"].items() if v["calls"]}
    assert calls["lib_read"] == [3, 3, 0] and calls["lib_old"] == [2]                       # the prototype `int lib_old(int x);` is not a call
    assert u["symbols"]["LIB_B"]["refs"] == 1 and u["symbols"]["LIB_MAX"]["refs"] == 1
    assert set(u["fields"]) == {"legacy", "refs"} and [i["path"] for i in u["includes"]] == ["lib.h"]
    shadow = cparse.local_definitions("int lib_old(int x) { return x; }\n", "mine.c")
    u2 = cparse.scan_usage("int g(void) { return lib_old(1); }\n", "b.c", interest, shadow=shadow)
    assert "lib_old" not in u2["symbols"]


def test_dead_blocks_are_removed_but_line_numbers_are_kept():
    """AC: BSA-AC-637. `#if 0` regions (nested, with #else) are comments in disguise: not API; a later declaration keeps its true line number."""
    src = "#if 0\nint dead(void);\n#if X\nint dead2(void);\n#endif\n#else\nint live(void);\n#endif\nint after(void);\n"
    m = cparse.parse(src, "d.h")
    assert {f["name"]: f["line"] for f in m["functions"]} == {"live": 7, "after": 9}


@pytest.mark.skipif(not shutil.which("ctags") or not os.path.isdir(UBOOT), reason="needs Universal Ctags and a u-boot checkout")
def test_reader_agrees_with_universal_ctags_on_real_u_boot_code():
    """AC: BSA-AC-637. Independent cross-check on REAL C: 60 u-boot headers + 40 lib sources, function names compared with Universal Ctags. Measured on the full
    625 headers: recall 0.997 / precision 0.998 with 0 crashes; here the sample must stay >= 0.97 / 0.97 with 0 crashes."""
    files = sorted(glob.glob(UBOOT + "/include/u-boot/*.h"))[:20] + sorted(glob.glob(UBOOT + "/include/*.h"))[:40] + sorted(glob.glob(UBOOT + "/lib/*.c"))[:40]
    assert len(files) >= 60
    tot_ct = tot_me = both = 0
    for f in files:
        m = cparse.parse_file(f, "c")                                                          # a crash would raise here
        mine = {x["name"] for x in m["functions"]}
        p = subprocess.run(["ctags", "-x", "--language-force=C", "--c-kinds=fp", "-f", "-", f], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        ct = {ln.split()[0] for ln in p.stdout.splitlines() if len(ln.split()) > 1 and ln.split()[1] in ("function", "prototype")}
        tot_ct += len(ct)
        tot_me += len(mine)
        both += len(ct & mine)
    assert tot_ct > 200 and both / tot_ct >= 0.97 and both / tot_me >= 0.97
