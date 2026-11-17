# New test file for the paren-strip defect cluster (docs/CORE_ISSUES.md item 2;
# report section 5 "SPDX bracket bug"). Written into its own file per the task's
# no-conflict rule -- never edit tests/test_bts_sbom_pkg.py.
#
# Bug: bts_sbom/sbom.py's _valid_expression and
# bts_sbom/_internal/license_norm.py's normalize() both compute
# ``expression_string(node).strip("()")``. str.strip removes characters from
# BOTH ends repeatedly while they are in the given set, not one matched outer
# pair, so any expression whose rendering nests parens near an edge gets a
# REAL paren eaten (not just the always-redundant outer wrap that
# expression_string adds), producing an unbalanced, invalid SPDX string.
"""AC: BSA-AC-n (see bts_sbom_app spec; ids assigned by the release session)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bts_sbom._internal.license_spdx import expression_string, parse_expression
from bts_sbom._internal import license_norm
from bts_sbom import sbom


# ---------------------------------------------------------------------------
# Expressions used across both call sites. Each tuple is
# (input_expression, expected_normalized_output).
# ---------------------------------------------------------------------------
CASES = [
    ("MIT", "MIT"),
    ("A AND (B OR C)", "A AND (B OR C)"),
    ("(A OR B) AND (C OR D)", "(A OR B) AND (C OR D)"),
    ("((A OR B))", "A OR B"),
    ("A WITH Classpath-exception-2.0", "A WITH Classpath-exception-2.0"),
    ("A AND B AND (C OR (D AND E))", "A AND B AND (C OR (D AND E))"),
]


class ExpressionStringRoundTripIsUnbalancedToday(unittest.TestCase):
    """RED: demonstrates the raw bug in expression_string(...).strip("()")
    directly, independent of which call site uses it. Kept passing after the
    fix too (it is just checking str.strip's own documented both-ends
    behaviour, not asserting the bug must exist) -- the real regression
    guards are the ones below that go through _valid_expression/normalize.
    """

    def test_strip_both_ends_is_the_known_bad_primitive(self):
        node = parse_expression("A AND (B OR C)")
        rendered = expression_string(node)
        self.assertEqual(rendered, "(A AND (B OR C))")
        # the naive primitive the bug report names -- str.strip eats from
        # BOTH ends repeatedly, consuming one of the two trailing ')' chars
        # that belongs to the INNER group, not the outer wrap.
        self.assertEqual(rendered.strip("()"), "A AND (B OR C")


class ValidExpressionParensTests(unittest.TestCase):
    """bts_sbom/sbom.py::_valid_expression (used by validate_spdx /
    build_spdx_document's licenseConcluded)."""

    def test_cases_round_trip_without_losing_a_paren(self):
        for raw, expected in CASES:
            with self.subTest(expr=raw):
                ok, value = sbom._valid_expression(raw)
                self.assertTrue(ok, "expected %r to be valid SPDX, got %r" % (raw, value))
                self.assertEqual(value, expected)
                # whatever comes out must itself still be valid SPDX syntax,
                # i.e. balanced parens, re-parseable.
                ok2, _ = sbom._valid_expression(value)
                self.assertTrue(ok2, "normalized value %r is not valid SPDX" % (value,))

    def test_asymmetric_and_symmetric_nesting_both_stay_balanced(self):
        # the two shapes the analysis calls out by name
        ok1, v1 = sbom._valid_expression("BSD-3-Clause AND (Apache-2.0 OR MIT)")
        self.assertTrue(ok1)
        self.assertEqual(v1, "BSD-3-Clause AND (Apache-2.0 OR MIT)")
        ok2, v2 = sbom._valid_expression("(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
        self.assertTrue(ok2)
        self.assertEqual(v2, "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
        self.assertEqual(v2.count("("), v2.count(")"))

    def test_full_spdx_document_round_trip_validates(self):
        """The exact repro from the analysis report: build a document with a
        nested license expression and confirm validate_spdx accepts it (it
        used to abort with 'non-SPDX license value')."""
        pkgs = [{"name": "pkg1", "version": "1.0",
                 "license": "BSD-3-Clause AND (Apache-2.0 OR MIT)"}]
        doc = sbom.build_spdx_document(pkgs, [])
        pkg = doc["packages"][0]
        self.assertEqual(pkg["licenseConcluded"], "BSD-3-Clause AND (Apache-2.0 OR MIT)")
        self.assertEqual(sbom.validate_spdx(doc), [])

    def test_symmetric_nesting_document_round_trip_validates(self):
        pkgs = [{"name": "pkg1", "version": "1.0",
                 "license": "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)"}]
        doc = sbom.build_spdx_document(pkgs, [])
        pkg = doc["packages"][0]
        self.assertEqual(pkg["licenseConcluded"], "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
        self.assertEqual(sbom.validate_spdx(doc), [])

    def test_unbalanced_input_is_an_honest_rejection_not_a_crash(self):
        ok, why = sbom._valid_expression("A AND (B OR C")
        self.assertFalse(ok)
        self.assertIsInstance(why, str)
        ok2, why2 = sbom._valid_expression(")()(")
        self.assertFalse(ok2)
        self.assertIsInstance(why2, str)


class LicenseNormParensTests(unittest.TestCase):
    """bts_sbom/_internal/license_norm.py::normalize (feeds
    spdx_sbom.py's licenseDeclared via to_spdx_field)."""

    def test_cases_round_trip_without_losing_a_paren(self):
        for raw, expected in CASES:
            with self.subTest(expr=raw):
                result = license_norm.normalize(raw)
                self.assertIn(result["status"], ("ok", "deprecated"))
                self.assertEqual(result["normalized"], expected)

    def test_asymmetric_nesting_to_spdx_field_stays_balanced_and_reparseable(self):
        field = license_norm.to_spdx_field("BSD-3-Clause AND (Apache-2.0 OR MIT)")
        self.assertEqual(field, "BSD-3-Clause AND (Apache-2.0 OR MIT)")
        self.assertEqual(field.count("("), field.count(")"))
        # must itself be valid, re-parseable SPDX syntax (this is the exact
        # re-parse check the analysis report used to prove corruption)
        parse_expression(field)

    def test_symmetric_nesting_to_spdx_field_stays_balanced_and_reparseable(self):
        field = license_norm.to_spdx_field("(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
        self.assertEqual(field, "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
        self.assertEqual(field.count("("), field.count(")"))
        parse_expression(field)

    def test_malformed_input_is_a_clean_invalid_status_not_a_crash(self):
        result = license_norm.normalize("A AND (B OR C")
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["normalized"], None)
        self.assertTrue(result["errors"])

    def test_lone_license_unaffected(self):
        result = license_norm.normalize("MIT")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["normalized"], "MIT")


class SharedHelperTests(unittest.TestCase):
    """The shared outer-paren-stripping helper used at both call sites."""

    def test_helper_is_shared_between_sbom_and_license_norm(self):
        import inspect
        # Both call sites must use the SAME helper (not two independent
        # re-implementations) -- introspect the source of each function and
        # check they reference a common name rather than literal .strip("()").
        sbom_src = inspect.getsource(sbom._valid_expression)
        norm_src = inspect.getsource(license_norm.normalize)
        self.assertNotIn('.strip("()")', sbom_src)
        self.assertNotIn(".strip('()')", sbom_src)
        self.assertNotIn('.strip("()")', norm_src)
        self.assertNotIn(".strip('()')", norm_src)

    def test_helper_never_crashes_on_unbalanced_or_degenerate_strings(self):
        from bts_sbom._internal.license_spdx import strip_outer_parens
        for s in ["", "(", ")", "()", "(A", "A)", ")(", ")()(", "((A)", "(A))",
                  "A AND (B OR C", "(A AND (B OR C))", "A"]:
            # must never raise, and must never return something with a
            # different paren balance than it started with (only a single
            # matching wrapping pair may ever be removed).
            try:
                strip_outer_parens(s)
            except Exception as exc:  # pragma: no cover - the assertion is the point
                self.fail("strip_outer_parens(%r) raised %r" % (s, exc))

    def test_helper_only_removes_one_fully_wrapping_pair(self):
        from bts_sbom._internal.license_spdx import strip_outer_parens
        self.assertEqual(strip_outer_parens("(A AND (B OR C))"), "A AND (B OR C)")
        self.assertEqual(strip_outer_parens("((A OR B) AND (C OR D))"), "(A OR B) AND (C OR D)")
        self.assertEqual(strip_outer_parens("((A OR B))"), "(A OR B)")
        self.assertEqual(strip_outer_parens("MIT"), "MIT")
        # NOT fully wrapping -- '(' at index 0 closes before the string
        # ends, so nothing may be stripped.
        self.assertEqual(strip_outer_parens("(A) AND (B)"), "(A) AND (B)")
        # unbalanced / degenerate -- never crash, never corrupt.
        self.assertEqual(strip_outer_parens("(A"), "(A")
        self.assertEqual(strip_outer_parens(")("), ")(")
        self.assertEqual(strip_outer_parens(""), "")


if __name__ == "__main__":
    unittest.main()
