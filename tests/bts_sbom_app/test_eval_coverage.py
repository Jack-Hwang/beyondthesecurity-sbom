"""The eval-set composition table (전형/경계/적대) - course week 5 lesson 2: only-typical eval sets miss the failures
that matter, so every declared corpus reports how many typical / boundary / adversarial items it holds, WHICH RULE
decided each item, and a gate refuses the two compositions that make a measurement undecidable (an explicit tag
outside the closed kind set, and a declared-adversarial corpus with zero attack samples). Informative gaps - an
all-typical set - are notes, never silent."""
import json

from bts_sbom_app import cli, evalguard, evals


# ------------------------------------------------------------------ kind_of: the deciding rule is explicit and visible
def test_kind_rules_are_explicit_label_ood_or_the_declared_default():
    """AC: BSA-AC-1265"""
    assert evalguard.kind_of({"kind": "boundary"}, "") == "boundary"                                   # an explicit tag wins over everything
    assert evalguard.kind_of({"kind": "ADVERSARIAL "}, "") == "adversarial"                            # explicit tags are case/space-normalised
    assert evalguard.kind_of({"kind": "sneaky"}, "") == "sneaky"                                       # an unknown explicit tag is returned VERBATIM - never coerced to typical
    assert evalguard.kind_of({"label": "attack"}, "injection_samples") == "adversarial"                # a labelled attack sample is adversarial
    assert evalguard.kind_of({"label": "benign"}, "injection_samples") == "typical"                    # its benign twin probes precision, not attack strength
    assert evalguard.kind_of({"label": "attack"}, "rag_golden") == "typical"                           # the label rule only applies to the declared corpora
    assert evalguard.kind_of({"ood": True}, "") == "boundary"                                          # an ood item is boundary
    assert evalguard.kind_of({}, "") == "typical"                                                      # everything else: the declared default
    assert evalguard.KINDS == ("typical", "boundary", "adversarial") and set(evalguard.ADVERSARIAL_SETS) == {"injection_samples", "injection_holdout"}


def test_composition_counts_kinds_rules_and_flags_unknown_tags():
    """AC: BSA-AC-1265"""
    sets = {"s1": [{"q": "a"}, {"q": "b", "ood": True}, {"q": "c", "kind": "adversarial"}, {"q": "d", "kind": "weird"}],
            "injection_samples": [{"label": "attack"}, {"label": "benign"}]}
    c = evalguard.composition(sets)
    assert c["s1"]["kinds"] == {"typical": 1, "boundary": 1, "adversarial": 1} and c["s1"]["n"] == 4
    assert c["s1"]["kind_rules"] == {"explicit": 2, "label": 0, "ood": 1, "default": 1}
    assert c["s1"]["unknown_kinds"] == [{"kind": "weird", "q": "d"}]                                   # the unknown tag is named, with its item
    assert c["injection_samples"]["kinds"] == {"typical": 1, "boundary": 0, "adversarial": 1} and c["injection_samples"]["kind_rules"]["label"] == 2


def test_coverage_gate_fails_undecidable_compositions_and_notes_the_rest():
    """AC: BSA-AC-1265"""
    good = evalguard.composition({"injection_samples": [{"label": "attack"}, {"label": "benign"}], "chat": [{"q": "a"}]})
    failed, notes = evalguard.coverage_gate(good)
    assert failed == [] and any(t.startswith("chat:") for t in notes)                                  # all-typical chat set: a NOTE, not a failure
    unknown = evalguard.composition({"s": [{"q": "x", "kind": "tricky"}]})
    f2, n2 = evalguard.coverage_gate(unknown)
    assert len(f2) == 1 and "outside the closed set" in f2[0] and "tricky" in f2[0] and n2 == []
    empty_attacks = evalguard.composition({"injection_holdout": [{"label": "benign"}, {"label": "benign"}]})
    f3, _ = evalguard.coverage_gate(empty_attacks)
    assert len(f3) == 1 and "0 attack samples" in f3[0] and "recall is undecidable" in f3[0]           # a recall number with no positive class


def test_eval_inventory_covers_every_declared_corpus_on_this_repo():
    """AC: BSA-AC-1265"""
    inv = evals.eval_inventory()                                                                       # the real corpora: retrieval + injection + chat routing
    names = set(inv["sets"])
    assert {"rag_golden", "rag_dev", "rag_test", "chat_features", "injection_samples", "injection_holdout"} <= names
    cf = inv["sets"]["chat_features"]
    assert cf["n"] == 27 and cf["kinds"]["typical"] == 27 and cf["kind_rules"]["default"] == 27        # the routing set is honestly all-typical, and the report says so
    ih = inv["sets"]["injection_holdout"]
    assert ih["kinds"]["adversarial"] >= 1 and ih["kind_rules"]["label"] == ih["n"]                    # the label rule decided every injection item
    assert inv["coverage_gate"]["pass"] is True and inv["coverage_gate"]["failed"] == []
    assert any(t.startswith("chat_features:") for t in inv["coverage_gate"]["notes"])                  # the only-typical gap is visible, not silent


def test_the_evalsets_command_reports_the_composition_and_gates_it(capsys):
    """AC: BSA-AC-1265"""
    assert cli.main(["evalsets", "--json"]) == 0                                                       # the repo's real composition passes
    rep = json.loads(capsys.readouterr().out)
    assert rep["inventory"]["coverage_gate"]["pass"] is True and "chat_features" in rep["inventory"]["sets"]
    out = capsys.readouterr()
    assert cli.main(["evalsets"]) == 0
    text = capsys.readouterr().out
    assert "composition (전형/경계/적대):" in text and "typical 27" in text and "coverage gate: pass" in text
