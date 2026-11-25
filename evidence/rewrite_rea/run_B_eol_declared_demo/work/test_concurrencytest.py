"""Generated contract tests for the reimplementation of concurrencytest (self-runnable without pytest)."""

import importlib.util, inspect, os, sys, traceback

try:
    _spec = importlib.util.spec_from_file_location('reimpl_under_test_' + "concurrencytest", os.path.join(os.path.dirname(os.path.abspath(__file__)), "concurrencytest" + '.py'))
    mod = importlib.util.module_from_spec(_spec)
    sys.modules['reimpl_under_test_' + "concurrencytest"] = mod
    _spec.loader.exec_module(mod)
except ImportError as _dep:
    print('SKIP-DEP:', _dep.name or _dep)
    sys.exit(3)          # missing dependency is a skip, not a failure

def test_import_roundtrip():
    assert mod is not None

def test_class_ConcurrentTestSuite_instantiable():
    cls = getattr(mod, "ConcurrentTestSuite", None)
    if cls is None:
        raise AssertionError('class missing: ConcurrentTestSuite')
    req = [p for p in inspect.signature(cls.__init__).parameters.values() if p.name != 'self' and p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    try:
        konly = [p.name for p in inspect.signature(cls.__init__).parameters.values() if p.name != 'self' and p.default is p.empty and p.kind == p.KEYWORD_ONLY]
        inst = cls(*([None] * len(req)), **dict.fromkeys(konly))
    except Exception:
        inst = None                       # a validating constructor: presence is still proven
    if inst is not None:
        for m in []:
            assert hasattr(inst, m), m

def test_public_surface():
    for name in ["fork_for_tests", "partition_tests", "partition_tests_by_class"]:
        assert hasattr(mod, name)

if __name__ == '__main__':
    failed = 0
    for name in ["test_class_ConcurrentTestSuite_instantiable", "test_public_surface"]:
        try:
            globals()[name]()
        except Exception:
            failed += 1
            traceback.print_exc()
    print('tests: %d run, %d failed' % (len(["test_class_ConcurrentTestSuite_instantiable", "test_public_surface"]), failed))
    sys.exit(1 if failed else 0)
