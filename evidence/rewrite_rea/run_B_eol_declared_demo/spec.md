# Clean-room spec: concurrencytest

Why reimplementation: license: GPL-3.0-only (strong-copyleft) - a patch cannot change a licence; eol: DEMO declaration for the mechanism run - not a measured fact about this component

## Requirements

- reimplement the public surface below as a NEW module named `concurrencytest.py`
- same public names and signatures; behaviour follows each contract
- no third-party dependencies beyond: traceback, testtools, typing, sys, os, multiprocessing, unittest, subunit, collections, itertools, atexit

## Function contracts
- `fork_for_tests(num_processes, partition_func)`:
  Create a test runner that executes tests in multiple forked processes.
  
  The returned callable partitions a test suite into groups and executes each group
  in a separate worker process using `os.fork()`.
  
  Args:
  num_processes:
  Number of worker processes to spawn. Defaults to the number of CPUs on the
  system.
  
  partition_func:
  Function used to partition tests across workers. It receives the test suite
  and the worker count and must return a list of test lists (one list per
  worker). Defaults to `partition_tests` (round-robin partition strategy).
  
  Returns:
  Callable function that takes a `TestSuite` and returns an iterable of
  test-like objects compatible with `ConcurrentTestSuite`.
- `partition_tests(suite, count)`:
  Partition a unittest suite into multiple lists of tests, using round-robin.
  
  This function splits a test suite into its individual test cases and assigs them
  in a round-robin fashion to distribute load evenly across workers. This helps
  avoid situations where one worker gets all slow tests while others finish quickly.
  One potential drawback is that if you have a `setUpClass`/`tearDownClass` defined
  in a `TestCase`, it may be run multiple times if tests from the same class are run
  on different workers.
  
  Args:
  suite: `TestSuite` containing all test cases to partition.
  count: Number of partitions.
  
  Returns:
  List of `count` lists, where each inner list contains the tests assigned to
  that partition. The tests maintain their original order, distributed
  round-robin.
- `partition_tests_by_class(suite, count)`:
  Partition a unittest suite into multiple lists of tests, keeping class locality.
  
  This function groups all tests belonging to the same test case class and assigns
  them as a block to the worker with the current smallest number of tests already
  assigned. This ensures that all tests from a single class run in the same worker,
  which preserves `setUpClass`/`tearDownClass` lifecycle semantics.
  
  Args:
  suite: `TestSuite` containing all test cases to partition.
  count: Number of partitions.
  
  Returns:
  List of `count` lists, where each inner list contains the tests assigned to
  that partition. Each class's tests are contained within a single partition,
  and partitions are balanced by total test count.

## Class contracts
- `ConcurrentTestSuite` methods (none): (contract unspecified)

## Clean-room rule

Write original code. Do not reproduce any existing implementation text.


## Compatibility target
- the legacy component is end-of-life or incompatible: the replacement must run on the interpreter that executes the contract tests (Python 3.12.10) and use no standard-library API that current releases removed