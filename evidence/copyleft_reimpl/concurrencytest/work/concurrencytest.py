from typing import Callable, List, Iterable, Sequence, Any, Tuple, Dict
import os
import sys
import atexit
import traceback
import unittest
import itertools
import collections
import multiprocessing
import pickle


def _flatten_tests(suite: unittest.TestSuite) -> List[unittest.TestCase]:
    """Recursively flatten a TestSuite into a list of TestCase instances.

    Preserves the in-order traversal of the suite.
    """
    tests: List[unittest.TestCase] = []

    def _recurse(s):
        if isinstance(s, unittest.TestSuite):
            for t in s:
                _recurse(t)
        else:
            # assume it's a TestCase-like object
            tests.append(s)

    _recurse(suite)
    return tests


def partition_tests(suite: unittest.TestSuite, count: int) -> List[List[unittest.TestCase]]:
    """
    Partition a unittest suite into `count` lists using round-robin distribution.

    Args:
        suite: TestSuite to partition.
        count: number of partitions.

    Returns:
        A list of `count` lists of TestCase objects, distributed round-robin.
    """
    if count <= 0:
        raise ValueError("count must be >= 1")
    flat = _flatten_tests(suite)
    # Create empty lists
    partitions: List[List[unittest.TestCase]] = [[] for _ in range(count)]
    for idx, test in enumerate(flat):
        partitions[idx % count].append(test)
    return partitions


def partition_tests_by_class(suite: unittest.TestSuite, count: int) -> List[List[unittest.TestCase]]:
    """
    Partition a unittest suite into `count` lists while keeping tests from the same
    TestCase class together. Assign each class block to the partition with the
    currently smallest total number of tests, to attempt balance by count.

    Args:
        suite: TestSuite to partition.
        count: number of partitions.

    Returns:
        A list of `count` lists of TestCase objects.
    """
    if count <= 0:
        raise ValueError("count must be >= 1")
    flat = _flatten_tests(suite)
    # Group tests by test class
    groups = collections.OrderedDict()
    for test in flat:
        cls = type(test)
        groups.setdefault(cls, []).append(test)

    # Start with empty partitions
    partitions: List[List[unittest.TestCase]] = [[] for _ in range(count)]
    sizes = [0] * count

    # For each group in original order, assign to smallest partition
    for group_tests in groups.values():
        # find index with minimal size (first minimal)
        min_idx = min(range(count), key=lambda i: sizes[i])
        partitions[min_idx].extend(group_tests)
        sizes[min_idx] += len(group_tests)

    return partitions


class ConcurrentTestSuite:
    """
    Lightweight container representing the result of a concurrent test execution.

    The object is iterable yielding per-worker result summaries (simple dicts).
    """

    def __init__(self, worker_results: Sequence[Dict[str, Any]]):
        self._worker_results = list(worker_results)

    def __iter__(self):
        return iter(self._worker_results)

    def __len__(self):
        return len(self._worker_results)

    def __getitem__(self, item):
        return self._worker_results[item]

    def summary(self) -> Dict[str, int]:
        """Aggregate a simple summary across workers.

        Returns a dict with keys: runs, failures, errors, skipped
        """
        agg = {"runs": 0, "failures": 0, "errors": 0, "skipped": 0}
        for w in self._worker_results:
            agg["runs"] += int(w.get("runs", 0))
            agg["failures"] += int(w.get("failures", 0))
            agg["errors"] += int(w.get("errors", 0))
            agg["skipped"] += int(w.get("skipped", 0))
        return agg


def fork_for_tests(num_processes: int = None,
                   partition_func: Callable[[unittest.TestSuite, int], List[List[unittest.TestCase]]] = None) -> Callable[[unittest.TestSuite], ConcurrentTestSuite]:
    """
    Create a callable that partitions a TestSuite and runs partitions in separate
    worker processes using os.fork().

    The returned callable accepts a TestSuite and returns a ConcurrentTestSuite
    containing per-worker result summaries.
    """
    if num_processes is None:
        try:
            num_processes = multiprocessing.cpu_count()
        except Exception:
            num_processes = 1
    if num_processes <= 0:
        raise ValueError("num_processes must be >= 1")

    if partition_func is None:
        partition_func = partition_tests

    def runner(suite: unittest.TestSuite) -> ConcurrentTestSuite:
        # Partition tests into lists of TestCase objects
        partitions = partition_func(suite, num_processes)

        # For each non-empty partition, create a pipe and fork a child to run it.
        fds: List[Tuple[int, int]] = []  # (r, w)
        pids: List[int] = []
        # Keep mapping from pid to read fd
        pid_to_rfd: Dict[int, int] = {}

        for part in partitions:
            r_fd, w_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                # Child
                try:
                    os.close(r_fd)
                    # Run the tests in this partition
                    # Build a TestSuite for these tests
                    suite_part = unittest.TestSuite(part)
                    result = unittest.TestResult()
                    try:
                        suite_part.run(result)
                    except Exception:
                        # Protect child from bubbling exception; record it
                        tb = traceback.format_exc()
                        summary = {
                            "runs": 0,
                            "failures": 0,
                            "errors": 1,
                            "skipped": 0,
                            "exceptions": [("internal", tb)],
                        }
                        # write and exit
                        with os.fdopen(w_fd, "wb") as wf:
                            wf.write(pickle.dumps(summary))
                        os._exit(1)

                    # Build a serializable summary of results
                    failures = [(getattr(t, 'id', None), str(e)) for t, e in getattr(result, 'failures', [])]
                    errors = [(getattr(t, 'id', None), str(e)) for t, e in getattr(result, 'errors', [])]
                    skipped = []
                    if hasattr(result, 'skipped'):
                        skipped = [(getattr(t, 'id', None), str(r)) for t, r in getattr(result, 'skipped', [])]

                    summary = {
                        "runs": getattr(result, 'testsRun', 0),
                        "failures": len(failures),
                        "errors": len(errors),
                        "skipped": len(skipped),
                        "failures_detail": failures,
                        "errors_detail": errors,
                        "skipped_detail": skipped,
                    }
                    with os.fdopen(w_fd, "wb") as wf:
                        wf.write(pickle.dumps(summary))
                finally:
                    # Ensure child exits
                    os._exit(0)
            else:
                # Parent
                os.close(w_fd)
                fds.append((r_fd, w_fd))
                pid_to_rfd[pid] = r_fd
                pids.append(pid)

        # Parent: collect results from children
        worker_results: List[Dict[str, Any]] = []

        # Read from each child's pipe once it exits
        for pid in pids:
            r_fd = pid_to_rfd.get(pid)
            # Wait for the child to finish
            try:
                _, _ = os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            # Read from fd
            data = b""
            try:
                # read all bytes
                with os.fdopen(r_fd, "rb") as rf:
                    data = rf.read()
                if data:
                    summary = pickle.loads(data)
                else:
                    summary = {"runs": 0, "failures": 0, "errors": 1, "skipped": 0, "note": "no data"}
            except Exception:
                summary = {"runs": 0, "failures": 0, "errors": 1, "skipped": 0, "exception": traceback.format_exc()}
            worker_results.append(summary)

        return ConcurrentTestSuite(worker_results)

    return runner
