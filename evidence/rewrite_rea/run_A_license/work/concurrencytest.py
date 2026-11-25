# concurrencytest.py
"""
Clean-room reimplementation of concurrencytest public surface.
Exports:
- fork_for_tests
- partition_tests
- partition_tests_by_class
- ConcurrentTestSuite

This module provides utilities to split unittest suites across worker
processes and a lightweight wrapper for concurrent test suites.
"""
from typing import Callable, Iterable, List, Sequence, Any
import os
import multiprocessing
import unittest
from collections import OrderedDict, defaultdict
import itertools

__all__ = [
    "fork_for_tests",
    "partition_tests",
    "partition_tests_by_class",
    "ConcurrentTestSuite",
]


def _iter_tests(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    """Yield individual test cases from a TestSuite preserving order.

    This walks nested TestSuites and yields leaf test cases.
    """
    # unittest.TestSuite is iterable, yields either TestSuite or TestCase
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            for t in _iter_tests(item):
                yield t
        else:
            yield item


def partition_tests(suite: unittest.TestSuite, count: int) -> List[List[unittest.TestCase]]:
    """
    Partition a unittest suite into `count` lists using round-robin assignment.

    The order of tests in the suite is preserved overall, but allocation to
    partitions cycles through partitions to balance load.
    """
    if count <= 0:
        raise ValueError("count must be >= 1")

    tests = list(_iter_tests(suite))
    # initialize empty partitions
    partitions: List[List[unittest.TestCase]] = [[] for _ in range(count)]
    # round robin assign
    for idx, test in enumerate(tests):
        partitions[idx % count].append(test)
    return partitions


def partition_tests_by_class(suite: unittest.TestSuite, count: int) -> List[List[unittest.TestCase]]:
    """
    Partition a unittest suite into `count` lists while keeping tests from the same
    TestCase class together.

    Classes are assigned as blocks to the partition currently holding the fewest
    tests (by count), to balance total test counts across partitions.
    """
    if count <= 0:
        raise ValueError("count must be >= 1")

    # Collect tests grouped by their test class in encounter order
    class_order: List[Any] = []
    class_groups: dict = OrderedDict()

    for test in _iter_tests(suite):
        cls = test.__class__
        if cls not in class_groups:
            class_groups[cls] = []
            class_order.append(cls)
        class_groups[cls].append(test)

    # Initialize partitions and their sizes
    partitions: List[List[unittest.TestCase]] = [[] for _ in range(count)]
    sizes: List[int] = [0] * count

    # Assign each class block to the smallest partition so far
    for cls in class_order:
        block = class_groups[cls]
        # find index of partition with minimal size; break ties by first index
        min_idx = min(range(count), key=lambda i: sizes[i])
        partitions[min_idx].extend(block)
        sizes[min_idx] += len(block)

    return partitions


def fork_for_tests(num_processes: int = None, partition_func: Callable[[unittest.TestSuite, int], List[List[unittest.TestCase]]] = None) -> Callable[[unittest.TestSuite], Iterable[unittest.TestSuite]]:
    """
    Create a callable that partitions a test suite and returns per-worker TestSuites.

    The returned function takes a single unittest.TestSuite and returns an iterable
    (list) of unittest.TestSuite objects, one per worker. Each returned TestSuite
    contains the tests assigned to that worker according to partition_func.

    Args:
      num_processes: number of worker partitions to create; defaults to CPU count.
      partition_func: function(suite, count) -> list-of-lists-of-tests; defaults to partition_tests.
    """
    if num_processes is None:
        try:
            num_processes = multiprocessing.cpu_count()
        except Exception:
            num_processes = 1
    else:
        if num_processes <= 0:
            raise ValueError("num_processes must be >= 1")

    if partition_func is None:
        partition_func = partition_tests

    def _runner(suite: unittest.TestSuite) -> Iterable[unittest.TestSuite]:
        parts = partition_func(suite, num_processes)
        # Ensure we return exactly num_processes suites
        # If partition_func returns fewer or more lists, we normalize: truncate or extend
        if len(parts) < num_processes:
            # extend with empty lists
            parts = list(parts) + [[] for _ in range(num_processes - len(parts))]
        elif len(parts) > num_processes:
            parts = parts[:num_processes]

        suites = [unittest.TestSuite(p) for p in parts]
        return suites

    return _runner


class ConcurrentTestSuite:
    """
    Lightweight wrapper for a collection of test suites intended to be run concurrently.

    This class acts like a sequence of per-worker TestSuite objects. It does not
    itself spawn processes or run tests; it simply holds the grouping created by
    fork_for_tests. It supports iteration and length queries so it can be used by
    runners that expect an iterable of test-like objects.
    """

    def __init__(self, suites: Iterable[unittest.TestSuite]):
        # Normalize to list
        self._suites: List[unittest.TestSuite] = list(suites)

    def __iter__(self):
        return iter(self._suites)

    def __len__(self):
        return len(self._suites)

    def __getitem__(self, index):
        return self._suites[index]

    def addSuite(self, suite: unittest.TestSuite) -> None:
        """Append a per-worker TestSuite to this collection."""
        self._suites.append(suite)

    def removeSuite(self, suite: unittest.TestSuite) -> None:
        """Remove a specific TestSuite from the collection."""
        self._suites.remove(suite)

    def as_list(self) -> List[unittest.TestSuite]:
        """Return the internal suites as a list."""
        return list(self._suites)
