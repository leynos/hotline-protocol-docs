"""Run a ``unittest`` discovery and write each test's outcome as JSON.

This script uses only the standard library because it runs under the same
``python3`` that ``make test-legacy`` uses, not the project environment.

Usage: ``python3 tools/golden_unittest_runner.py OUT START PATTERN [FILTER...]``
from the repository root. A test runs when its id contains any FILTER, or when
there is none. ``OUT`` receives a JSON object that maps test ids to
``{"outcome": ..., "detail": ...}``.
"""

import json
import sys
import traceback
import unittest
from pathlib import Path

OK = "ok"
DETAIL_WIDTH = 200


class Collector(unittest.TestResult):
    """Collects the outcome of each test by its id."""

    def __init__(self) -> None:
        """Start with no outcomes."""
        super().__init__()
        self.outcomes: dict[str, dict[str, str]] = {}

    def _put(self, test: unittest.TestCase, outcome: str, detail: str = "") -> None:
        """Record an outcome; a failure is never overwritten by a later pass."""
        key = test.id()
        number = 1
        while key in self.outcomes and self.outcomes[key]["outcome"] == OK:
            number += 1
            key = f"{test.id()}#{number}"
        previous = self.outcomes.get(key)
        if previous is None or outcome != OK:
            self.outcomes[key] = {"outcome": outcome, "detail": detail}

    def addSuccess(self, test: unittest.TestCase) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record a pass."""
        self._put(test, OK)

    def addError(self, test: unittest.TestCase, err: tuple) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record an error with the last line of its message."""
        self._put(test, "error", _last_line(err))

    def addFailure(self, test: unittest.TestCase, err: tuple) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record a failed assertion with the last line of its message."""
        self._put(test, "fail", _last_line(err))

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record a skip with its reason."""
        self._put(test, "skipped", reason)

    def addExpectedFailure(self, test: unittest.TestCase, err: tuple) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record an expected failure."""
        self._put(test, "expected failure")

    def addUnexpectedSuccess(self, test: unittest.TestCase) -> None:  # ruff: ignore[invalid-function-name]  # unittest's own method name
        """Record an unexpected success."""
        self._put(test, "unexpected success")

    def addSubTest(  # ruff: ignore[invalid-function-name]  # unittest's own method name
        self, test: unittest.TestCase, subtest: unittest.TestCase, err: tuple | None
    ) -> None:
        """Record a failing subtest against its parent test."""
        if err is not None:
            outcome = "fail" if issubclass(err[0], test.failureException) else "error"
            self._put(test, outcome, _last_line(err))


def _last_line(err: tuple) -> str:
    """Return the last non-empty line of an exception's message, shortened.

    Returns
    -------
    str
        That line, cut to ``DETAIL_WIDTH`` characters, or an empty string.
    """
    text = "".join(traceback.format_exception_only(err[0], err[1]))
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1][:DETAIL_WIDTH] if lines else ""


def flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    """List the test cases in a suite, however deeply nested.

    Returns
    -------
    list[unittest.TestCase]
        Every leaf test.
    """
    cases: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            cases.extend(flatten(item))
        else:
            cases.append(item)
    return cases


def main(argv: list[str]) -> int:
    """Discover, run and report.

    Returns
    -------
    int
        Zero once the outcomes are written, whatever they are.
    """
    out, start, pattern, *filters = argv
    # Behave as ``python3 -m unittest`` does: the working directory leads the path.
    sys.path[0] = ""
    suite = unittest.TestLoader().discover(start, pattern)
    chosen = [
        case
        for case in flatten(suite)
        if not filters or any(f in case.id() for f in filters)
    ]
    result = Collector()
    result.buffer = True
    unittest.TestSuite(chosen).run(result)
    Path(out).write_text(json.dumps(result.outcomes), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
