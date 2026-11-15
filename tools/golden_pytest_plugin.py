"""Pytest plugin for the test oracle: write each outcome as JSON.

Load it with ``-p golden_pytest_plugin`` and name the output file in
``GOLDEN_PYTEST_OUT``. A test is keyed ``module.Class.test`` (``module.test``
without a class), which is the ``unittest`` id of the test it replaced.
"""

import json
import os
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import pytest

RANK = ["ok", "skipped", "fail", "error"]
OUTCOMES: dict[str, dict[str, str]] = {}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Keep the worst outcome of the phases (and parameters) of each test."""
    path, _, name = report.nodeid.partition("::")
    key = f"{Path(path).stem}.{name.partition('[')[0].replace('::', '.')}"
    outcome = "skipped" if report.skipped else "ok" if report.passed else "fail"
    if outcome == "fail" and report.when != "call":
        outcome = "error"
    lines = [x for x in report.longreprtext.splitlines() if x.strip()] or [""]
    detail = lines[-1].removeprefix("E   ")[:200] if outcome != "ok" else ""
    known = OUTCOMES.get(key, {"outcome": "ok"})["outcome"]
    counts = report.when == "call" or outcome != "ok"
    if counts and RANK.index(outcome) >= RANK.index(known):
        OUTCOMES[key] = {"outcome": outcome, "detail": detail}


def pytest_sessionfinish() -> None:
    """Write the collected outcomes."""
    out = Path(os.environ["GOLDEN_PYTEST_OUT"])
    out.write_text(json.dumps(OUTCOMES), encoding="utf-8")
