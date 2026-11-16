"""Decision controls for a whole liveness run, on a virtual clock and fake sockets.

The runner is run end to end against :class:`FakeConsumer`, which answers over
socket pairs. A virtual clock replaces ``time`` and the ``select`` timeouts, so
the 135-second window takes no real time.
"""

import contextlib
import datetime as dt
import hashlib
import json
import os
import select
import sys
import time
import typing as typ
from types import SimpleNamespace
from unittest import mock

import capture_identity
import native_liveness_cases as cases
import native_liveness_control as control
import pytest
from liveness_support import FakeConsumer, environment
from virtual_clock import VirtualClock

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

BINARY = b"binary"
NAMESPACE_INODE = environment()["emulator_netns_inode"]
EPOCH_SECONDS = 700


class RunConsumer(FakeConsumer):
    """The fake consumer, run with the deadline that the runner chooses."""

    def __init__(self, plan: dict, deadline: float) -> None:
        """Start the fake consumer and give it the runner's deadline."""
        super().__init__(plan)
        self.deadline = deadline


def run_modules() -> list:
    """List the modules that read ``ORACLE_SHA256`` when the runner runs.

    Returns
    -------
    list
        The control module and, when it is split out, the module that checks
        the report.
    """
    found = [control]
    report = sys.modules.get("native_liveness_control_report")
    return [*found, report] if report is not None else found


def call_run(plan_dir: Path, receipt: Path, binary: Path, output: Path) -> dict:
    """Run the control with its four paths.

    Returns
    -------
    dict
        The report.
    """
    return control.run(control.RunPaths(plan_dir, receipt, binary, output))


@pytest.fixture
def staged(tmp_path: Path) -> cabc.Iterator[Path]:
    """Stage a plan, a receipt and a binary, and fake the clock and the gates.

    Yields
    ------
    pathlib.Path
        The directory that holds the staged inputs.
    """
    cases.write_plan(tmp_path / "plan", environment())
    deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=EPOCH_SECONDS)
    (tmp_path / "receipt.json").write_text(
        json.dumps({"deadline_utc": deadline.isoformat()})
    )
    (tmp_path / "binary").write_bytes(BINARY)
    clock = VirtualClock()
    real_stat = os.stat

    def stat(
        path: str | Path,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> object:
        """Answer the namespace path; leave every other path to the system.

        Returns
        -------
        object
            The stat result.
        """
        if path == "/proc/self/ns/net":
            return SimpleNamespace(st_ino=NAMESPACE_INODE)
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    digest = hashlib.sha256(BINARY).hexdigest()
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(time, "monotonic", side_effect=lambda: clock.now)
        )
        stack.enter_context(mock.patch.object(time, "monotonic_ns", clock.monotonic_ns))
        stack.enter_context(mock.patch.object(time, "sleep", clock.sleep))
        stack.enter_context(mock.patch.object(select, "select", clock.select))
        stack.enter_context(mock.patch.object(os, "stat", stat))
        stack.enter_context(mock.patch.object(control, "runtime_gate"))
        stack.enter_context(mock.patch.object(control, "Timeline", RunConsumer))
        for module in run_modules():
            stack.enter_context(mock.patch.object(module, "ORACLE_SHA256", digest))
        yield tmp_path


class RunTests:
    """Check a whole run of the generated schedule."""

    def test_a_clean_run_completes_and_checks_its_own_report(
        self, staged: Path
    ) -> None:
        """The run completes, passes its offline check and writes both files."""
        report = call_run(
            staged / "plan", staged / "receipt.json", staged / "binary", staged / "out"
        )
        assert report["status"] == "completed", report["error"]
        written = json.loads((staged / "out/report.json").read_text())
        assert written == report, "the written report differs from the returned one"
        assert (staged / "out/plan.json").read_bytes() == (
            staged / "plan/plan.json"
        ).read_bytes(), "the plan was not copied"
        assert report["window_completed"] is True, "the window did not complete"
        assert report["native_conformance"] is False, "a conformance claim"
        assert set(report["window_status"]) == set(report["streams"]), (
            "a flow has no window status"
        )

    def test_the_report_records_the_identity_of_the_runner_and_the_generator(
        self, staged: Path
    ) -> None:
        """The report holds each set digest and the record of its modules."""
        report = call_run(
            staged / "plan", staged / "receipt.json", staged / "binary", staged / "out"
        )
        for role, modules in (
            ("source", control.CAPTURE_MODULES),
            ("cases", control.CASES_MODULES),
        ):
            record = report[f"{role}_identity"]
            assert report[f"{role}_sha256"] == record["digest"], (
                f"{role}: the hash is not the digest of the module set"
            )
            assert [item["path"] for item in record["files"]] == [
                f"scripts/{name}" for name in modules
            ], f"{role}: the identity lists other modules than the declared set"
            assert capture_identity.check(record, modules), (
                f"{role}: the identity does not describe the live modules"
            )

    def test_a_binary_that_differs_is_refused_before_any_output(
        self, staged: Path
    ) -> None:
        """A binary with another hash stops the run before the output exists."""
        (staged / "binary").write_bytes(b"other")
        with pytest.raises(ValueError, match="Oracle binary differs"):
            call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )
        assert not (staged / "out").exists(), "the output was made"

    def test_an_epoch_that_does_not_fit_is_refused(self, staged: Path) -> None:
        """A deadline further off than twelve minutes is refused."""
        late = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=EPOCH_SECONDS + 100)
        (staged / "receipt.json").write_text(
            json.dumps({"deadline_utc": late.isoformat()})
        )
        with pytest.raises(ValueError, match="fit12min"):
            call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )

    def test_a_failure_in_the_window_is_reported_not_raised(self, staged: Path) -> None:
        """A flow that fails during the run fails the report and keeps its bytes."""
        with mock.patch.object(
            control, "check_observer", side_effect=ValueError("Observer107 failed")
        ):
            report = call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )
        assert report["status"] == "failed", "status"
        assert report["error"] == "ValueError: Observer107 failed", report["error"]
        assert report["window_completed"] is False, "the window cannot have completed"
        assert report["events"], "the events were not kept"
