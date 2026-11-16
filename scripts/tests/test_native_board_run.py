"""Decision controls for a whole board run, on a virtual clock and a fake wire.

The runner is run end to end against the fake wire of the board tests, which
answers each request at once, so the paced posts take no real time.
"""

import contextlib
import datetime as dt
import hashlib
import json
import os
import time
import typing as typ
from types import SimpleNamespace
from unittest import mock

import capture_identity
import native_board_cases as cases
import native_board_control as control
import pytest
from test_native_board_wire import FakeWire, environment
from virtual_clock import VirtualClock

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from protocol_capture import Recorder

BINARY = b"binary"
EPOCH_SECONDS = 600
NAMESPACE_INODE = environment()["emulator_netns_inode"]


def call_run(plan_dir: Path, receipt: Path, binary: Path, output: Path) -> dict:
    """Run the control with its four paths.

    Returns
    -------
    dict
        The report.
    """
    return control.run(control.RunPaths(plan_dir, receipt, binary, output))


def fake_wire(recorder: Recorder, _deadline: float) -> FakeWire:
    """Build the fake wire in place of the real one.

    Returns
    -------
    FakeWire
        A wire that answers each request at once.
    """
    return FakeWire(recorder)


@pytest.fixture
def staged(tmp_path: Path) -> cabc.Iterator[Path]:
    """Stage a plan, a receipt and a binary, and fake the clock, the gates and the wire.

    Yields
    ------
    pathlib.Path
        The directory that holds the staged inputs.
    """
    cases.write_plan(tmp_path / "plan", environment())
    deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=EPOCH_SECONDS)
    (tmp_path / "receipt.json").write_text(
        json.dumps({
            "deadline_utc": deadline.isoformat(),
            "emulator_netns_inode": NAMESPACE_INODE,
        })
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
        stack.enter_context(mock.patch.object(os, "stat", stat))
        stack.enter_context(mock.patch.object(control, "runtime_gate"))
        stack.enter_context(mock.patch.object(control, "Wire", fake_wire))
        stack.enter_context(mock.patch.object(control, "ORACLE_SHA256", digest))
        yield tmp_path


class RunTests:
    """Check a whole run of the board case."""

    def test_a_clean_run_completes_and_checks_its_own_report(
        self, staged: Path
    ) -> None:
        """The run completes, passes its offline check and writes its report."""
        report = call_run(
            staged / "plan", staged / "receipt.json", staged / "binary", staged / "out"
        )
        assert report["status"] == "completed", report["error"]
        written = json.loads((staged / "out/report.json").read_text())
        assert written == report, "the written report differs from the returned one"
        assert len(report["segments_hex"]) == len(report["post_data_hex"]) - 1, (
            "a post that must be refused made a segment"
        )
        assert report["full_a7"] == "not_exercised", "a baseline claim"

    def test_the_report_records_the_identity_of_the_runner_and_the_generator(
        self, staged: Path
    ) -> None:
        """The report holds each set digest and the record of its modules."""
        report = call_run(
            staged / "plan", staged / "receipt.json", staged / "binary", staged / "out"
        )
        for role, modules in (
            ("runner", control.CAPTURE_MODULES),
            ("producer", control.PRODUCER_MODULES),
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
        with pytest.raises(ValueError, match="Native source fork differs"):
            call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )
        assert not (staged / "out").exists(), "the output was made"

    def test_a_deadline_beyond_the_epoch_is_refused(self, staged: Path) -> None:
        """A deadline further off than twelve minutes is refused."""
        late = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=2 * EPOCH_SECONDS)
        (staged / "receipt.json").write_text(
            json.dumps({"deadline_utc": late.isoformat()})
        )
        with pytest.raises(ValueError, match="deadline differs"):
            call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )

    def test_a_failure_in_the_case_is_reported_and_the_wire_closed(
        self, staged: Path
    ) -> None:
        """A failing case fails the report, keeps its bytes and closes every flow."""
        with mock.patch.object(
            control, "execute_case", side_effect=ValueError("Board post failed")
        ):
            report = call_run(
                staged / "plan",
                staged / "receipt.json",
                staged / "binary",
                staged / "out",
            )
        assert report["status"] == "failed", "status"
        assert report["error"] == "ValueError: Board post failed", report["error"]
        written = json.loads((staged / "out/report.json").read_text())
        assert written["status"] == "failed", "the written report differs"
