"""Decision controls for a failed 304 run, on a socket pair and a faked schedule.

The schedule is replaced by one that keeps a partial reply and then fails, so
the run is checked for what it gates, what it keeps and what it releases.
"""

import datetime as dt
import hashlib
import json
import socket
import time
import typing as typ
from types import SimpleNamespace
from unittest import mock

import capture_identity
import native_rate304_cases as cases
import native_rate304_control as control
import pytest
from native_plan import packet
from rate304_support import ENV

if typ.TYPE_CHECKING:
    from pathlib import Path

BINARY = b"binary"
EPOCH_SECONDS = 500
PARTIAL_BYTES = 13
NAMESPACE_INODE = ENV["emulator_netns_inode"]


def call_run(plan_dir: Path, receipt: Path, binary: Path, output: Path) -> dict:
    """Run the control with its four paths.

    Returns
    -------
    dict
        The report.
    """
    return control.run(control.RunPaths(plan_dir, receipt, binary, output))


def stage(base: Path, deadline_seconds: int = EPOCH_SECONDS) -> tuple[Path, Path, Path]:
    """Stage a prepared plan, a capture receipt and a binary.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path, pathlib.Path]
        The plan directory, the receipt and the binary.
    """
    plan_dir = base / "plan"
    cases.write_plan(plan_dir, ENV)
    now = dt.datetime.now(dt.UTC)
    receipt = base / "receipt.json"
    receipt.write_text(
        json.dumps({
            "deadline_utc": (now + dt.timedelta(seconds=deadline_seconds)).isoformat(),
            "epoch_started_utc": (now - dt.timedelta(seconds=60)).isoformat(),
        })
    )
    binary = base / "binary"
    binary.write_bytes(BINARY)
    return plan_dir, receipt, binary


class RunTests:
    """Check what a 304 run gates, keeps and releases."""

    def run_failing(self, base: Path) -> tuple[dict, socket.socket]:
        """Run with a schedule that keeps a partial reply and then fails.

        Returns
        -------
        tuple[dict, socket.socket]
            The report, and the socket that the run must have closed.
        """
        plan_dir, receipt, binary = stage(base)
        plan = cases.source_plan(ENV)
        wire = control.Wire(plan, time.monotonic() + 3)
        owned, peer = socket.socketpair()
        wire.recorder.sockets["observer"] = owned
        wire.buffers["observer"] = bytearray()
        partial = bytes.fromhex(packet(0, 10, reply=1))[:PARTIAL_BYTES]

        def fail_after_receive(actual: control.Wire, _plan: dict) -> None:
            """Keep a partial reply, then fail the schedule.

            Raises
            ------
            ValueError
                Always, after the partial reply is kept.
            """
            peer.sendall(partial)
            peer.shutdown(socket.SHUT_WR)
            actual.poll(0.1)
            message = "synthetic schedule failure"
            raise ValueError(message)

        with (
            mock.patch.object(control, "prepared", return_value=plan),
            mock.patch.object(control, "runtime_gate"),
            mock.patch.object(control, "Wire", return_value=wire),
            mock.patch.object(control, "perform", side_effect=fail_after_receive),
            mock.patch.object(
                control, "ORACLE_SHA256", hashlib.sha256(BINARY).hexdigest()
            ),
            mock.patch.object(
                control.os, "stat", return_value=SimpleNamespace(st_ino=NAMESPACE_INODE)
            ),
        ):
            report = call_run(plan_dir, receipt, binary, base / "out")
        peer.close()
        return report, owned

    def test_a_failing_schedule_is_reported_and_its_bytes_kept(
        self, tmp_path: Path
    ) -> None:
        """The report keeps the partial reply and the terminal, and the run closes."""
        report, owned = self.run_failing(tmp_path)
        assert report["status"] == "failed", "status"
        assert report["error"] == "ValueError: synthetic schedule failure", report[
            "error"
        ]
        assert report["unparsed_hex"]["observer"], "the partial reply was not kept"
        assert report["terminals"]["observer"] == "eof", "terminal"
        assert owned.fileno() == -1, "the socket was not closed"
        written = json.loads((tmp_path / "out/report.json").read_text())
        assert written == report, "the written report differs from the returned one"
        assert (tmp_path / "out/plan.json").read_bytes() == (
            tmp_path / "plan/plan.json"
        ).read_bytes(), "the plan was not copied"

    def test_the_report_records_the_identity_of_the_runner_and_the_generator(
        self, tmp_path: Path
    ) -> None:
        """The report holds each set digest and the record of its modules."""
        report, _ = self.run_failing(tmp_path)
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

    def test_an_epoch_with_too_little_margin_is_refused(self, tmp_path: Path) -> None:
        """A deadline under 390 seconds away is refused before any output."""
        plan_dir, receipt, binary = stage(tmp_path, deadline_seconds=300)
        with (
            mock.patch.object(control, "runtime_gate"),
            pytest.raises(ValueError, match="lacks390s"),
        ):
            call_run(plan_dir, receipt, binary, tmp_path / "out")
        assert not (tmp_path / "out").exists(), "the output was made"

    def test_a_binary_that_differs_is_refused_before_any_output(
        self, tmp_path: Path
    ) -> None:
        """A binary with another hash stops the run before the output exists."""
        plan_dir, receipt, binary = stage(tmp_path)
        with (
            mock.patch.object(control, "runtime_gate"),
            mock.patch.object(
                control.os, "stat", return_value=SimpleNamespace(st_ino=NAMESPACE_INODE)
            ),
            pytest.raises(ValueError, match="Oracle binary differs"),
        ):
            call_run(plan_dir, receipt, binary, tmp_path / "out")
        assert not (tmp_path / "out").exists(), "the output was made"
