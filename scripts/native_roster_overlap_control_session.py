"""Hold the as-run state of one control-only overlap and run its phases.

:class:`Session` runs the phases of the control driver in their original
order: setup, the coordinator operations, teardown, the socket close and the
report. The driver in ``native_roster_overlap_control`` decides when each
phase runs and what it does on failure.
"""

import datetime as dt
import json
import time
import typing as typ

from native_ban_expiry_control import utc
from native_roster_overlap_control_checks import (
    check_overlap,
    exact_rows,
    expected_frame,
    need,
    one,
    sha,
)
from native_roster_overlap_control_drain import DualDrain
from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from protocol_capture import Recorder

MAX_SECONDS = 600  # the longest that one overlap may run, in seconds


class Session:
    """The as-run state of one overlap, advanced by the driver's phases.

    Attributes are set by the phase that first needs them: ``recorder`` and
    ``end`` by :meth:`open`, ``steps`` and ``teardown_index`` by :meth:`setup`,
    and ``uids`` by the driver after the setup check.
    """

    recorder: Recorder
    end: float
    steps: list[dict]
    teardown_index: int
    uids: tuple[int, int]

    def __init__(self, plan: dict, plan_dir: Path, receipt_path: Path) -> None:
        """Admit the prepared plan and the capture receipt, before any socket.

        Parameters
        ----------
        plan : dict
            The prepared plan, already checked by the driver.
        plan_dir : pathlib.Path
            The directory that holds the prepared plan.
        receipt_path : pathlib.Path
            The capture receipt, a JSON file with the overlap deadline.
        """
        self.plan = plan
        self.plan_dir = plan_dir
        self.receipt_path = receipt_path
        self.receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.deadline = utc(self.receipt["deadline_utc"])
        need(
            0
            < (self.deadline - dt.datetime.now(dt.UTC)).total_seconds()
            <= MAX_SECONDS,
            "Overlap epoch must fit10min",
        )
        self.actions = 0
        self.operation_map: list[dict] = []
        self.late_observations: list[str] = []
        self.overlap_status = "not_completed"
        self.teardown_status = "not_started"
        self.old_or_new: str | None = None
        self.drain: DualDrain | None = None

    def open(
        self,
        output: Path,
        recorder_type: cabc.Callable[[dict], Recorder],
    ) -> None:
        """Create the output directory, then start the recorder and the clock.

        Parameters
        ----------
        output : pathlib.Path
            The directory to create; it must not exist.
        recorder_type : collections.abc.Callable[[dict], Recorder]
            The recorder class, called with the plan.
        """
        output.mkdir(parents=True, exist_ok=False)
        self.recorder = recorder_type(self.plan)
        self.end = time.monotonic() + min(
            MAX_SECONDS, (self.deadline - dt.datetime.now(dt.UTC)).total_seconds()
        )

    def mark(self, label: str, event_start: int, frame_start: int) -> None:
        """Record the event and frame ranges of one operation.

        Parameters
        ----------
        label : str
            The operation label, as the source plan names it.
        event_start : int
            The first event of the operation.
        frame_start : int
            The first frame of the operation.
        """
        self.operation_map.append({
            "label": label,
            "event_range": [event_start, len(self.recorder.events)],
            "frame_range": [frame_start, len(self.recorder.frames)],
        })

    def setup(self) -> None:
        """Run the setup requests and record the frames they produce."""
        self.steps = self.plan["steps"]
        self.teardown_index = next(
            i for i, s in enumerate(self.steps) if s["op"] == "shutdown_write"
        )
        event_start, frame_start = len(self.recorder.events), len(self.recorder.frames)
        for action, step in enumerate(self.steps[: self.teardown_index]):
            remaining = self.end - time.monotonic()
            need(remaining > 0, "Setup deadline reached")
            self.recorder.execute(
                action, {**step, "timeout": min(step.get("timeout", 2), remaining)}
            )
            self.actions += 1
        self.mark("setup", event_start, frame_start)

    def coordinate(self) -> None:
        """Run the coordinator operations in the order the source plan gives."""
        overlap = self.plan["overlap"]
        drain = DualDrain(self.recorder, self.end)
        self.drain = drain
        for operation in self.plan["coordinator"]["operations"]:
            event_start, frame_start = (
                len(self.recorder.events),
                len(self.recorder.frames),
            )
            try:
                self._operation(drain, operation, overlap)
            finally:
                self.mark(operation["label"], event_start, frame_start)

    def _operation(self, drain: DualDrain, operation: dict, overlap: dict) -> None:
        """Run one coordinator operation of the send, drain or quiet kind.

        Parameters
        ----------
        drain : DualDrain
            The collector of both sockets.
        operation : dict
            The source operation.
        overlap : dict
            The overlap section of the source plan.

        Raises
        ------
        ValueError
            When the operation kind is not recognised.
        """
        match operation["op"]:
            case "send":
                self._send(operation, overlap)
            case "drain":
                self._drain(drain, operation, overlap)
            case "quiet":
                self._quiet(operation, overlap)
            case _:
                message = "Unrecognised coordinator operation"
                raise ValueError(message)

    def _send(self, operation: dict, overlap: dict) -> None:
        """Send one request of the overlap on its connection.

        Parameters
        ----------
        operation : dict
            The source send operation.
        overlap : dict
            The overlap section of the source plan, with the request bytes.
        """
        self.recorder.execute(
            self.actions,
            {
                "op": "send",
                "connection": operation["connection"],
                "hex": overlap[operation["packet_key"]],
                "timeout": min(2, self.end - time.monotonic()),
            },
        )
        self.actions += 1

    def _drain(self, drain: DualDrain, operation: dict, overlap: dict) -> None:
        """Drain the frames of a drain operation and check them.

        Parameters
        ----------
        drain : DualDrain
            The collector of both sockets.
        operation : dict
            The source drain operation.
        overlap : dict
            The overlap section of the source plan, with the drain timing.
        """
        required = {tuple(item) for item in operation["required"]}
        frames = drain.until(required, overlap["drain_seconds"])
        a_uid, b_uid = self.uids
        if operation["label"] == "overlap-drain":
            self.old_or_new = check_overlap(frames, a_uid, b_uid)
        else:
            need(len(frames) == 1, "Unexpected frame before stable snapshot")
            exact_rows(one(frames, "a", 0, 13, 1), a_uid, b_uid, b_new=True)
            self.overlap_status = "completed"

    def _quiet(self, operation: dict, overlap: dict) -> None:
        """Observe that a connection stays quiet, recording a late frame.

        Parameters
        ----------
        operation : dict
            The source quiet operation.
        overlap : dict
            The overlap section of the source plan, with the quiet timing.
        """
        try:
            self.recorder.execute(
                self.actions,
                {
                    "op": "expect_quiet",
                    "connection": operation["connection"],
                    "timeout": min(
                        overlap["quiet_seconds"], self.end - time.monotonic()
                    ),
                },
            )
        except ValueError as failure:
            self.late_observations.append(f"{operation['label']}: {failure}")
        self.actions += 1

    def teardown(self) -> None:
        """Run the teardown steps, then grade how the teardown ended."""
        before_teardown = len(self.recorder.frames)
        event_start, frame_start = len(self.recorder.events), len(self.recorder.frames)
        eof_actions: set[int] = set()
        self.teardown_status = "in_progress"
        try:
            for step in self.steps[self.teardown_index :]:
                remaining = self.end - time.monotonic()
                need(remaining > 0, "Teardown deadline reached")
                if step["op"] == "read_eof":
                    eof_actions.add(self.actions)
                self.recorder.execute(
                    self.actions,
                    {**step, "timeout": min(step.get("timeout", 2), remaining)},
                )
                self.actions += 1
        finally:
            self.mark("teardown", event_start, frame_start)
        leaves = self._leaves(before_teardown)
        need(bool(leaves), "Departure UID missing from retained teardown")
        late_bytes = any(
            event["event"] == "receive"
            and event["hex"]
            and event["action"] in eof_actions
            for event in self.recorder.events[event_start:]
        )
        self.teardown_status = (
            "completed_with_late_bytes"
            if self.late_observations
            or late_bytes
            or len(self.recorder.frames[before_teardown:]) > len(leaves)
            else "completed"
        )

    def _leaves(self, before: int) -> list[dict]:
        """Find the departure frames of account b that the teardown retained.

        Parameters
        ----------
        before : int
            The frame count at the start of the teardown.

        Returns
        -------
        list[dict]
            The departure frames of account b, from connection a.
        """
        b_uid = self.uids[1]
        return [
            frame
            for frame in self.recorder.frames[before:]
            if expected_frame(frame, "a", TYPE_USER_LEFT, 0, 0)
            and fields(frame).get(FIELD_USER_ID) == b_uid.to_bytes(2, "big")
        ]

    def fail_teardown(self) -> None:
        """Mark an unfinished teardown as failed, after a failure."""
        if self.teardown_status == "in_progress":
            self.teardown_status = "failed"

    def close(self) -> None:
        """Close both sockets, recording each close as an event."""
        for label, sock in list(self.recorder.sockets.items()):
            sock.close()
            self.recorder.event(self.actions, label, "close")

    def report(self, status: str, error: str, oracle: str) -> dict:
        """Build the as-run report from the state of the overlap.

        Parameters
        ----------
        status : str
            The overall status, ``"completed"`` or ``"failed"``.
        error : str
            The error text, empty when the overlap did not fail.
        oracle : str
            The pinned digest of the oracle binary that the run was checked against.

        Returns
        -------
        dict
            The as-run report, with the digests of its sources.
        """
        return {
            "status": status,
            "overlap_status": self.overlap_status,
            "teardown_status": self.teardown_status,
            "late_observations": self.late_observations,
            "error": error,
            "completed_actions": self.actions,
            "old_or_new_snapshot": self.old_or_new,
            "scope": (
                "one outstanding 300 and session-only 304; no cross-socket total order"
            ),
            "oracle_sha256": oracle,
            "plan_sha256": sha((self.plan_dir / "plan.json").read_bytes()),
            "receipt_sha256": sha(self.receipt_path.read_bytes()),
            "coordinator_sha256": sha(
                json.dumps(self.plan["coordinator"], sort_keys=True).encode()
            ),
            "operation_map": self.operation_map,
            "started_at_utc": self.recorder.started_at_utc,
            "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
            "events": self.recorder.events,
            "frames": self.recorder.frames,
            "unparsed_hex": {}
            if self.drain is None
            else {name: data.hex() for name, data in self.drain.buffers.items()},
            "streams": self.recorder.streams(),
        }
