"""Shared fixtures for the temporary-ban tests: loop naming and a fake recorder."""

import contextlib
import datetime as dt
import time
import typing as typ

import native_ban_expiry_cases as cases
import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc


@contextlib.contextmanager
def iteration(key: object) -> cabc.Iterator[None]:
    """Name the loop key in the message of any failed assertion or expectation.

    Parameters
    ----------
    key : object
        The value that identifies the loop iteration.

    Yields
    ------
    None
        The body of one iteration of a loop.

    Raises
    ------
    AssertionError
        When the body fails, with the key prefixed to the failure message.
    """
    try:
        yield
    except (AssertionError, pytest.fail.Exception) as failure:
        message = f"iteration {key!r}: {failure}"
        raise AssertionError(message) from failure


def environment() -> dict:
    """Describe the owned emulator and working image of the control runs.

    Returns
    -------
    dict
        The runtime identity that the plans and receipts must match.
    """
    return {
        "source_a7_sha256": cases.A7_SHA,
        "fixture_profile": "control-only",
        "full_file_baseline": "not_exercised",
        "emulator_pid": 9001,
        "emulator_starttime": 111,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 456,
        "owned_working_image": (
            "/repo/state/mac-runtime/native-ban-expiry-01/working.dsk"
        ),
        "owned_working_image_inode": 222,
    }


class FakeRecorder:
    """Only consume the real generated post-probe actions; never open sockets."""

    selected_frames: typ.ClassVar[list[dict]] = []

    def __init__(self, plan: dict) -> None:
        """Start a recorder for one plan, with no sockets and no frames yet.

        Parameters
        ----------
        plan : dict
            The plan whose steps the recorder is asked to execute.
        """
        self.plan = plan
        self.started = time.monotonic_ns()
        self.started_at_utc = dt.datetime.now(dt.UTC).isoformat()
        self.sockets = {}
        self.variables = {}
        self.events: list[dict] = []
        self.frames: list[dict] = []
        self.remaining = iter(self.selected_frames)

    def execute(self, index: int, step: dict) -> None:
        """Record one step and, for a frame read, consume the next selected frame.

        Parameters
        ----------
        index : int
            The position of the step in the plan.
        step : dict
            The step, with its operation and optional connection and hex.
        """
        event = "send" if step["op"] == "send" else step["op"]
        self.events.append({
            "action": index,
            "connection": step.get("connection", "main"),
            "event": event,
            "elapsed_ns": 0,
            "hex": step.get("hex", ""),
        })
        if step["op"] == "read_frame":
            self.frames.append(next(self.remaining))

    def event(self, index: int, label: str, kind: str) -> None:
        """Record a labelled event that has no step of its own.

        Parameters
        ----------
        index : int
            The position of the action that the event belongs to.
        label : str
            The connection the event happened on.
        kind : str
            The kind of event.
        """
        self.events.append({
            "action": index,
            "connection": label,
            "event": kind,
            "elapsed_ns": 0,
            "hex": "",
        })

    def streams(self) -> dict:  # ruff: ignore[no-self-use]  # the recorder API is a method
        """Return the captured streams, which the fake never fills.

        Returns
        -------
        dict
            An empty mapping.
        """
        return {}
