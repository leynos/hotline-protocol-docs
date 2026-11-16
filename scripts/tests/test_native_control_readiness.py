"""Offline controls for the isolated ban request gate."""

import json
import os
import sys
import typing as typ
from unittest import mock

import native_ban_control_cases as cases
import pytest
from native_control_readiness import execute_ban_step, main, plan_gate, target_gate
from native_plan import packet, payload

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

    from protocol_capture import Recorder

type Frame = dict[str, typ.Any]

TARGET_UID = b"\0\2"
OTHER_UID = b"\0\3"
SHORT_PLAN_STEPS = 18
FIXTURE_PORT = 15750
EMULATOR_PID = 42
PREPARED_PLANS = 5


def gate_module() -> types.ModuleType:
    """Find the module that holds the gates that ``target_gate`` calls.

    Returns
    -------
    types.ModuleType
        The module that defines ``target_gate``, so that a patch of its
        ``login_gate`` reaches the call, whether the gates are one file or many.
    """
    return sys.modules[target_gate.__module__]


def frame(
    kind: int, connection: str, values: list[tuple[int, bytes]], **extra: int
) -> Frame:
    """Build a decoded frame.

    Parameters
    ----------
    kind : int
        The transaction type.
    connection : str
        The connection that received the frame.
    values : list[tuple[int, bytes]]
        The fields of the frame.
    **extra : int
        ``is_reply`` or ``id``, replacing the default of zero.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return {
        "type": kind,
        "connection": connection,
        "is_reply": 0,
        "id": 0,
        "error": 0,
        "fields": [{"id": field, "hex": value.hex()} for field, value in values],
        **extra,
    }


def row(uid: int, name: bytes) -> bytes:
    """Encode one roster row.

    Returns
    -------
    bytes
        The user ID, the icon and status words, and the length-prefixed name.
    """
    return uid.to_bytes(2, "big") + b"\0\1\0\0" + len(name).to_bytes(2, "big") + name


def witnesses(
    uid: int = 2, access: bytes = bytes(8), name: bytes = cases.NAME
) -> list[Frame]:
    """Build the frames of an admin and a target session before the ban.

    Returns
    -------
    list[dict[str, typing.Any]]
        The admin's login, the target's login, the join and the roster reply.
    """
    main_frames = [frame(0, "main", []), frame(354, "main", []), frame(109, "main", [])]
    target = [
        frame(0, "target", [], is_reply=1),
        frame(354, "target", [(110, access)]),
        frame(109, "target", []),
    ]
    join = frame(301, "main", [(103, uid.to_bytes(2, "big")), (102, name)])
    roster = frame(
        0,
        "main",
        [(300, row(1, b"framing-fixture")), (300, row(2, cases.NAME))],
        is_reply=1,
        id=32,
    )
    return [*main_frames, *target, join, roster]


class FakeRecorder:
    """A recorder that keeps the frames and the steps that it was given."""

    def __init__(self, frames: list[Frame], uid: bytes = TARGET_UID) -> None:
        """Hold the frames and the saved target UID.

        Parameters
        ----------
        frames : list[dict[str, typing.Any]]
            The frames seen so far.
        uid : bytes
            The target UID saved by the plan.
        """
        self.frames = frames
        self.variables = {"target_uid": uid}
        self.sent: list[Frame] = []

    def execute(self, action: int, step: Frame) -> None:
        """Record the step that would be sent."""
        del action
        self.sent.append(step)


class NativeControlReadinessTests:
    """Offline controls for the isolated ban request gate."""

    ban_step: Frame

    @pytest.fixture(autouse=True)
    def prepared_step(self) -> None:
        """Build the 110 request that the gate guards."""
        self.ban_step = {
            "op": "send",
            "hex": packet(110, 33, payload([(103, TARGET_UID), (113, TARGET_UID)])),
        }

    def test_exact_short_plan_has_no_transfer_or_reason(self) -> None:
        """The plans send no transfer request and no reason field."""
        plans = cases.plans()
        assert len(plans["readiness"]) == SHORT_PLAN_STEPS, "readiness length"
        sent = [
            s["hex"] for steps in plans.values() for s in steps if s["op"] == "send"
        ]
        assert not any(s.startswith(("000000ca", "48545846")) for s in sent), (
            "expected no transfer request"
        )
        bans = [s for s in sent if s.startswith("0000006e")]
        assert len(bans) == 1, "expected one ban request"
        assert "007100020002" in bans[0], "expected the option"
        assert "006500" not in bans[0], "expected no reason field"

    def test_valid_current_uid_and_zero_access_allow_one_110(self) -> None:
        """A matching UID and zero access let the request through."""
        recorder = FakeRecorder(witnesses())
        with mock.patch.object(gate_module(), "login_gate"):
            assert target_gate(recorder.frames) == TARGET_UID, "expected the UID"
            execute_ban_step(typ.cast("Recorder", recorder), 17, self.ban_step)
        assert recorder.sent == [self.ban_step], "expected the one request"

    def test_wrong_current_uid_sends_no_110(self) -> None:
        """A roster that lacks the saved UID stops the request."""
        recorder = FakeRecorder(witnesses(uid=3), OTHER_UID)
        with (
            mock.patch.object(gate_module(), "login_gate"),
            pytest.raises(ValueError, match="roster target"),
        ):
            execute_ban_step(typ.cast("Recorder", recorder), 17, self.ban_step)
        assert not recorder.sent, "expected no request"

    def test_nonzero_access_sends_no_110(self) -> None:
        """A target with privileges stops the request."""
        recorder = FakeRecorder(witnesses(access=b"\x80" + bytes(7)))
        with (
            mock.patch.object(gate_module(), "login_gate"),
            pytest.raises(ValueError, match="access"),
        ):
            execute_ban_step(typ.cast("Recorder", recorder), 17, self.ban_step)
        assert not recorder.sent, "expected no request"

    def test_mismatched_saved_uid_sends_no_110(self) -> None:
        """A saved UID that is not the announced one stops the request."""
        recorder = FakeRecorder(witnesses(), OTHER_UID)
        with (
            mock.patch.object(gate_module(), "login_gate"),
            pytest.raises(ValueError, match="Saved target UID"),
        ):
            execute_ban_step(typ.cast("Recorder", recorder), 17, self.ban_step)
        assert not recorder.sent, "expected no request"

    def test_rehashed_plan_source_is_required_before_contact(
        self, tmp_path: Path
    ) -> None:
        """A changed plan file is refused even when its list is unchanged."""
        directory = tmp_path / "plans"
        hashes = cases.write_plans(
            directory,
            {"source_a7_sha256": cases.A7_SHA, "emulator_pid": EMULATOR_PID},
            FIXTURE_PORT,
        )
        (directory / "source-hashes.json").write_text(json.dumps(hashes))
        assert len(hashes) == PREPARED_PLANS, "expected five plans"
        plan_gate(directory, EMULATOR_PID)
        path = directory / "ban.json"
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(ValueError, match="source plan changed"):
            plan_gate(directory, EMULATOR_PID)

    def test_live_cli_rejects_unprivileged_controller_before_receipt_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A live run as an ordinary user is refused before any file is read."""
        argv = [
            "program",
            "run",
            "--plans",
            "/missing-plans",
            "--binary",
            "/missing-binary",
            "--capture-ready",
            "/missing-receipt",
            "--output",
            "/missing-output",
        ]
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        with pytest.raises(PermissionError, match="requires root"):
            main()
