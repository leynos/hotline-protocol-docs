"""Offline controls for the configured-address ban fixture plan and capture."""

import copy
import json
import socket
import sys
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import capture_identity
import native_configured_ban_cases as cases
import native_configured_ban_control as control
import native_configured_ban_control_gates as gates
import protocol_capture
import pytest
from native_plan import packet, payload
from protocol_capture import (
    Recorder,
    decode_frame,
    digest,
    validate_plan,
    verify_capture,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc


class FakeRecorder(Recorder):
    """Recorder that answers each scripted step with fixed fake frames."""

    def __init__(self, plan: dict) -> None:
        """Start the fake recorder with its fixed start time and target UID."""
        super().__init__(plan)
        self.started_at_utc = "2026-11-14T04:00:00+00:00"
        self.variables = {"target_uid": b"\0\5"}

    def execute(self, action: int, step: dict) -> None:
        """Record the scripted effect of one step of the plan."""
        name = step["connection"]
        op = step["op"]
        match op:
            case "send":
                self.event(action, name, "send", bytes.fromhex(step["hex"]))
            case "read":
                self.event(action, name, "receive", b"TRTP\0\0\0\0")
            case "read_frame":
                kind, identifier, reply = {
                    4: (0, 1, 1),
                    5: (354, 0, 0),
                    6: (109, 0, 0),
                    11: (0, 1, 1),
                    12: (354, 0, 0),
                    13: (109, 0, 0),
                    14: (301, 0, 0),
                    16: (0, 32, 1),
                    17: (104, 0, 0),
                    18: (104, 0, 0),
                }[action]
                values = [(101, control.base.BAN_TEXT)] if kind == 104 else []
                if kind == 301:
                    values = [(103, b"\0\5"), (102, cases.NAME)]
                raw = bytes.fromhex(
                    packet(kind, identifier, payload(values), reply=reply)
                )
                self.event(action, name, "receive", raw)
                self.frames.append({
                    "action": action,
                    "connection": name,
                    **decode_frame(raw),
                })
            case _:
                self.event(action, name, "eof" if op == "read_eof" else op)


class ConfiguredBanPreparationTest:
    """Check the configured-address ban plan, its gates and its report tail."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def test_identity_gate_requires_current_uid_name_and_distinct_roster(self) -> None:
        """Check that the identity gate needs the current UID, name and roster."""

        def frame(  # pylint: disable=too-many-arguments  # the frame shape has six fields
            connection: str,
            kind: int,
            identifier: int = 0,
            *,
            reply: int = 0,
            error: int = 0,
            values: cabc.Sequence[tuple[int, bytes]] = (),
        ) -> dict[str, typ.Any]:
            """Build one recorded frame with its header and fields.

            Returns
            -------
            dict[str, typing.Any]
                The frame as the identity gate reads it.
            """
            return {
                "connection": connection,
                "type": kind,
                "id": identifier,
                "is_reply": reply,
                "error": error,
                "fields": [{"id": key, "hex": value.hex()} for key, value in values],
            }

        frames = [frame("main", 0), frame("main", 354), frame("main", 109)]
        frames += [
            frame("target", 0, 1, reply=1),
            frame("target", 354, values=[(110, cases.ZERO)]),
            frame("target", 109),
            frame("main", 301, values=[(103, b"\0\5"), (102, cases.NAME)]),
            frame("main", 0, 32, reply=1),
        ]
        rows = [
            {"uid": 5, "name_hex": cases.NAME.hex()},
            {"uid": 4, "name_hex": b"framing-fixture".hex()},
        ]
        with (
            mock.patch.object(control.base, "login_gate"),
            mock.patch.object(gates, "roster", return_value=rows),
        ):
            assert control.identity_gate(frames) == b"\0\5", "the UID gate differs"
            wrong_name = copy.deepcopy(frames)
            wrong_name[6]["fields"][1]["hex"] = b"intruder".hex()
            with pytest.raises(ValueError, match="UID/name differs"):
                control.identity_gate(wrong_name)
            rows[1]["uid"] = 5
            with pytest.raises(ValueError, match="roster identities differ"):
                control.identity_gate(frames)

    def test_plan_has_complete_tail_and_no_110(self) -> None:
        """Check the phase lengths, the held tail and that no 110 request is sent."""
        steps = cases.plans()
        expected_counts = {"readiness": 18, "guard": 10, "seed": 12, "held-apply": 23}
        assert {name: len(value) for name, value in steps.items()} == expected_counts, (
            "the phase step counts differ"
        )
        expected_tail = [
            ("read_frame", "main"),
            ("read_frame", "target"),
            ("read_eof", "main"),
            ("read_eof", "target"),
            ("close", "main"),
            ("close", "target"),
        ]
        assert [
            (step["op"], step.get("connection")) for step in steps["held-apply"][-6:]
        ] == expected_tail, "the held tail differs"
        assert all("expect_hex" not in step for step in steps["held-apply"][-4:-2]), (
            "an expected hex value is in the held tail"
        )
        for phase_name, phase in steps.items():
            for step in phase:
                if step["op"] == "send" and "{" not in step["hex"]:
                    assert bytes.fromhex(step["hex"])[2:4] != b"\0\x6e", (
                        f"{phase_name}: a 110 request is planned"
                    )

    def test_plans_validate_and_reject_primary_port(self) -> None:
        """Check that the plans validate and that the primary port is refused."""
        with tempfile.TemporaryDirectory() as directory:
            with pytest.raises(ValueError, match="owned lab port"):
                cases.write_plans(
                    Path(directory) / "bad", {"source_a7_sha256": cases.A7_SHA}, 15500
                )
            path = Path(directory) / "good"
            hashes = cases.write_plans(
                path, {"source_a7_sha256": cases.A7_SHA, "emulator_pid": 123}, 15770
            )
            assert set(hashes) == control.EXPECTED_PLANS, "the plan names differ"
            for name, source_hash in hashes.items():
                source = (path / f"{name}.json").read_bytes()
                assert digest(source) == source_hash, f"{name}: the digest differs"
                validate_plan(json.loads(source))

    def test_pre_save_activity_fails_closed(self) -> None:
        """Check that activity before the reviewed Save fails closed."""
        sender, receiver = socket.socketpair()
        try:
            fake = FakeRecorder({})
            fake.sockets = {"main": receiver}
            sender.sendall(b"unexpected notice")
            with (
                tempfile.TemporaryDirectory() as directory,
                pytest.raises(ValueError, match="before reviewed Save"),
            ):
                control.wait_for_reviewed_save(
                    typ.cast("Recorder", fake), Path(directory) / "trigger", 10**20
                )
        finally:
            sender.close()
            receiver.close()

    def test_report_producer_and_consumer_include_eof_tail(self) -> None:
        """Check the report round trip, the EOF tail and the main notice header."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = {
                "schema_version": 1,
                "profile": "native-mac-oracle",
                "operator": "offline fake",
                "oracle_sha256": digest(b"binary"),
                "gap_ids": ["GAP-044"],
                "endpoints": {"control": {"host": "127.0.0.1", "port": 15770}},
                "steps": cases.plans()["held-apply"],
            }
            source = (json.dumps(plan) + "\n").encode()
            (root / "source.json").write_bytes(source)
            (root / "binary").write_bytes(b"binary")
            (root / "capture.json").write_text("{}")
            with (
                mock.patch.object(control, "ORACLE_SHA256", digest(b"binary")),
                mock.patch.object(protocol_capture, "ORACLE_SHA256", digest(b"binary")),
                mock.patch.object(control, "Recorder", FakeRecorder),
                mock.patch.object(control, "identity_gate", return_value=b"\0\5"),
                mock.patch.object(gates, "identity_gate", return_value=b"\0\5"),
                mock.patch.object(control.base, "capture_gate"),
                mock.patch.object(control, "wait_for_reviewed_save"),
            ):
                report = control.run_held(
                    control.HeldInputs(
                        root / "source.json",
                        root / "binary",
                        root / "out",
                        root / "trigger",
                        root / "capture.json",
                    )
                )
                restored = json.loads((root / "out/report.json").read_text())
                assert restored == report, "the saved report differs"
                assert verify_capture(root / "out") == restored, (
                    "the verified capture differs"
                )
                assert report["completed_actions"] == 23, "the action count differs"
                record = report["driver_identity"]
                assert report["driver_sha256"] == record["digest"], (
                    "the driver hash is not the digest of the module set"
                )
                assert [item["path"] for item in record["files"]] == [
                    f"scripts/{name}" for name in control.CAPTURE_MODULES
                ], "the identity lists other modules than the declared set"
                assert capture_identity.check(record, control.CAPTURE_MODULES), (
                    "the identity does not describe the live modules"
                )
                control.outcome(restored, plan)
                shortened = copy.deepcopy(restored)
                shortened["completed_actions"] = 21
                with pytest.raises(ValueError, match="tail incomplete"):
                    control.outcome(shortened, plan)
                no_eof = copy.deepcopy(restored)
                no_eof["events"] = [
                    e for e in no_eof["events"] if e["connection"] != "target"
                ]
                with pytest.raises(ValueError, match="target close missing"):
                    control.outcome(no_eof, plan)
                for header in ("flags", "is_reply", "error"):
                    wrong_header = copy.deepcopy(restored)
                    next(f for f in wrong_header["frames"] if f["type"] == 104)[
                        header
                    ] = 1
                    with pytest.raises(
                        ValueError, match="main configured-ban notice differs"
                    ):
                        control.outcome(wrong_header, plan)


class ConfiguredBanCommandTest:
    """Check the command line: the plans it writes and the order it runs the cases."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def test_prepare_writes_the_plans_and_their_hashes(self) -> None:
        """The prepare command writes each plan and the hash of each plan."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"source_a7_sha256": cases.A7_SHA, "emulator_pid": 123}
            (root / "runtime.json").write_text(json.dumps(record))
            argv = [
                "native_configured_ban_control.py",
                "prepare",
                "--runtime-record",
                str(root / "runtime.json"),
                "--port",
                "15770",
                "--output",
                str(root / "plans"),
            ]
            with mock.patch.object(sys, "argv", argv):
                control.main()
            written = json.loads((root / "plans/source-hashes.json").read_text())
            assert set(written) == control.EXPECTED_PLANS, "the plan names differ"
            for name, source_hash in written.items():
                source = (root / "plans" / f"{name}.json").read_bytes()
                assert digest(source) == source_hash, f"{name}: the digest differs"

    def test_execute_runs_each_case_after_a_fresh_capture_gate(self) -> None:
        """The execute command gates the capture before each case and the tail last."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ready.json").write_text(json.dumps({"emulator_pid": 77}))
            argv = [
                "native_configured_ban_control.py",
                "execute",
                "--plans",
                str(root / "plans"),
                "--binary",
                str(root / "binary"),
                "--capture-ready",
                str(root / "ready.json"),
                "--output",
                str(root / "out"),
                "--save-trigger",
                str(root / "trigger"),
            ]
            (root / "plans").mkdir()
            (root / "plans/held-apply.json").write_text(json.dumps({"steps": []}))
            order: list[str] = []

            def note(label: str) -> cabc.Callable[..., dict]:
                """Build a fake that records its call and returns a marked report.

                Returns
                -------
                collections.abc.Callable[..., dict]
                    The fake.
                """

                def fake(*args: object, **_kwargs: object) -> dict:
                    """Record the call.

                    Returns
                    -------
                    dict
                        A report that names the label.
                    """
                    order.append(label)
                    return {"label": label, "args": args}

                return fake

            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(control.base, "require_controller_uid"),
                mock.patch.object(
                    control.base,
                    "capture_gate",
                    side_effect=lambda _receipt: order.append("gate"),
                ),
                mock.patch.object(control.base, "readiness", note("readiness")),
                mock.patch.object(control, "plan_gate", note("plans")),
                mock.patch.object(control, "account_gate", note("account")),
                mock.patch.object(control, "run_plan", note("run")),
                mock.patch.object(control, "run_held", note("held")),
                mock.patch.object(control, "outcome", note("outcome")),
            ):
                control.main()
            cases_run = ("readiness", "account", "account")
            expected = ["gate", "plans"]
            for label in cases_run:
                expected += ["gate", "run", label]
            expected += ["held", "outcome"]
            assert order == expected, (
                "the cases ran in another order or without their capture gates"
            )
            assert (root / "out").is_dir(), "the output directory was not made"
