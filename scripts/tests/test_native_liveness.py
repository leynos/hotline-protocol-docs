"""Replay the generated liveness schedule and reject each fault it can carry."""

import contextlib
import json
import re
import socket
import tempfile
import time
import typing as typ
from copy import deepcopy
from pathlib import Path

import native_liveness_cases as cases
import native_liveness_control as control
import pytest
from liveness_support import FakeConsumer, environment, message, roster_record
from native_plan import packet, payload
from protocol_capture import decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc


class LivenessTests:
    """Replay the generated liveness schedule and reject each fault it can carry."""

    @pytest.fixture(autouse=True)
    def cleanups(self) -> cabc.Iterator[None]:
        """Run the registered cleanups, last registered first, even on failure."""
        with contextlib.ExitStack() as stack:
            self.cleanup_stack = stack
            yield

    def plan(self) -> dict:
        """Build the source plan for the control-only environment.

        Returns
        -------
        dict
            The source plan that the schedule is generated from.
        """
        return cases.source_plan(environment())

    def exercise(self, **faults: bool) -> FakeConsumer:
        """Run the whole generated schedule against a fake consumer.

        Parameters
        ----------
        **faults : bool
            The fault controls that the fake consumer applies.

        Returns
        -------
        FakeConsumer
            The consumer after the schedule and its observation window.
        """
        plan = self.plan()
        fake = FakeConsumer(plan, **faults)
        self.cleanup_stack.callback(fake.dispose)
        fake.connect("o")
        fake.send("o", plan["observer_login_hex"])
        control.check_observer(fake)
        fake.operations.append({"label": "t0", "elapsed_ns": 0})
        for op in plan["schedule"]["operations"]:
            event_start, frame_start = len(fake.recorder.events), len(fake.frames)
            control.perform_operation(fake, op, time.monotonic() + 2)
            fake.operations.append({
                "label": op["label"],
                "event_range": [event_start, len(fake.recorder.events)],
                "frame_range": [frame_start, len(fake.frames)],
            })
        fake.window_status = {
            name: fake.terminals.get(name, "bounded_no_eof_through_window")
            for name in fake.buffers
        }
        fake.window_frame_count = len(fake.frames)
        return fake

    def report(self, fake: FakeConsumer) -> dict:
        """Build the offline report of an exercised consumer with fixed timing.

        Returns
        -------
        dict
            The report that ``control.verify_report`` checks.
        """
        plan = fake.plan
        events = deepcopy(fake.recorder.events)
        operations = deepcopy(fake.operations)
        t0 = 1_000_000_000
        for index, event in enumerate(events[: operations[1]["event_range"][0]]):
            event["elapsed_ns"] = index
        operations[0]["elapsed_ns"] = t0
        previous = t0
        for item, op in zip(
            operations[1:], plan["schedule"]["operations"], strict=True
        ):
            actual = max(
                previous + 1_000_000, t0 + op["at_seconds"] * 1_000_000_000 + 1_000_000
            )
            for event in events[slice(*item["event_range"])]:
                event["elapsed_ns"] = actual
            item["actual_elapsed_ns"] = actual
            previous = actual
        return {
            "status": "completed",
            "window_completed": True,
            "window_elapsed_ns": t0 + 135_002_000_000,
            "window_frame_count": fake.window_frame_count,
            "native_conformance": False,
            "plan_sha256": control.digest((json.dumps(plan, indent=2) + "\n").encode()),
            "cases_sha256": control.digest(Path(cases.__file__).read_bytes()),
            "source_sha256": control.digest(Path(control.__file__).read_bytes()),
            "oracle_sha256": control.ORACLE_SHA256,
            "events": events,
            "frames": deepcopy(fake.frames),
            "operations": operations,
            "streams": fake.recorder.streams(),
            "unparsed_hex": {name: raw.hex() for name, raw in fake.buffers.items()},
            "window_status": dict(fake.window_status),
            "terminals": {
                name: fake.terminals.get(name, "bounded_no_eof")
                for name in fake.buffers
            },
        }

    def test_generated_schedule_through_fake_consumer(self) -> None:
        """The generated schedule completes with its planned operations."""
        fake = self.exercise()
        control.check_complete(fake)
        plan = fake.plan
        assert len(fake.buffers) == 7, "the connection count differs"
        assert (
            len([
                op
                for op in plan["schedule"]["operations"]
                if op["label"].startswith("o500")
            ])
            == 26
        ), "the o500 operation count differs"
        assert [
            (op["label"], op["at_seconds"])
            for op in plan["schedule"]["operations"]
            if op["label"].startswith("b")
        ] == [
            ("b-admit-preonline", 0),
            ("b107-selected", 45),
            ("b121-partial-body", 50),
        ], "the B schedule differs"
        assert (
            len(
                bytes.fromhex(
                    next(
                        op["hex"]
                        for op in plan["schedule"]["operations"]
                        if op["label"] == "b121-partial-body"
                    )
                )
            )
            == 21
        ), "the partial B121 length differs"
        assert fake.window_status["b"] == "bounded_no_eof_through_window", (
            "the B window status differs"
        )

    def test_premature_b_online_blocks_partial121(self) -> None:
        """A B connection that comes online early blocks the partial B121."""
        with pytest.raises(ValueError, match="became online"):
            self.exercise(early_b=True)

    def test_wrong_b_reply_id_blocks_partial121(self) -> None:
        """A B login reply with the wrong identifier blocks the partial B121."""
        with pytest.raises(ValueError, match="valid107"):
            self.exercise(wrong_b_id=True)

    def test_b_nonzero_status_blocks_partial121(self) -> None:
        """A B login reply with a nonzero status blocks the partial B121."""
        with pytest.raises(ValueError, match="valid107"):
            self.exercise(b_error=True)

    def test_failed_login_must_remain_failure(self) -> None:
        """A failed F login must stay a failure in the completed check."""
        fake = self.exercise(f_success=True)
        with pytest.raises(ValueError, match="F failure107"):
            control.check_complete(fake)

    def test_observer_roster_must_exclude_b(self) -> None:
        """The observer roster must not list the B user."""
        fake = self.exercise()
        matching = control.matching(fake.frames, "o", 10)[0]
        matching["fields"].append({
            "id": 300,
            "hex": roster_record(2, cases.NAME_B).hex(),
        })
        with pytest.raises(ValueError, match="B appeared"):
            control.check_b_preonline(fake)

    def test_missing_window_classification_rejected(self) -> None:
        """A missing window classification is rejected."""
        fake = self.exercise()
        fake.window_status.pop("a")
        with pytest.raises(ValueError, match="Missing window observation"):
            control.check_complete(fake)

    def test_truncated_receive_bytes_retained(self) -> None:
        """Bytes received before a frame is complete stay in the buffer."""
        plan = self.plan()
        timeline = control.Timeline(plan, time.monotonic() + 1)
        client, peer = socket.socketpair()
        self.cleanup_stack.callback(client.close)
        self.cleanup_stack.callback(peer.close)
        timeline.recorder.sockets["a"] = client
        timeline.buffers["a"] = bytearray()
        prefix = bytes.fromhex(packet(0, 3, payload([]), reply=1))[:11]
        peer.sendall(prefix)
        timeline.poll(0.02)
        assert timeline.buffers["a"] == prefix, "the received prefix was not kept"
        assert timeline.frames == [], "a truncated frame was decoded"
        assert timeline.recorder.streams()["a"]["received_hex"] == prefix.hex(), (
            "the raw stream differs"
        )

    def test_source_hash_and_environment_drift(self) -> None:
        """Source identity, reserved values and plan hashes detect drift."""
        with pytest.raises(ValueError, match="identity incomplete"):
            cases.source_plan({"fixture_profile": "control-only"})
        with pytest.raises(ValueError, match="reserved"):
            cases.source_plan(environment(), 15841)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan"
            cases.write_plan(path, environment())
            assert control.prepared(path) == self.plan(), "the prepared plan differs"
            altered = json.loads((path / "plan.json").read_text())
            altered["schedule"]["operations"][0]["hex"] = "00"
            (path / "plan.json").write_text(json.dumps(altered))
            with pytest.raises(ValueError, match="hash differs"):
                control.prepared(path)

    def test_unmeasured_close_not_required(self) -> None:
        """An unmeasured close is not required for a complete run."""
        fake = self.exercise()
        control.check_complete(fake)
        assert not any(value == "eof" for value in fake.window_status.values()), (
            "an unmeasured close was recorded as eof"
        )

    def test_late_tail_kept_outside_window_inference(self) -> None:
        """A late tail frame stays outside the window inference."""
        fake = self.exercise()
        raw = message(0, 2, [])
        fake.frames.append({
            "connection": "b",
            "raw_hex": raw.hex(),
            **decode_frame(raw),
        })
        control.check_complete(fake)
        fake.window_frame_count = len(fake.frames)
        with pytest.raises(ValueError, match="Incomplete B121"):
            control.check_complete(fake)

    def test_offline_report_source_raw_and_delivery_faults(self) -> None:
        """Each altered offline report is rejected by its own check."""
        fake = self.exercise()
        source = self.report(fake)
        control.verify_report(fake.plan, source)
        for key, value, reason in (
            ("source_sha256", "0" * 64, "source identity"),
            ("plan_sha256", "0" * 64, "source identity"),
            ("window_status", {}, "finite socket status"),
        ):
            altered = deepcopy(source)
            altered[key] = value
            try:
                control.verify_report(fake.plan, altered)
            except ValueError as error:
                raised = str(error)
            else:
                pytest.fail(f"{key}: the altered report was accepted")
            assert re.search(reason, raised), f"{key}"
        altered = deepcopy(source)
        altered["streams"]["b"]["sent_hex"] += "00"
        with pytest.raises(ValueError, match="Raw streams"):
            control.verify_report(fake.plan, altered)
        altered = deepcopy(source)
        altered["frames"][0]["id"] = 999
        with pytest.raises(ValueError, match="Decoded frame"):
            control.verify_report(fake.plan, altered)

    def test_relabelled_real_eof_rejected(self) -> None:
        """A relabelled real EOF is rejected by both socket outcome checks."""
        fake = self.exercise(a_eof=True)
        source = self.report(fake)
        assert source["window_status"]["a"] == "eof", "the real EOF was not kept"
        control.verify_report(fake.plan, source)
        altered = deepcopy(source)
        altered["window_status"]["a"] = "bounded_no_eof_through_window"
        with pytest.raises(ValueError, match="Window socket outcome"):
            control.verify_report(fake.plan, altered)
        altered = deepcopy(source)
        altered["terminals"]["a"] = "bounded_no_eof"
        with pytest.raises(ValueError, match="Final socket outcome"):
            control.verify_report(fake.plan, altered)

    def test_moved_operation_and_window_time_rejected(self) -> None:
        """A moved operation time and a moved window time are both rejected."""
        fake = self.exercise()
        source = self.report(fake)
        control.verify_report(fake.plan, source)
        altered = deepcopy(source)
        altered["operations"][20]["actual_elapsed_ns"] += 10_000_000_000
        with pytest.raises(ValueError, match="Scheduled time"):
            control.verify_report(fake.plan, altered)
        altered = deepcopy(source)
        altered["window_elapsed_ns"] = (
            altered["operations"][0]["elapsed_ns"] + 125_000_000_000
        )
        with pytest.raises(ValueError, match="window timing"):
            control.verify_report(fake.plan, altered)
