"""Offline fake-wire and report fault controls for one native 304 rate case."""

import contextlib
import copy
import re
import socket
import threading
import time
import typing as typ
from unittest import mock

import native_rate304_cases as cases
import native_rate304_control as control
import native_rate304_control_classify as classifying
import pytest
from native_plan import packet, payload
from protocol_capture import decode_frame
from rate304_faults import classify_faults, extra_notifications, report_faults
from rate304_support import ENV, fake_report, frame, roster, update
from rate304_wire import PeerScript, build_full_report, serve_phase

if typ.TYPE_CHECKING:
    import collections.abc as cabc

DIGEST_CODES = {6000: 348, 6001: 200, 6002: 206, 6004: 303}


@pytest.fixture
def cleanups() -> cabc.Iterator[contextlib.ExitStack]:
    """Provide a stack of cleanups that run in reverse order after the test.

    Yields
    ------
    contextlib.ExitStack
        The stack to which a test registers its cleanups.
    """
    with contextlib.ExitStack() as stack:
        yield stack


class Rate304Tests:
    """Reject each fake-wire and report fault of one native 304 rate case."""

    @pytest.fixture(autouse=True)
    def setUp(self) -> cabc.Iterator[None]:
        """Build the plan and report, and patch the field digest for the test.

        Yields
        ------
        None
            Control returns to the test while the digest patch is active.
        """
        self.plan = cases.source_plan(ENV)
        self.report = fake_report(self.plan)
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    classifying,
                    "field_digest",
                    side_effect=lambda f: control.BASELINE_FIELDS[
                        DIGEST_CODES[f["id"]]
                    ],
                )
            )
            yield

    def test_producer_exact_104_only_and_ids(self) -> None:
        """Check the producer's frame and reject the two unprepared plans."""
        raw = bytes.fromhex(cases.update(1000, 2))
        decoded = decode_frame(raw)
        assert decoded["type"] == 304, "the producer type differs"
        assert decoded["id"] == 1000, "the producer identifier differs"
        assert decoded["fields"] == [{"id": 104, "hex": "0002"}], "the fields differ"
        assert self.plan["request_ids"]["paced_304"] == list(range(1000, 1027)), (
            "the paced identifiers differ"
        )
        with pytest.raises(
            ValueError,
            match=re.escape("Only reserved control-only port15880 is prepared"),
        ):
            cases.source_plan(ENV, 15881)
        with pytest.raises(
            ValueError,
            match=re.escape("Only reserved control-only port15880 is prepared"),
        ):
            cases.source_plan({**ENV, "fixture_profile": "full-a7"})

    def test_generated_schedule_exact(self) -> None:
        """Check the generated schedule and reject a cadence of sixteen."""
        assert self.plan["schedule"]["schema_version"] == 2, "schema version differs"
        assert "26 ordered 304+500" in self.plan["schedule"]["phase_mode"], (
            "phase mode differs"
        )
        actions = control.expected_actions(self.plan, 14, 1)
        assert actions[0] == (
            "observer-login",
            "observer",
            self.plan["logins"]["observer"],
        ), "the first action differs"
        assert actions[-1][0] == "observer-303", "the last action differs"
        assert len(actions) == 4 + 52 + 14 + 4 + 52 + 2 + 5, "action count differs"
        with pytest.raises(
            ValueError, match=re.escape("Observer idle cadence differs")
        ):
            control.expected_actions(self.plan, 16, 1)

    def test_observer_303_uses_dynamic_self_uid(self) -> None:
        """Check the 303 control carries the observer's own UID."""
        raw = cases.observer_control(303, 6004, 7)
        decoded = decode_frame(bytes.fromhex(raw))
        assert decoded["type"] == 303, "the control type differs"
        assert decoded["fields"] == [{"id": 103, "hex": "0007"}], "the UID differs"
        assert control.expected_actions(self.plan, 14, 7)[-1][2] == raw, "303 differs"
        for uid in (None, 0, -1, 65536):
            with pytest.raises(
                ValueError,
                match=re.escape("303 requires resolved nonzero observer UID"),
            ):
                cases.observer_control(303, 6004, uid)
        with pytest.raises(
            ValueError,
            match=re.escape("Only 303 accepts a dynamic observer UID"),
        ):
            cases.observer_control(300, 10, 7)

    def test_303_report_target_must_match_independent_roster_uid(self) -> None:
        """Check that a report accepts its own UID and rejects another target."""
        valid = self.full_fake_report(observer_uid=7)
        control.verify_report(self.plan, valid)
        assert valid["identities"]["observer_uid"] == 7, "the observer UID differs"
        with pytest.raises(
            ValueError, match=re.escape("As-run request action schedule differs")
        ):
            control.verify_report(
                self.plan, self.full_fake_report(observer_uid=7, target_uid=1)
            )

    def test_post_ban_roster_uid_drift_rejected_with_consistent_raw(self) -> None:
        """Reject a post-ban roster UID drift even when the raw bytes agree."""
        report = self.full_fake_report(observer_uid=7)
        old = next(
            f
            for f in report["frames"]
            if f["connection"] == "observer" and f["id"] == 6003
        )
        changed = frame(
            "observer",
            0,
            6003,
            [(300, roster(8, 1, cases.OBS_NAME))],
            reply=1,
            when=old["arrival_elapsed_ns"],
        )
        report["frames"][report["frames"].index(old)] = changed
        event = next(
            e
            for e in report["events"]
            if e["event"] == "receive" and e["hex"] == old["raw_hex"]
        )
        event["hex"] = changed["raw_hex"]
        received = report["streams"]["observer"]["received_hex"]
        assert received.count(old["raw_hex"]) == 1, "the old frame is not unique"
        report["streams"]["observer"]["received_hex"] = received.replace(
            old["raw_hex"], changed["raw_hex"], 1
        )
        with pytest.raises(ValueError, match="post-ban roster UID"):
            control.verify_report(self.plan, report)

    def test_fake_wire_acceptance_and_semantic_faults(self) -> None:
        """Accept the fake wire and reject each semantic fault it can carry."""
        control.classify(self.plan, self.report)
        terminal = copy.deepcopy(self.report)
        terminal["frames"].extend([
            frame("burst", 104, 7, [(101, b"observed terminal notice")], when=1370),
            frame("observer", 302, 0, [(103, b"\0\4")], when=1550),
        ])
        control.classify(self.plan, terminal)
        for mutate, message in classify_faults():
            changed = copy.deepcopy(self.report)
            mutate(changed)
            with pytest.raises(ValueError, match=re.escape(message)):
                control.classify(self.plan, changed)

    def test_real_socketpair_reassembles_and_preserves_truncated_tail(
        self, cleanups: contextlib.ExitStack
    ) -> None:
        """Reassemble a frame from split reads and keep a truncated tail."""
        wire = control.Wire(self.plan, time.monotonic() + 2)
        source, peer = socket.socketpair()
        cleanups.callback(source.close)
        cleanups.callback(peer.close)
        wire.recorder.sockets["observer"] = source
        wire.buffers["observer"] = bytearray()
        raw = bytes.fromhex(packet(0, 77, payload([(101, b"ok")]), reply=1))
        peer.sendall(raw[:11])
        wire.poll(0.02)
        assert not wire.frames, "a partial frame was delivered"
        peer.sendall(raw[11:] + b"\xaa\xbb")
        wire.poll(0.02)
        assert wire.frames[0]["raw_hex"] == raw.hex(), "the reassembled frame differs"
        assert wire.buffers["observer"] == b"\xaa\xbb", "the tail was not kept"
        peer.shutdown(socket.SHUT_WR)
        wire.poll(0.02)
        assert wire.terminals["observer"] == "eof", "the terminal differs"
        assert wire.buffers["observer"] == b"\xaa\xbb", "the tail changed at close"

    def _check_outcome(
        self,
        wire: control.Wire,
        script: PeerScript,
        seconds: float,
        expected: str | None,
    ) -> None:
        """Check the outcome of one phase against the scenario it ran."""
        failing = script.missing or script.duplicate or script.foreign
        if failing or seconds < script.delay:
            assert expected is not None, "a failing phase names its message"
            with pytest.raises(ValueError, match=re.escape(expected)):
                control.run_update_phase(wire, "paced", 2, seconds)
        else:
            receipt = control.run_update_phase(wire, "paced", 2, seconds)
            assert receipt["mode"] == self.plan["schedule"]["phase_mode"], (
                "phase mode differs"
            )
            assert "observer" not in wire.terminals, "an observer terminal appeared"
            assert len(wire.match("paced", 0, None, 1)) == 26, "paced replies differ"
        assert wire.recorder.streams()["paced"]["sent_hex"], "no paced bytes sent"
        assert (
            wire.recorder.streams()["paced"]["received_hex"] or seconds < script.delay
        ), "no paced bytes received"
        if failing:
            assert wire.recorder.streams()["observer"]["received_hex"], (
                "no observer bytes received"
            )
        if script.missing:
            assert control.validated_phase_progress(wire, "paced", 2) == 25, (
                "missing progress differs"
            )
        if script.duplicate:
            assert control.validated_phase_progress(wire, "paced", 2) == 5, (
                "duplicate progress differs"
            )

    def rehearse_phase(
        self,
        script: PeerScript,
        *,
        seconds: float = 2,
        expected: str | None = None,
    ) -> None:
        """Run actual 52 request sends and two response sockets with delayed peers."""
        wire = control.Wire(self.plan, time.monotonic() + 4)
        subject, subject_peer = socket.socketpair()
        observer, observer_peer = socket.socketpair()
        for name, sock in (("paced", subject), ("observer", observer)):
            wire.recorder.sockets[name] = sock
            wire.buffers[name] = bytearray()
        for sock in (subject_peer, observer_peer):
            sock.settimeout(3)
        errors: list[Exception] = []
        worker = threading.Thread(
            target=serve_phase,
            args=(subject_peer, observer_peer, script, errors),
            daemon=True,
        )
        worker.start()
        try:
            self._check_outcome(wire, script, seconds, expected)
        finally:
            worker.join(timeout=3)
            for sock in (subject, observer, subject_peer, observer_peer):
                sock.close()
        assert not worker.is_alive(), "the peer thread is still running"
        assert not errors, "the peer reported an error"
        assert wire.recorder.sockets["observer"].fileno() == -1, "observer still open"

    def test_real_delayed_peer_pipeline_and_faults(self) -> None:
        """Run the delayed-peer phases and their failing variants."""
        self.rehearse_phase(PeerScript(0.75))
        self.rehearse_phase(PeerScript(0.75, observer_first=True))
        self.rehearse_phase(
            PeerScript(0.75, missing=True),
            seconds=1.1,
            expected="Missing paced 26 subject/observer301 and500 ACKs",
        )
        self.rehearse_phase(
            PeerScript(0.75, duplicate=True),
            expected="observer duplicate 301 icon7",
        )
        self.rehearse_phase(
            PeerScript(0.75, foreign=True),
            expected="paced foreign 301 during phase",
        )
        self.rehearse_phase(
            PeerScript(0.75),
            seconds=0.6,
            expected="Missing paced 26 subject/observer301 and500 ACKs",
        )

    def test_old_pair_boundary_fails_before_delayed_response(self) -> None:
        """Fail the old pair bound before a delayed response, then accept it."""
        wire = control.Wire(self.plan, time.monotonic() + 2)
        subject, peer = socket.socketpair()
        wire.recorder.sockets["paced"] = subject
        wire.buffers["paced"] = bytearray()

        def delayed_reply() -> None:
            """Send the late presence notice and acknowledgement."""
            time.sleep(0.75)
            peer.sendall(bytes.fromhex(packet(301, 0, payload(update(2, 2)))))
            peer.sendall(bytes.fromhex(packet(0, 2000, reply=1)))

        try:
            wire.send("paced", cases.update(1000, 2), "paced-304-00")
            wire.send("paced", cases.barrier(2000), "paced-500-00")
            worker = threading.Thread(target=delayed_reply)
            worker.start()
            with pytest.raises(ValueError, match=r"Missing old 0.55s pair"):
                wire.wait_for(
                    lambda: bool(wire.match("paced", 0, 2000, 1)),
                    0.55,
                    "old 0.55s pair",
                )
            assert "paced" in wire.recorder.sockets, "the paced socket was dropped"
            wire.wait_for(lambda: bool(wire.match("paced", 0, 2000, 1)), 1, "late ACK")
            worker.join(timeout=1)
            assert not worker.is_alive(), "the delayed peer is still running"
        finally:
            subject.close()
            peer.close()

    def full_fake_report(
        self,
        *,
        observer_after_barrier: bool = False,
        observer_uid: int = 1,
        target_uid: int | None = None,
    ) -> dict[str, typ.Any]:
        """Build the completed fake report of this test's plan.

        Returns
        -------
        dict[str, typ.Any]
            The completed report of the run.
        """
        return build_full_report(
            self.plan,
            observer_after_barrier=observer_after_barrier,
            observer_uid=observer_uid,
            target_uid=target_uid,
        )

    def test_full_fake_wire_report_and_faults(self) -> None:
        """Accept the completed report and reject each report fault."""
        report = self.full_fake_report()
        control.verify_report(self.plan, report)
        control.verify_report(
            self.plan, self.full_fake_report(observer_after_barrier=True)
        )
        for mutate, message in report_faults():
            changed = copy.deepcopy(report)
            mutate(changed)
            with pytest.raises(ValueError, match=re.escape(message)):
                control.verify_report(self.plan, changed)

    def test_extra_notification_rejected_with_consistent_raw_stream(self) -> None:
        """Reject each extra notification whose raw stream is consistent."""
        original = self.full_fake_report()
        for name, kind, values, message in extra_notifications():
            report = copy.deepcopy(original)
            when = report["events"][-1]["elapsed_ns"] + 1
            extra = frame(name, kind, 99, values, when=when)
            report["frames"].append(extra)
            report["events"].append({
                "connection": name,
                "event": "receive",
                "hex": extra["raw_hex"],
                "elapsed_ns": when,
            })
            report["streams"][name]["received_hex"] += extra["raw_hex"]
            if message is None:
                control.verify_report(self.plan, report)
            else:
                with pytest.raises(ValueError, match=re.escape(message)):
                    control.verify_report(self.plan, report)
