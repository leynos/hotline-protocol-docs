"""Offline socket and frame faults for the generated roster-overlap plan."""

import datetime as dt
import json
import socket
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from unittest import mock

import native_roster_overlap_cases as cases
import native_roster_overlap_control as control
import pytest
from native_plan import packet
from protocol_capture import Recorder
from roster_overlap_support import (
    FakeNativeRecorder,
    decoded,
    environment,
    notice,
    overlap_messages,
    record,
    reply,
    roster_reply,
)
from verify_native_auth import ADMIN

OVERLAP_ARRIVALS = {
    ("a", 1, 0, 11),
    ("a", 1, 0, 12),
    ("b", 1, 0, 12),
    ("a", 0, 301, 0),
    ("b", 0, 301, 0),
}


class RosterOverlapTests:
    """Overlap arrival orders, torn identities and the setup consumer."""

    def fixture(
        self, request: pytest.FixtureRequest
    ) -> tuple[Recorder, socket.socket, socket.socket]:
        """Build a recorder over two socket pairs and close every socket afterwards.

        Returns
        -------
        tuple[Recorder, socket.socket, socket.socket]
            The recorder and the two server ends of the socket pairs.
        """
        plan = cases.source_plan(environment())
        recorder = Recorder(plan)
        client_a, server_a = socket.socketpair()
        client_b, server_b = socket.socketpair()
        recorder.sockets = {"a": client_a, "b": client_b}
        for sock in (client_a, server_a, client_b, server_b):
            request.addfinalizer(sock.close)
        return recorder, server_a, server_b

    def test_generated_plan_limits_requests_and_prepared_hash(self) -> None:
        """Check the request count, teardown order and the prepared plan hash."""
        plan = cases.source_plan(environment())
        assert plan["endpoints"]["control"]["port"] == 15820, "control port"
        assert sum(s["op"] == "connect" for s in plan["steps"]) == 2, "connect count"
        sends = [
            bytes.fromhex(s["hex"])[2:4]
            for s in plan["steps"]
            if s["op"] == "send" and not s["hex"].startswith("54525450")
        ]
        assert set(sends) == {b"\0k", b"\x01,"}, "request kinds"
        assert [s["op"] for s in plan["steps"][-7:]] == [
            "shutdown_write",
            "read_eof",
            "close",
            "read_frame",
            "shutdown_write",
            "read_eof",
            "close",
        ], "teardown order"
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "plans"
            cases.write_plan(directory, environment())
            assert control.prepared(directory) == plan, "prepared plan"
            altered = json.loads((directory / "plan.json").read_text())
            altered["overlap"]["b_304"] = cases.source_plan(environment())["overlap"][
                "a_300"
            ]
            (directory / "plan.json").write_text(json.dumps(altered))
            with pytest.raises(ValueError, match="hash differs"):
                control.prepared(directory)

    def test_both_arrival_orders_from_generated_plan(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Check the overlap verdict and streams for both arrival orders."""
        for order in ("ack-first", "update-first"):
            recorder, server_a, server_b = self.fixture(request)
            a, b = overlap_messages(order)
            server_a.sendall(a)
            server_b.sendall(b)
            frames = control.DualDrain(recorder, time.monotonic() + 1).until(
                OVERLAP_ARRIVALS, 1
            )
            assert control.check_overlap(frames, 1, 2) == "old", f"{order}: verdict"
            assert len(frames) == 5, f"{order}: frame count"
            assert all(f["raw_hex"] and f["arrival_ns"] >= 0 for f in frames), (
                f"{order}: frame provenance"
            )
            assert recorder.streams()["a"]["received_hex"] == a.hex(), (
                f"{order}: stream a bytes"
            )
            assert recorder.streams()["b"]["received_hex"] == b.hex(), (
                f"{order}: stream b bytes"
            )

    def test_truncated_malformed_and_wrong_correlation(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Reject a truncated, malformed or uncorrelated frame before any verdict."""
        required = {("a", 1, 0, 11)}
        recorder, server_a, _server_b = self.fixture(request)
        server_a.sendall(roster_reply(11)[:10])
        server_a.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError, match="Truncated frame"):
            control.DualDrain(recorder, time.monotonic() + 1).until(required, 1)
        assert recorder.streams()["a"]["received_hex"] == roster_reply(11)[:10].hex(), (
            "truncated bytes retained"
        )
        recorder, server_a, _server_b = self.fixture(request)
        server_a.sendall(bytes.fromhex(packet(0, 11, b"\0\1", reply=1)))
        with pytest.raises(ValueError, match="Malformed"):
            control.DualDrain(recorder, time.monotonic() + 1).until(required, 1)
        recorder, server_a, _server_b = self.fixture(request)
        server_a.sendall(roster_reply(99))
        with pytest.raises(TimeoutError, match="timed out"):
            control.DualDrain(recorder, time.monotonic() + 0.02).until(required, 0.02)

    def test_torn_identity_and_extra_update_fail(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Reject a torn roster identity, a surplus frame and a repeated scalar."""
        recorder, server_a, server_b = self.fixture(request)
        a, b = overlap_messages("ack-first")
        torn = roster_reply(11, name=cases.NEW_B, icon=2)
        server_a.sendall(torn + a[len(roster_reply(11)) :])
        server_b.sendall(b)
        frames = control.DualDrain(recorder, time.monotonic() + 1).until(
            OVERLAP_ARRIVALS, 1
        )
        with pytest.raises(ValueError, match="torn"):
            control.check_overlap(frames, 1, 2)
        with pytest.raises(ValueError, match="set differs"):
            control.check_overlap([*frames, frames[1]], 1, 2)
        duplicate = [dict(frame) for frame in frames]
        update = control.one(duplicate, "a", 301, 0, 0)
        update["fields"] = [*update["fields"], update["fields"][-1]]
        with pytest.raises(ValueError, match="repeated scalar"):
            control.check_overlap(duplicate, 1, 2)

    def test_actual_setup_consumer_rejects_third_user(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Accept the two-member setup and reject a third user in the roster."""
        recorder, _server_a, _server_b = self.fixture(request)
        a = [
            reply(0, 1, []),
            notice(354, 2, [(110, ADMIN)]),
            notice(109, 3, []),
            notice(
                301,
                4,
                [
                    (103, b"\0\x02"),
                    (102, cases.OLD_B),
                    (104, cases.ICON_B),
                    (112, b"\0\x20"),
                ],
            ),
            roster_reply(10),
        ]
        b = [
            reply(0, 1, []),
            notice(354, 2, [(110, ADMIN)]),
            notice(109, 3, []),
            roster_reply(10),
        ]
        recorder.frames = [decoded(raw, "a") for raw in a] + [
            decoded(raw, "b") for raw in b
        ]
        recorder.variables["b_uid"] = b"\0\x02"
        assert control.check_setup(recorder) == (1, 2), "two-member setup"
        third = reply(
            0,
            10,
            [
                (300, record(1, 1, cases.OLD_A)),
                (300, record(2, 2, cases.OLD_B)),
                (300, record(3, 4, b"unexpected")),
            ],
        )
        recorder.frames[4] = decoded(third, "a")
        with pytest.raises(ValueError, match="third member"):
            control.check_setup(recorder)


class WholeRunTests:
    """Whole coordinator runs over both arrival orders and the late tail."""

    def test_generated_plan_through_actual_coordinator_both_orders_and_tail(
        self,
    ) -> None:
        """Run the coordinator on the generated plan and reject altered maps."""
        for order, late in (("ack-first", False), ("update-first", True)):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cases.write_plan(root / "plans", environment())
                binary = root / "oracle"
                binary.write_bytes(b"oracle")
                (root / "receipt.json").write_text(
                    json.dumps({
                        "deadline_utc": (
                            dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2)
                        ).isoformat()
                    })
                )
                FakeNativeRecorder.order, FakeNativeRecorder.late_tail = order, late
                with (
                    mock.patch.object(control, "runtime_gate"),
                    mock.patch.object(
                        control, "ORACLE_SHA256", sha256(b"oracle").hexdigest()
                    ),
                    mock.patch.object(control, "Recorder", FakeNativeRecorder),
                ):
                    report = control.run(
                        root / "plans", root / "receipt.json", binary, root / "out"
                    )
                assert report["status"] == "completed", f"{order}: {report['error']}"
                assert report["overlap_status"] == "completed", f"{order}: overlap"
                assert report["old_or_new_snapshot"] == (
                    "old" if order == "ack-first" else "new"
                ), f"{order}: snapshot"
                assert report["teardown_status"] == (
                    "completed_with_late_bytes" if late else "completed"
                ), f"{order}: teardown"
                control.verify_operation_map(cases.source_plan(environment()), report)
                changed = json.loads(json.dumps(report))
                injected = next(
                    e for e in changed["operation_map"] if e["label"] == "b304-rename"
                )
                changed["events"][injected["event_range"][0]]["hex"] = "00"
                with pytest.raises(ValueError, match="Injected request bytes"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )
                changed = json.loads(json.dumps(report))
                drain = next(
                    e for e in changed["operation_map"] if e["label"] == "overlap-drain"
                )
                changed["events"][drain["event_range"][0]]["action"] = 1
                with pytest.raises(ValueError, match="Custom drain"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )
                changed = json.loads(json.dumps(report))
                changed["operation_map"][2]["event_range"][0] += 1
                with pytest.raises(ValueError, match="Operation map bounds"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )
