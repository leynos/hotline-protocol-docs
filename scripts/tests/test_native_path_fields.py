"""Offline controls for the exact field-212/325 native path matrix."""

import copy
import datetime as dt
import json
import socket
import tempfile
import threading
import time
import typing as typ
from pathlib import Path
from unittest import mock

import capture_identity
import native_path_fields_cases as cases
import native_path_fields_control as control
import pytest
from native_plan import packet
from native_rate304_control import Wire
from path_fields_support import (
    model_report,
    non_blocking_socket_pair,
    wire_bounds,
)
from path_fields_wire import FakeWire

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ENV = {
    "fixture_profile": "control-only",
    "emulator_pid": 100,
    "emulator_starttime": "123",
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 456,
    "owned_working_image": "/ignored/working.dsk",
    "owned_working_image_inode": 789,
}


class PathFieldTests:
    """Check the exact cells, the request ledger and the immutable prepared source."""

    def test_exact_cells_and_limits(self) -> None:
        """Pin the twelve cells, their fields and their byte lengths."""
        values = cases.cells()
        assert len(values) == 12, "twelve cells"
        assert [v["field"] for v in values] == [212] * 6 + [325] * 6, "cell fields"
        lengths = [len(bytes.fromhex(v["value_hex"])) for v in values]
        expected = [19, 22, 19, 19, 2048, 2049, 12, 15, 12, 12, 2048, 2049]
        assert lengths == expected, "cell lengths"
        assert values[2]["value_hex"] == "00030000086d2d706174683437000003482d9a", (
            "third cell value"
        )
        assert values[8]["value_hex"] == "00020000076d2d6e34372d9a", "ninth cell value"

    def test_request_ledger(self) -> None:
        """Pin the request, login and mutation counts of the source plan."""
        plan = cases.source_plan(ENV)
        assert "separate unchanged closed 18-action" in plan["preflight"], (
            "preflight text"
        )
        assert len(plan["requests"]) == 81, "request count"
        assert plan["case_request_count_with_login"] == 82, "request count with login"
        assert plan["mutation_count"] == 20, "mutation count"
        assert len({r["id"] for r in plan["requests"]}) == 81, "unique request ids"
        assert [
            r["kind"] for r in plan["requests"] if r["label"].startswith("move-")
        ] == [208] * 6, "move request kinds"

    def test_prepared_source_and_plan_are_immutable(self) -> None:
        """Refuse a prepared plan whose hashed source or plan bytes changed."""
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "prepared"
            cases.write_plan(output, ENV)
            assert control.prepared(output) == cases.source_plan(ENV), (
                "prepared plan matches the source plan"
            )
            hashes = output / "source-hashes.json"
            original = hashes.read_text()
            changed = json.loads(original)
            changed["native_path_fields_control.py"] = "0" * 64
            hashes.write_text(json.dumps(changed))
            with pytest.raises(ValueError, match="source hash differs"):
                control.prepared(output)
            hashes.write_text(original)
            (output / "plan.json").write_text("{}\n")
            with pytest.raises(ValueError, match="source hash differs"):
                control.prepared(output)

    def test_changed_count_high_byte_padding_marker_or_id_rejected(self) -> None:
        """Reject each altered plan field against the hashed source."""
        plan = cases.source_plan(ENV)
        changes = (
            lambda p: p["cells"][2].__setitem__("declared_count", 2),
            lambda p: p["cells"][0].__setitem__(
                "value_hex", p["cells"][0]["value_hex"].replace("482d9a", "482d9b")
            ),
            lambda p: p["cells"][4].__setitem__(
                "value_hex", p["cells"][4]["value_hex"][:-2]
            ),
            lambda p: p["cells"][1].__setitem__(
                "marker_hex", p["cells"][0]["marker_hex"]
            ),
            lambda p: p["requests"][1].__setitem__("id", p["requests"][0]["id"]),
        )
        for change in changes:
            altered = copy.deepcopy(plan)
            change(altered)
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp)
                raw = (json.dumps(altered, indent=2) + "\n").encode()
                (output / "plan.json").write_bytes(raw)
                record = capture_identity.identity(control.CAPTURE_MODULES)
                (output / "source-hashes.json").write_text(
                    json.dumps({
                        "plan.json": cases.sha(raw),
                        "native_path_fields_cases.py": cases.sha(
                            Path(cases.__file__).read_bytes()
                        ),
                        "native_path_fields_control.py": record["digest"],
                        control.IDENTITY_KEY: record,
                    })
                )
                with pytest.raises(ValueError, match="differs from source"):
                    control.prepared(output)


class PathModelTests:
    """Check the fixture model's outcomes, faults and runner failure paths."""

    def setup_method(self) -> None:
        """Load the source plan that every test in the class replays."""
        self.plan = cases.source_plan(ENV)

    def test_observed_nonzero_move_error_is_not_hardcoded(self) -> None:
        """Keep the observed non-zero status of a failed move."""
        wire = FakeWire(self.plan, move_error="move-1")
        result = control.perform(
            typ.cast("control.Wire", wire), self.plan, lambda: None
        )
        assert result["results"][1]["status"] == 999, "observed move status"
        assert result["results"][1]["selected_parent"] == "S", "selected parent"
        wire.close_all()

    def test_foreign_owned_parent_entry_stops_before_second_move(self) -> None:
        """Stop before the second move when a foreign entry appears."""
        wire = FakeWire(self.plan, foreign_after_move=True)
        with pytest.raises(ValueError, match="Unexpected name"):
            control.perform(typ.cast("control.Wire", wire), self.plan, lambda: None)
        assert not any(a["label"] == "move-1" for a in wire.actions), "no second move"
        assert "666f726569676e" in wire.partial["views"][-1]["names"], "foreign name"
        wire.close_all()

    def test_type_change_in_moved_record_stops_before_second_move(self) -> None:
        """Stop before the second move when a moved record changes its type."""
        wire = FakeWire(self.plan, type_flip_after_move=True)
        with pytest.raises(ValueError, match="file type or creator"):
            control.perform(typ.cast("control.Wire", wire), self.plan, lambda: None)
        assert not any(a["label"] == "move-1" for a in wire.actions), "no second move"
        wire.close_all()

    def test_all_twelve_model_outcomes_and_raw_faults(self) -> None:
        """Accept the faithful model report and reject each altered report."""
        wire = FakeWire(self.plan)
        result = control.perform(
            typ.cast("control.Wire", wire), self.plan, lambda: None
        )
        wire.close_all()
        report = model_report(wire, self.plan, result)
        control.verify_report(self.plan, report)
        assert [r["index"] for r in result["results"]] == list(range(12)), (
            "results in case order"
        )
        assert report["request_count"] == 82, "request count with login"
        faults = (
            (
                lambda r: r["views"].pop(
                    next(
                        i
                        for i, v in enumerate(r["views"])
                        if v["label"] == "after-view-0-H"
                    )
                ),
                "View/raw reply differs",
            ),
            (
                lambda r: r["results"][0].__setitem__("selected_parent", "wrapper"),
                "Missing/foreign selected marker",
            ),
            (
                lambda r: r["results"][6].__setitem__("value_hex", "00"),
                "Field cell identity differs",
            ),
            (
                lambda r: r["frames"][0].__setitem__("arrival_elapsed_ns", 0),
                "Frame arrival outside captured receive bracket",
            ),
            (
                lambda r: r["frames"][0].__setitem__(
                    "arrival_elapsed_ns", r["frames"][0]["arrival_elapsed_ns"] + 10**10
                ),
                "Frame arrival outside captured receive bracket",
            ),
            (
                lambda r: r["streams"]["main"].__setitem__("sent_hex", "00"),
                "Raw stream/event mismatch",
            ),
            (
                lambda r: r["actions"][7].__setitem__("elapsed_ns", 0),
                "Action/send event or time bracket differs",
            ),
            (
                lambda r: r["actions"][7].__setitem__(
                    "elapsed_ns", r["actions"][7]["elapsed_ns"] + 10**10
                ),
                "Action/send event or time bracket differs",
            ),
            (
                lambda r: r["terminals"].__setitem__("main", "eof"),
                "Terminal label differs from events",
            ),
            (
                lambda r: r["unparsed_hex"].__setitem__("main", "00"),
                "Received bytes omitted",
            ),
            (
                lambda r: r.__setitem__("source_sha256", "0" * 64),
                "Plan/source/oracle differs",
            ),
            (
                lambda r: next(
                    v for v in r["views"] if v["label"] == "final-roster"
                ).__setitem__("uid", 8),
                "View/raw reply differs",
            ),
        )
        for fault, message in faults:
            changed = copy.deepcopy(report)
            fault(changed)
            with pytest.raises(ValueError, match=message):
                control.verify_report(self.plan, changed)

    def test_missing_selected_readback_fails_before_later_move(self) -> None:
        """Stop before the later move when the selected readback is missing."""
        wire = FakeWire(self.plan, missing_readback=True)
        with pytest.raises(ValueError, match="Marker outside selected"):
            control.perform(typ.cast("control.Wire", wire), self.plan, lambda: None)
        assert "move-0" in wire.partial["progress"], "first move recorded"
        assert not any(a["label"] == "move-1" for a in wire.actions), "no second move"
        wire.close_all()

    def test_late_cleanup_failure_keeps_all_twelve_results(self) -> None:
        """Keep the twelve results and the counts when cleanup fails late."""
        wire = FakeWire(self.plan)
        original_send = wire.send

        def fail_cleanup(name: str, raw: str, label: str) -> None:
            """Fail the news cleanup request and forward every other send.

            Raises
            ------
            OSError
                For the news cleanup request.
            """
            if label == "remove-news-category":
                message = "synthetic cleanup failure"
                raise OSError(message)
            return original_send(name, raw, label)

        typ.cast("typ.Any", wire).send = fail_cleanup
        with pytest.raises(OSError, match="synthetic cleanup failure"):
            control.perform(typ.cast("control.Wire", wire), self.plan, lambda: None)
        assert len(wire.partial["results"]) == 12, "all twelve results kept"
        assert wire.partial["own_uid"] == next(
            v["uid"] for v in wire.partial["views"] if v["label"] == "initial-roster"
        ), "own uid from the initial roster"
        assert wire.partial["current_case_index"] is None, "no case in progress"
        assert wire.partial["mutation_count"] == 17, "mutations before the failure"
        assert wire.partial["request_count"] == 74, "requests before the failure"
        wire.close_all()

    def test_real_socketpair_split_reply_and_partial_failure_tail(self) -> None:
        """Keep a split reply and a partial tail read from a real socket pair."""
        wire = Wire(wire_bounds(self.plan), time.monotonic() + 3)
        owned, peer = non_blocking_socket_pair()
        wire.recorder.sockets["main"] = owned
        wire.buffers["main"] = bytearray()
        complete = bytes.fromhex(packet(0, 100, reply=1))
        partial = bytes.fromhex(packet(0, 101, reply=1))[:13]

        def transmit() -> None:
            """Send the split reply and close the writing side."""
            peer.sendall(complete[:7])
            time.sleep(0.02)
            peer.sendall(complete[7:] + partial)
            peer.shutdown(socket.SHUT_WR)

        worker = threading.Thread(target=transmit)
        worker.start()
        try:
            wire.wait_for(lambda: bool(wire.match("main", 0, 100, 1)), 1, "split reply")
            wire.poll(0.1)
            assert bytes(wire.buffers["main"]) == partial, "partial tail kept"
            assert (
                wire.recorder.streams()["main"]["received_hex"]
                == (complete + partial).hex()
            ), "received bytes"
            wire.close_all()
            assert wire.terminals["main"] == "eof", "terminal label"
            assert owned.fileno() == -1, "descriptor closed"
        finally:
            worker.join(timeout=1)
            owned.close()
            peer.close()
        assert not worker.is_alive(), "sender finished"

    def test_runner_failure_retains_real_partial_bytes_and_closes_fd(self) -> None:
        """Keep the partial bytes and close the descriptor on a runner failure."""
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            plan_dir = base / "plan"
            cases.write_plan(plan_dir, ENV)
            receipt = base / "receipt.json"
            receipt.write_text(
                json.dumps({
                    "deadline_utc": dt.datetime.fromtimestamp(
                        time.time() + 600, dt.UTC
                    ).isoformat(),
                    "emulator_pid": ENV["emulator_pid"],
                })
            )
            binary = base / "binary"
            binary.write_bytes(b"synthetic binary")
            wire = control.Wire(wire_bounds(self.plan), time.monotonic() + 3)
            owned, peer = non_blocking_socket_pair()
            wire.recorder.sockets["main"] = owned
            wire.buffers["main"] = bytearray()
            partial = bytes.fromhex(packet(0, 101, reply=1))[:13]

            def fail_after_receive(
                actual: control.Wire,
                _plan: dict,
                _guard: cabc.Callable[[], None],
            ) -> None:
                """Keep a partial reply, then fail the case run.

                Raises
                ------
                ValueError
                    Always, after the partial reply is kept.
                """
                actual.partial = {
                    "views": [],
                    "results": [{"index": 0, "status": "incomplete"}],
                    "progress": ["before-info-0"],
                    "mutation_count": 12,
                    "own_uid": 7,
                    "current_case_index": 0,
                }
                peer.sendall(partial)
                peer.shutdown(socket.SHUT_WR)
                actual.poll(0.1)
                message = "synthetic incomplete response"
                raise ValueError(message)

            try:
                with (
                    mock.patch.object(control, "prepared", return_value=self.plan),
                    mock.patch.object(control, "runtime_gate", return_value=None),
                    mock.patch.object(control, "Wire", return_value=wire),
                    mock.patch.object(
                        control, "perform", side_effect=fail_after_receive
                    ),
                    mock.patch.object(
                        control, "ORACLE_SHA256", control.sha(binary.read_bytes())
                    ),
                    mock.patch.object(
                        control.os,
                        "stat",
                        return_value=type("S", (), {"st_ino": 456})(),
                    ),
                ):
                    report = control.run(
                        control.RunPaths(plan_dir, receipt, binary, base / "result")
                    )
                assert report["status"] == "failed", "runner reports failure"
                assert report["unparsed_hex"]["main"] == partial.hex(), "partial kept"
                assert report["results"][0]["index"] == 0, "first result kept"
                assert report["current_case_index"] == 0, "case index kept"
                assert owned.fileno() == -1, "descriptor closed"
                assert (
                    json.loads((base / "result" / "report.json").read_text())["status"]
                    == "failed"
                ), "failure written to the report"
            finally:
                owned.close()
                peer.close()
