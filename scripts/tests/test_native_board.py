"""Offline generated-wire and fault controls for the isolated board fixture."""

import copy
import json
import socket
import time
import typing as typ

import capture_identity
import native_board_cases as cases
import pytest
from native_board_control import (
    CAPTURE_MODULES,
    IDENTITY_KEY,
    CaseResults,
    Wire,
    execute_case,
    prepared,
    verify_report,
)
from native_plan import packet, payload
from native_wire_names import (
    FIELD_DATA,
)
from protocol_capture import Recorder
from test_native_board_wire import (
    ACK,
    BOARD_POST,
    BOARD_UPDATE,
    BOUNDARY_POSTS,
    BOUNDARY_SIZES,
    DEADLINE_SECONDS,
    EXPECTED_POSTS,
    EXPECTED_WAITING_UPDATES,
    FIRST_POST_ID,
    MALFORMED_HEADER_BYTES,
    MALFORMED_SIZE_BYTES,
    NANOS_PER_SECOND,
    NON_BLOCKING_TIMEOUT,
    POLL_SECONDS,
    PREFIX,
    PREFIX_BYTES,
    READ_LIMIT,
    REQUEST_ID,
    SHORT_FRAME_BYTES,
    TIMING_SKEW_SECONDS,
    FakeWire,
    environment,
    fake_report,
    refuses,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


class BoardTests:
    """Reject generated, malformed and faulted board cases with offline controls."""

    def test_generated_full_chain(self) -> None:
        """A generated case verifies, with its posts, reads and waiting updates."""
        plan, report = fake_report()
        verify_report(plan, report)
        assert len(report["post_data_hex"]) == EXPECTED_POSTS, "the post count differs"
        assert len(bytes.fromhex(report["reads"]["10"])) == READ_LIMIT, (
            "the full read length differs"
        )
        assert bytes.fromhex(report["reads"]["11"]) == bytes.fromhex(
            report["reads"]["12"]
        ), "the rejected read differs from the stored prefix"
        assert (
            sum(len(bytes.fromhex(x)) for x in report["segments_hex"]) > READ_LIMIT
        ), "the segments do not exceed one read"
        assert (
            len([
                f
                for f in report["frames"]
                if f["connection"] == "waiting" and f["type"] == BOARD_UPDATE
            ])
            == EXPECTED_WAITING_UPDATES
        ), "the waiting updates differ"

    def test_generated_boundaries(self) -> None:
        """The generated post sizes sit on the fixed boundaries."""
        assert [len(cases.post_data(i)) for i in BOUNDARY_POSTS] == BOUNDARY_SIZES, (
            "the post boundaries differ"
        )
        refuses(cases.post_data, 10)

    def test_static_and_runtime_identity_required(self) -> None:
        """A plan without its runtime identity or empty baseline is refused."""
        for key in (
            "emulator_pid",
            "emulator_netns_inode",
            "owned_working_image_inode",
        ):
            env = environment()
            env[key] = 0
            refuses(cases.source_plan, env)
        env = environment()
        env["stopped_board_baseline"]["data_size"] = 1
        refuses(cases.source_plan, env)

    def test_prepared_plan_hash_and_source(self, tmp_path: Path) -> None:
        """A prepared plan is refused when its source hash or its plan changes."""
        root = tmp_path / "new"
        cases.write_plan(root, environment())
        prepared(root)
        hashes_path = root / "source-hashes.json"
        original_hashes = hashes_path.read_text()
        hashes = json.loads(original_hashes)
        hashes["native_board_control.py"] = "0" * 64
        hashes_path.write_text(json.dumps(hashes))
        with pytest.raises(ValueError, match="source hash"):
            prepared(root)
        hashes_path.write_text(original_hashes)
        plan = json.loads((root / "plan.json").read_text())
        plan["operations"][0]["label"] = "changed"
        (root / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        refuses(prepared, root)

    def test_the_plan_records_the_identity_of_the_control_modules(
        self, tmp_path: Path
    ) -> None:
        """The source hashes hold the control's set digest and its identity record."""
        root = tmp_path / "new"
        cases.write_plan(root, environment())
        hashes = json.loads((root / "source-hashes.json").read_text())
        record = hashes[IDENTITY_KEY]
        assert hashes["native_board_control.py"] == record["digest"], (
            "the control's hash is not the digest of its module set"
        )
        assert [item["path"] for item in record["files"]] == [
            f"scripts/{name}" for name in CAPTURE_MODULES
        ], "the identity lists other modules than the declared set"
        assert capture_identity.check(record, CAPTURE_MODULES), (
            "the identity does not describe the live modules"
        )

    def test_a_prepared_plan_is_refused_when_a_control_module_is_altered(
        self, tmp_path: Path
    ) -> None:
        """A recorded module hash that differs from the live file is refused."""
        root = tmp_path / "new"
        cases.write_plan(root, environment())
        path = root / "source-hashes.json"
        hashes = json.loads(path.read_text())
        hashes[IDENTITY_KEY]["files"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(hashes))
        with pytest.raises(ValueError, match="source hash"):
            prepared(root)

    def test_corrupt_segment_fails_before_false_success(self) -> None:
        """A corrupt segment fails the case rather than reporting success."""
        refuses(fake_report, "corrupt_segment")

    def test_actor_and_boundary_semantic_faults(self) -> None:
        """Each semantic fault of an actor or boundary is refused."""
        for fault in (
            "permission",
            "waiting_online",
            "missing_eligible",
            "denied_update",
            "filler",
            "error_status",
        ):
            refuses(fake_report, fault, errors=(ValueError, AssertionError))

    def test_source_operation_fault_rejected(self) -> None:
        """A planned operation with a foreign request is refused by the source."""
        plan = cases.source_plan(environment())
        plan["operations"][4]["hex"] = packet(BOARD_POST, FIRST_POST_ID)
        recorder = Recorder(plan)
        wire = FakeWire(recorder)
        try:
            refuses(execute_case, wire, plan, CaseResults(), pace_seconds=0)
        finally:
            for name in list(recorder.sockets):
                wire.close(name)

    def test_optional_waiting_update_requires_actual_first_three_segment(self) -> None:
        """The waiting connection's update must be the first post's actual segment."""
        plan, report = fake_report("wrong_waiting")
        with pytest.raises(ValueError, match="Waiting update"):
            verify_report(plan, report)

    def test_nonblocking_parser_preserves_fragmented_socketpair_bytes(self) -> None:
        """A frame split across reads is reassembled with its bytes unchanged."""
        plan = cases.source_plan(environment())
        recorder = Recorder(plan)
        wire = Wire(recorder, time.monotonic() + DEADLINE_SECONDS)
        client, server = socket.socketpair()
        try:
            client.settimeout(NON_BLOCKING_TIMEOUT)
            recorder.sockets["sender"] = client
            wire.buffers["sender"] = bytearray()
            raw = bytes.fromhex(
                packet(ACK, REQUEST_ID, payload([(FIELD_DATA, b"x")]), reply=1)
            )
            server.sendall(raw[:SHORT_FRAME_BYTES])
            wire.poll(time.monotonic() + POLL_SECONDS)
            assert not recorder.frames, "a partial frame was reported"
            server.sendall(raw[SHORT_FRAME_BYTES:])
            wire.poll(time.monotonic() + POLL_SECONDS)
            assert recorder.frames[0]["raw_hex"] == raw.hex(), "the frame bytes differ"
            server.shutdown(socket.SHUT_WR)
            wire.poll(time.monotonic() + POLL_SECONDS)
            assert "sender" in wire.eof, "the end of stream was not observed"
        finally:
            client.close()
            server.close()

    def test_real_wire_tail_failures_close_owned_fd_and_preserve_bytes(self) -> None:
        """A truncated or oversized tail fails the close, and the fd is still freed."""
        for malformed in (False, True):
            plan = cases.source_plan(environment())
            recorder = Recorder(plan)
            wire = Wire(recorder, time.monotonic() + DEADLINE_SECONDS)
            client, server = socket.socketpair()
            try:
                client.settimeout(NON_BLOCKING_TIMEOUT)
                recorder.sockets["sender"] = client
                wire.buffers["sender"] = bytearray()
                raw = (
                    bytes.fromhex(packet(ACK, REQUEST_ID))[:SHORT_FRAME_BYTES]
                    if not malformed
                    else bytes.fromhex(packet(ACK, REQUEST_ID))[:MALFORMED_HEADER_BYTES]
                    + b"\xff" * MALFORMED_SIZE_BYTES
                )
                server.sendall(raw)
                server.shutdown(socket.SHUT_WR)
                with pytest.raises(ValueError, match=r"Truncated|size bound"):
                    wire.close("sender")
                assert client.fileno() == -1, "the socket was not closed"
                assert "sender" not in recorder.sockets, "the socket was kept"
                assert (
                    b"".join(
                        bytes.fromhex(e["hex"])
                        for e in recorder.events
                        if e["event"] == "receive"
                    )
                    == raw
                ), "the received bytes differ"
                assert recorder.events[-1]["event"] == "close", "close not last"
            finally:
                client.close()
                server.close()

    def test_faults_reject_report_claims(self) -> None:
        """Each altered claim in a completed report is refused by verification."""
        plan, report = fake_report()
        for alteration in (
            "prefix",
            "boundary",
            "read",
            "status",
            "timing",
            "missing_frame",
        ):
            bad = copy.deepcopy(report)
            match alteration:
                case "prefix":
                    bad["segments_hex"][0] = (
                        PREFIX + bytes.fromhex(bad["segments_hex"][0])[PREFIX_BYTES:]
                    ).hex()
                case "boundary":
                    bad["post_data_hex"][12] = "00"
                case "read":
                    bad["reads"]["11"] = "00"
                case "status":
                    bad["status"] = "completed_storage_proven"
                case "timing":
                    bad["events"][0]["elapsed_ns"] = int(
                        (bad["elapsed_seconds"] + TIMING_SKEW_SECONDS)
                        * NANOS_PER_SECOND
                    )
                case _:
                    bad["frames"].pop()
            refuses(verify_report, plan, bad)
