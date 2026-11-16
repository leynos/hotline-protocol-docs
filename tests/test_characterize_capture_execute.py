"""Characterize ``Recorder.execute`` of ``protocol_capture`` against a fake socket.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``). The socket is a fake that serves queued
chunks, so nothing is opened. Besides each operation's events, the tests pin
which error a step ends with when it carries two faults, because the function
runs its checks in a fixed order that a split into one function per operation
could change.
"""

import socket
import struct

import pytest
from capture_fake_socket import (
    LIMIT,
    FakeSocket,
    ending,
    frame,
    kinds,
    recorder,
)

CHARACTERIZES = "protocol_capture.py"


class TestSimpleOperations:
    """Operations that read nothing."""

    def test_a_pause_sleeps_then_records_one_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The sleep is the plan's seconds."""
        slept: list[float] = []
        monkeypatch.setattr("time.sleep", slept.append)
        rec = recorder()
        assert ending(rec, {"op": "pause", "seconds": 5}) == "done", (
            "expected ending(rec, {'op': 'pause', 'seconds': 5}) == 'don"
        )
        assert slept == [5], slept
        assert kinds(rec) == ["pause"], rec.events

    def test_a_close_removes_the_socket_and_closes_it(self) -> None:
        """The connection is gone afterwards."""
        fake = FakeSocket()
        rec = recorder(fake)
        assert ending(rec, {"op": "close", "connection": "main"}) == "done", (
            "expected ending(rec, {'op': 'close', 'connection': 'main'})"
        )
        assert fake.closed, "expected the socket to be closed"
        assert "main" not in rec.sockets, rec.sockets
        assert kinds(rec) == ["close"], rec.events

    def test_a_write_shutdown_is_recorded(self) -> None:
        """The send side is shut down."""
        fake = FakeSocket()
        rec = recorder(fake)
        step = {"op": "shutdown_write", "connection": "main"}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert fake.shutdowns == [socket.SHUT_WR], fake.shutdowns
        assert kinds(rec) == ["shutdown_write"], rec.events

    def test_silence_is_a_quiet_event(self) -> None:
        """A timeout is the expected outcome."""
        fake = FakeSocket()
        fake.silent = True
        rec = recorder(fake)
        step = {"op": "expect_quiet", "connection": "main", "timeout": 1}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert kinds(rec) == ["quiet"], rec.events
        assert fake.timeouts == [1], fake.timeouts

    def test_bytes_during_silence_are_kept_then_refused(self) -> None:
        """The byte is an event before the error."""
        rec = recorder(FakeSocket([b"x"]))
        step = {"op": "expect_quiet", "connection": "main"}
        assert ending(rec, step) == (
            "ValueError: Expected bounded silence, received bytes or EOF"
        ), "expected ending(rec, step) == 'ValueError: Expected bounded"
        assert kinds(rec) == ["receive"], rec.events
        assert rec.events[0]["hex"] == "78", rec.events

    def test_end_of_stream_during_silence_is_an_eof_event_then_refused(self) -> None:
        """No data is the end of the stream."""
        rec = recorder(FakeSocket())
        step = {"op": "expect_quiet", "connection": "main"}
        assert ending(rec, step) == (
            "ValueError: Expected bounded silence, received bytes or EOF"
        ), "expected ending(rec, step) == 'ValueError: Expected bounded"
        assert kinds(rec) == ["eof"], rec.events


class TestSend:
    """The send operation."""

    def test_a_variable_is_substituted_and_sent_in_the_chunks_accepted(self) -> None:
        """Each accepted chunk is an event."""
        fake = FakeSocket(step=2)
        rec = recorder(fake)
        rec.variables["n"] = b"\x01\x02"
        step = {"op": "send", "connection": "main", "hex": "aa{n}bb"}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert fake.sent == b"\xaa\x01\x02\xbb", fake.sent
        assert [e["hex"] for e in rec.events] == ["aa01", "02bb"], rec.events

    def test_a_socket_that_accepts_nothing_is_an_eof_error(self) -> None:
        """A zero count is a closed socket."""
        rec = recorder(FakeSocket(step=-1))
        step = {"op": "send", "connection": "main", "hex": "aa"}
        assert ending(rec, step) == "EOFError: Socket closed during send", (
            "expected ending(rec, step) == 'EOFError: Socket closed duri"
        )

    def test_an_unsaved_variable_is_a_key_error(self) -> None:
        """The plan check normally prevents this."""
        rec = recorder()
        step = {"op": "send", "connection": "main", "hex": "{nope}"}
        assert ending(rec, step) == "KeyError: 'nope'", (
            "expected ending(rec, step) == 'KeyError: 'nope''"
        )

    def test_a_send_over_the_remaining_limit_is_refused_before_it_starts(self) -> None:
        """The refusal comes before the connection's timeout is touched."""
        fake = FakeSocket()
        rec = recorder(fake)
        rec.byte_count = LIMIT - 1
        step = {"op": "send", "connection": "main", "hex": "aabb"}
        assert (
            ending(rec, step) == "ValueError: Send exceeds remaining capture limit"
        ), "expected ending(rec, step) == 'ValueError: Send exceeds rem"
        assert not fake.timeouts, fake.timeouts

    def test_a_send_after_the_deadline_is_a_timeout(self) -> None:
        """A step whose time has run out sends nothing."""
        fake = FakeSocket()
        rec = recorder(fake)
        step = {"op": "send", "connection": "main", "hex": "aa", "timeout": -1}
        assert ending(rec, step) == "TimeoutError: Action timed out", (
            "expected ending(rec, step) == 'TimeoutError: Action timed o"
        )
        assert fake.sent == b"", fake.sent


class TestReads:
    """The fixed-length and read-to-end operations."""

    def test_a_read_records_each_chunk(self) -> None:
        """A read of four bytes from two chunks."""
        rec = recorder(FakeSocket([b"ab", b"cd"]))
        step = {"op": "read", "connection": "main", "size": 4}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert [e["hex"] for e in rec.events] == ["6162", "6364"], rec.events

    def test_end_of_stream_before_the_size_is_an_eof_error_after_its_event(
        self,
    ) -> None:
        """The partial bytes stay recorded."""
        rec = recorder(FakeSocket([b"ab"]))
        step = {"op": "read", "connection": "main", "size": 4}
        assert ending(rec, step) == "EOFError: EOF before 4 requested bytes", (
            "expected ending(rec, step) == 'EOFError: EOF before 4 reque"
        )
        assert kinds(rec) == ["receive", "eof"], rec.events

    def test_a_read_to_end_stops_at_the_end_of_the_stream(self) -> None:
        """No size means read until EOF."""
        rec = recorder(FakeSocket([b"ab"]))
        assert ending(rec, {"op": "read_eof", "connection": "main"}) == "done", (
            "expected ending(rec, {'op': 'read_eof', 'connection': 'main"
        )
        assert kinds(rec) == ["receive", "eof"], rec.events

    def test_a_read_after_the_deadline_is_a_timeout_before_any_receive(self) -> None:
        """Nothing is read once the time has run out."""
        rec = recorder(FakeSocket([b"ab"]))
        step = {"op": "read", "connection": "main", "size": 2, "timeout": -1}
        assert ending(rec, step) == "TimeoutError: Action timed out", (
            "expected ending(rec, step) == 'TimeoutError: Action timed o"
        )
        assert rec.events == [], rec.events

    def test_the_session_limit_is_refused_after_the_chunk_is_recorded(self) -> None:
        """The chunk that crosses the limit is kept."""
        rec = recorder(FakeSocket([b"abc"]))
        rec.byte_count = LIMIT - 1
        step = {"op": "read_eof", "connection": "main"}
        assert ending(rec, step) == "ValueError: Session exceeds capture limit", (
            "expected ending(rec, step) == 'ValueError: Session exceeds "
        )
        assert kinds(rec) == ["receive"], rec.events

    def test_the_expected_bytes_are_checked_before_a_save(self) -> None:
        """A mismatch hides a save that would also fail."""
        rec = recorder(FakeSocket([b"\x01\x02"]))
        step = {
            "op": "read",
            "connection": "main",
            "size": 2,
            "expect_hex": "0304",
            "save": {"name": "v", "offset": 5, "size": 1},
        }
        assert ending(rec, step) == "ValueError: Expected 0304, received 0102", (
            "expected ending(rec, step) == 'ValueError: Expected 0304, r"
        )
        assert not rec.variables, rec.variables

    def test_a_save_past_the_end_is_refused(self) -> None:
        """Offset plus size must fit in what was received."""
        rec = recorder(FakeSocket([b"\x01\x02"]))
        step = {
            "op": "read",
            "connection": "main",
            "size": 2,
            "save": {"name": "v", "offset": 1, "size": 2},
        }
        assert ending(rec, step) == "ValueError: Saved bytes exceed received value", (
            "expected ending(rec, step) == 'ValueError: Saved bytes exce"
        )

    def test_a_save_keeps_the_slice(self) -> None:
        """The slice is kept under its name."""
        rec = recorder(FakeSocket([b"\x01\x02\x03"]))
        step = {
            "op": "read",
            "connection": "main",
            "size": 3,
            "save": {"name": "v", "offset": 1, "size": 2},
        }
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert rec.variables == {"v": b"\x02\x03"}, rec.variables

    @pytest.mark.parametrize("width", [0, 5])
    def test_a_saved_size_of_the_wrong_width_is_refused_before_any_read(
        self, width: int
    ) -> None:
        """Zero or five bytes cannot give a size, and nothing is read."""
        fake = FakeSocket([b"abcd"])
        rec = recorder(fake)
        rec.variables["n"] = b"\x00" * width
        step = {"op": "read", "connection": "main", "size_from": "n"}
        assert ending(rec, step) == (
            "ValueError: Saved size must contain one to four bytes"
        ), "expected ending(rec, step) == 'ValueError: Saved size must "
        assert rec.events == [], rec.events

    def test_a_saved_size_of_zero_or_over_the_limit_is_refused_before_any_read(
        self,
    ) -> None:
        """The range comes after the width."""
        rec = recorder(FakeSocket([b"abcd"]))
        rec.variables["n"] = b"\x00"
        step = {"op": "read", "connection": "main", "size_from": "n"}
        assert ending(rec, step) == "ValueError: Read size exceeds capture limit", (
            "expected ending(rec, step) == 'ValueError: Read size exceed"
        )
        rec.variables["n"] = (LIMIT + 1).to_bytes(4, "big")
        assert ending(rec, step) == "ValueError: Read size exceeds capture limit", (
            "expected ending(rec, step) == 'ValueError: Read size exceed"
        )
        assert rec.events == [], rec.events

    def test_a_missing_saved_size_is_a_key_error(self) -> None:
        """The variable must exist."""
        rec = recorder(FakeSocket())
        step = {"op": "read", "connection": "main", "size_from": "n"}
        assert ending(rec, step) == "KeyError: 'n'", (
            "expected ending(rec, step) == 'KeyError: 'n''"
        )

    def test_a_saved_size_drives_the_read(self) -> None:
        """Big-endian, one to four bytes."""
        rec = recorder(FakeSocket([b"abcdef"]))
        rec.variables["n"] = b"\x00\x03"
        step = {"op": "read", "connection": "main", "size_from": "n"}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert rec.events[0]["hex"] == "616263", rec.events


class TestFrameReads:
    """The frame operation."""

    def test_a_frame_is_decoded_and_kept(self) -> None:
        """The header is read first, then the rest."""
        rec = recorder(FakeSocket([frame(b"\x00\x00")]))
        step = {"op": "read_frame", "connection": "main"}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert len(rec.frames) == 1, rec.frames
        assert rec.frames[0]["action"] == 0, rec.frames
        assert rec.frames[0]["connection"] == "main", rec.frames
        assert rec.frames[0]["data_size"] == 2, rec.frames

    def test_a_frame_over_the_limit_is_refused_after_its_header_is_read(self) -> None:
        """Only the header is recorded."""
        head = struct.pack(">BBHIIII", 0, 1, 0, 7, 0, LIMIT, LIMIT)
        rec = recorder(FakeSocket([head]))
        step = {"op": "read_frame", "connection": "main"}
        assert ending(rec, step) == "ValueError: Frame exceeds capture limit", (
            "expected ending(rec, step) == 'ValueError: Frame exceeds ca"
        )
        assert [e["hex"] for e in rec.events] == [head.hex()], rec.events

    def test_a_non_matching_frame_is_followed_by_the_next(self) -> None:
        """Reading goes on until the match."""
        rec = recorder(FakeSocket([frame(is_reply=0), frame(is_reply=1)]))
        step = {
            "op": "read_frame",
            "connection": "main",
            "match_frame": {"is_reply": 1},
        }
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert len(rec.frames) == 2, rec.frames

    def test_the_observation_bound_message_is_as_recorded(self) -> None:
        """The message runs two words together; it is kept."""
        rec = recorder(FakeSocket([frame(is_reply=0)] * 256))
        step = {
            "op": "read_frame",
            "connection": "main",
            "match_frame": {"is_reply": 1},
        }
        assert ending(rec, step) == (
            "ValueError: Frame match exceeds256-frame observation bound"
        ), "expected ending(rec, step) == 'ValueError: Frame match exce"
        assert len(rec.frames) == 256, len(rec.frames)

    def test_the_expected_bytes_are_checked_before_the_field_saves(self) -> None:
        """A mismatch hides a field save that would also fail."""
        rec = recorder(FakeSocket([frame(b"\x00\x00")]))
        step = {
            "op": "read_frame",
            "connection": "main",
            "expect_hex": "00",
            "save_fields": {"v": 1},
        }
        assert ending(rec, step).startswith("ValueError: Expected 00, received "), (
            "expected ending(rec, step).startswith('ValueError: Expected"
        )

    def test_a_byte_save_is_checked_before_the_field_saves(self) -> None:
        """A save past the end hides a missing field."""
        rec = recorder(FakeSocket([frame(b"\x00\x00")]))
        step = {
            "op": "read_frame",
            "connection": "main",
            "save": {"name": "v", "offset": 90, "size": 1},
            "save_fields": {"w": 1},
        }
        assert ending(rec, step) == "ValueError: Saved bytes exceed received value", (
            "expected ending(rec, step) == 'ValueError: Saved bytes exce"
        )

    def test_a_missing_field_is_refused(self) -> None:
        """A frame without the field cannot save it."""
        rec = recorder(FakeSocket([frame(b"\x00\x00")]))
        step = {"op": "read_frame", "connection": "main", "save_fields": {"w": 1}}
        assert ending(rec, step) == (
            "ValueError: Saved field is missing, ambiguous or incomplete"
        ), "expected ending(rec, step) == 'ValueError: Saved field is m"

    def test_a_field_is_saved_by_identifier(self) -> None:
        """The field's value bytes are kept under the name."""
        payload = b"\x00\x01\x00\x01\x00\x02\xab\xcd"
        rec = recorder(FakeSocket([frame(payload)]))
        step = {"op": "read_frame", "connection": "main", "save_fields": {"w": 1}}
        assert ending(rec, step) == "done", "expected ending(rec, step) == 'done'"
        assert rec.variables == {"w": b"\xab\xcd"}, rec.variables

    def test_an_absent_connection_is_a_key_error(self) -> None:
        """The socket is looked up by name."""
        rec = recorder()
        assert ending(rec, {"op": "read", "connection": "ghost", "size": 1}) == (
            "KeyError: 'ghost'"
        ), "expected ending(rec, {'op': 'read', 'connection': 'ghost', "
