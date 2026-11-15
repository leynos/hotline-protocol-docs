"""Exercise capture tooling against explicitly synthetic TCP peers."""

import typing as typ
from unittest import mock

import protocol_capture
import pytest
from capture_support import CONNECT, peer
from protocol_capture import run_plan, verify_capture

if typ.TYPE_CHECKING:
    import socket

    from capture_support import Harness

HANDSHAKE_HEX = "54525450484f544c00010002"
FIRST_RESERVED_PORT = 1


class CaptureTests:
    """Keep local tooling results distinct from native-server evidence."""

    def test_segmented_response_preserves_bytes_and_synthetic_identity(
        self, harness: Harness
    ) -> None:
        """Two segments of the reply reassemble, and the profile stays synthetic."""

        def respond(connection: socket.socket) -> None:
            """Expect the handshake, then answer in two segments."""
            assert connection.recv(12) == b"TRTPHOTL\x00\x01\x00\x02", (
                "expected the handshake"
            )
            connection.sendall(b"TR")
            connection.sendall(b"TP\x00\x00\x00\x00")

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    {"op": "send", "connection": "main", "hex": HANDSHAKE_HEX},
                    {
                        "op": "read",
                        "connection": "main",
                        "size": 8,
                        "expect_hex": "5452545000000000",
                    },
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"
        assert report["profile"] == "synthetic-tool-test", "expected synthetic profile"
        assert not report["native_conformance"], "expected no native claim"
        received = bytes.fromhex(report["streams"]["main"]["received_hex"])
        assert received == b"TRTP\x00\x00\x00\x00", "expected both segments"
        verify_capture(harness.root / "capture")

    def test_eof_preserves_partial_input_and_failure(self, harness: Harness) -> None:
        """EOF before the requested size fails but keeps the bytes read."""
        with peer(lambda c: c.sendall(b"TR")) as port:
            report = harness.capture(
                port, [{"op": "read", "connection": "main", "size": 8}]
            )
        assert report["status"] == "failed", "expected failure on early EOF"
        assert "EOF" in report["error"], "expected the error to name EOF"
        assert report["streams"]["main"]["received_hex"] == "5452", "expected prefix"
        verify_capture(harness.root / "capture")

    def test_timeout_is_distinct_from_eof_and_keeps_received_prefix(
        self, harness: Harness
    ) -> None:
        """A slow peer times out rather than reaching EOF."""

        def respond(connection: socket.socket) -> None:
            """Send one byte, then wait for the client to close."""
            connection.sendall(b"T")
            assert connection.recv(1) == b"", "expected the client to close"

        with peer(respond) as port:
            report = harness.capture(
                port,
                [{"op": "read", "connection": "main", "size": 8, "timeout": 0.05}],
            )
        assert report["status"] == "failed", "expected failure on timeout"
        assert "timed out" in report["error"], "expected a timeout error"
        assert report["streams"]["main"]["received_hex"] == "54", "expected prefix"

    def test_wrong_expected_bytes_do_not_become_a_success(
        self, harness: Harness
    ) -> None:
        """Bytes that differ from ``expect_hex`` fail but are retained."""
        with peer(lambda c: c.sendall(b"NO")) as port:
            report = harness.capture(
                port,
                [{"op": "read", "connection": "main", "size": 2, "expect_hex": "4f4b"}],
            )
        assert report["status"] == "failed", "expected failure on mismatch"
        assert "Expected" in report["error"], "expected the mismatch to be named"
        assert report["streams"]["main"]["received_hex"] == "4e4f", "expected bytes"

    def test_eof_expectation_records_tail_bytes(self, harness: Harness) -> None:
        """Reading to EOF keeps the tail the peer sent."""
        with peer(lambda c: c.sendall(b"tail")) as port:
            report = harness.capture(port, [{"op": "read_eof", "connection": "main"}])
        assert report["status"] == "completed", "expected the capture to complete"
        assert report["streams"]["main"]["received_hex"] == "7461696c", "expected tail"

    def test_malformed_plan_is_rejected_before_network_or_output(
        self, harness: Harness
    ) -> None:
        """A step naming an undeclared connection never opens a socket."""
        path = harness.plan(
            FIRST_RESERVED_PORT,
            [{"op": "send", "connection": "unknown", "hex": "00"}],
        )
        with pytest.raises(ValueError, match="Unknown connection"):
            run_plan(path, harness.binary, harness.root / "capture")
        assert not (harness.root / "capture").exists(), "expected no output"

    def test_binary_mismatch_is_rejected_before_network_or_output(
        self, harness: Harness
    ) -> None:
        """A binary whose hash differs from the plan's is refused."""
        path = harness.plan(FIRST_RESERVED_PORT, [])
        harness.binary.write_bytes(b"different")
        with pytest.raises(ValueError, match="binary hash"):
            run_plan(path, harness.binary, harness.root / "capture")
        assert not (harness.root / "capture").exists(), "expected no output"

    def test_dynamic_size_on_eof_read_is_rejected_before_io(
        self, harness: Harness
    ) -> None:
        """Only fixed-length reads may take their size from saved bytes."""
        path = harness.plan(
            FIRST_RESERVED_PORT,
            [{"op": "read_eof", "connection": "main", "size_from": "missing"}],
        )
        with pytest.raises(ValueError, match="Only fixed-length reads"):
            run_plan(path, harness.binary, harness.root / "capture")
        assert not (harness.root / "capture").exists(), "expected no output"

    def test_capture_limit_failure_keeps_the_chunk_already_received(
        self, harness: Harness
    ) -> None:
        """Exceeding the session limit fails but keeps the chunk that crossed it."""
        with (
            peer(lambda c: c.sendall(b"abc")) as port,
            mock.patch.object(protocol_capture, "MAX_CAPTURE_BYTES", 2),
        ):
            report = harness.capture(port, [{"op": "read_eof", "connection": "main"}])
        assert report["status"] == "failed", "expected failure over the limit"
        assert report["streams"]["main"]["received_hex"] == "616263", "expected chunk"

    def test_connection_labels_cannot_conflate_separate_tcp_lifetimes(
        self, harness: Harness
    ) -> None:
        """A closed label may not be declared again."""
        path = harness.plan(
            FIRST_RESERVED_PORT,
            [{"op": "close", "connection": "main"}, CONNECT],
        )
        with pytest.raises(ValueError, match="Invalid connection declaration"):
            run_plan(path, harness.binary, harness.root / "capture")
        assert not (harness.root / "capture").exists(), "expected no output"

    def test_existing_output_is_preserved(self, harness: Harness) -> None:
        """An existing output directory is refused and left untouched."""
        path = harness.plan(FIRST_RESERVED_PORT, [])
        output = harness.root / "capture"
        output.mkdir()
        marker = output / "keep"
        marker.write_text("untouched")
        with pytest.raises(FileExistsError):
            run_plan(path, harness.binary, output)
        assert marker.read_text() == "untouched", "expected the marker to survive"

    def test_modified_capture_fails_hash_verification(self, harness: Harness) -> None:
        """Editing a retained report breaks its checksum."""
        with peer(lambda c: c.sendall(b"ok")) as port:
            harness.capture(port, [{"op": "read", "connection": "main", "size": 2}])
        (harness.root / "capture/report.json").write_text("{}")
        with pytest.raises(ValueError, match="Checksum"):
            verify_capture(harness.root / "capture")

    def test_connect_retains_addresses_for_packet_correlation(
        self, harness: Harness
    ) -> None:
        """The connect event keeps both socket addresses."""
        with peer(lambda c: c.sendall(b"x")) as port:
            report = harness.capture(
                port, [{"op": "read", "connection": "main", "size": 1}]
            )
        event = report["events"][0]
        assert event["peer_address"] == ["127.0.0.1", port], "expected the peer"
        assert event["local_address"][0] == "127.0.0.1", "expected the local host"
        assert event["local_address"][1] > 0, "expected an ephemeral local port"

    def test_half_close_preserves_receive_direction(self, harness: Harness) -> None:
        """Shutting down writes still lets the peer's reply arrive."""

        def respond(connection: socket.socket) -> None:
            """Wait for the client's FIN, then reply."""
            assert connection.recv(1) == b"", "expected a FIN first"
            connection.sendall(b"after-fin")

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    {"op": "shutdown_write", "connection": "main"},
                    {
                        "op": "read_eof",
                        "connection": "main",
                        "expect_hex": b"after-fin".hex(),
                    },
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"
        events = [e["event"] for e in report["events"]]
        assert "shutdown_write" in events, "expected the shutdown event"

    def test_quiet_window_is_bounded_and_connection_remains_usable(
        self, harness: Harness
    ) -> None:
        """A silent window passes, and the connection carries on afterwards."""

        def respond(connection: socket.socket) -> None:
            """Echo one byte, changed, once the client speaks."""
            assert connection.recv(1) == b"x", "expected the client byte"
            connection.sendall(b"y")

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    {"op": "expect_quiet", "connection": "main", "timeout": 0.02},
                    {"op": "send", "connection": "main", "hex": "78"},
                    {"op": "read", "connection": "main", "size": 1, "expect_hex": "79"},
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"
        assert "quiet" in [e["event"] for e in report["events"]], "expected quiet event"

    def test_quiet_window_rejects_eof_and_keeps_unexpected_bytes(
        self, harness: Harness
    ) -> None:
        """EOF or stray bytes in a quiet window fail the capture."""
        for value in [b"", b"unexpected"]:
            with peer(lambda c, value=value: c.sendall(value)) as port:
                plan = harness.plan(
                    port,
                    [{"op": "expect_quiet", "connection": "main", "timeout": 0.2}],
                )
                output = harness.root / ("quiet-" + value.hex())
                report = run_plan(plan, harness.binary, output)
            assert report["status"] == "failed", f"expected failure for {value!r}"
            if value:
                assert report["streams"]["main"]["received_hex"], "expected the bytes"
            else:
                events = [e["event"] for e in report["events"]]
                assert "eof" in events, "expected the EOF event"

    def test_send_after_half_close_is_rejected_before_io(
        self, harness: Harness
    ) -> None:
        """Sending after shutting down writes is refused at validation."""
        plan = harness.plan(
            FIRST_RESERVED_PORT,
            [
                {"op": "shutdown_write", "connection": "main"},
                {"op": "send", "connection": "main", "hex": "78"},
            ],
        )
        with pytest.raises(ValueError, match="write side"):
            run_plan(plan, harness.binary, harness.root / "invalid")
