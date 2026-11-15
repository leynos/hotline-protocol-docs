"""Exercise frame decoding and saved fields against synthetic TCP peers."""

import struct
import typing as typ

import pytest
from capture_support import frame_of, peer, read_frame_step, reseal
from protocol_capture import run_plan, verify_capture

if typ.TYPE_CHECKING:
    import socket

    from capture_support import Harness

REFERENCE_PAYLOAD = bytes.fromhex("0001006b000412345678")
FIRST_RESERVED_PORT = 1
UINT32_MAX = 0xFFFFFFFF
FRAME_BOUND = 256
FIELD_REFERENCE = 107
FIELD_LENGTH = 108
NOTIFICATION_TYPE = 302


class FrameCaptureTests:
    """Decode received frames and save fields from them."""

    def test_frame_decoding_and_saved_reference_use_real_received_bytes(
        self, harness: Harness
    ) -> None:
        """A saved slice of a received frame is sent back unchanged."""

        def respond(connection: socket.socket) -> None:
            """Send a frame and expect its saved reference back."""
            connection.sendall(frame_of(REFERENCE_PAYLOAD))
            assert connection.recv(4) == bytes.fromhex("12345678"), (
                "expected the saved field back"
            )

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    *read_frame_step(
                        save={"name": "reference", "offset": 26, "size": 4}
                    ),
                    {"op": "send", "connection": "main", "hex": "{reference}"},
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"
        fields = report["frames"][0]["fields"]
        assert fields == [{"id": FIELD_REFERENCE, "hex": "12345678"}], "expected field"
        assert report["frames"][0]["id"] == 7, "expected the frame ID"

    def test_recomputed_checksums_do_not_hide_a_wrong_decoded_view(
        self, harness: Harness
    ) -> None:
        """A resealed report with an altered frame ID still fails verification."""
        with peer(lambda c: c.sendall(frame_of(REFERENCE_PAYLOAD))) as port:
            report = harness.capture(port, read_frame_step())
        directory = harness.root / "capture"
        report["frames"][0]["id"] = 999
        reseal(directory, report)
        with pytest.raises(ValueError, match="Decoded frame mismatch"):
            verify_capture(directory)

    def test_oversized_advertised_frame_is_not_allocated(
        self, harness: Harness
    ) -> None:
        """A frame that advertises 4 GiB is refused, not allocated."""
        header = struct.pack(">BBHIIII", 0, 1, 0, 7, 0, UINT32_MAX, UINT32_MAX)
        with peer(lambda c: c.sendall(header)) as port:
            report = harness.capture(port, read_frame_step())
        assert report["status"] == "failed", "expected failure on the huge frame"
        assert "capture limit" in report["error"], "expected the limit to be named"

    def test_saved_field_selects_reference_after_variable_width_metadata(
        self, harness: Harness
    ) -> None:
        """A saved field is found by ID, whatever field precedes it."""
        payload = bytes.fromhex("0002006c00020001006b000412345678")

        def respond(connection: socket.socket) -> None:
            """Send a frame and expect the saved field back."""
            connection.sendall(frame_of(payload))
            assert connection.recv(4) == bytes.fromhex("12345678"), (
                "expected the saved field back"
            )

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    *read_frame_step(
                        save_field={"name": "reference", "id": FIELD_REFERENCE}
                    ),
                    {"op": "send", "connection": "main", "hex": "{reference}"},
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"

    def test_matching_reply_preserves_interleaved_notification(
        self, harness: Harness
    ) -> None:
        """A notification before the matching reply is kept in the frames."""
        notice = frame_of(b"\0\0", kind=NOTIFICATION_TYPE, identifier=3, is_reply=0)
        reply = frame_of(REFERENCE_PAYLOAD, identifier=10)

        def respond(connection: socket.socket) -> None:
            """Send both frames and expect the saved field back."""
            connection.sendall(notice + reply)
            assert connection.recv(4) == bytes.fromhex("12345678"), (
                "expected the saved field back"
            )

        with peer(respond) as port:
            report = harness.capture(
                port,
                [
                    *read_frame_step(
                        match_frame={"is_reply": 1, "id": 10},
                        save_field={"name": "reference", "id": FIELD_REFERENCE},
                    ),
                    {"op": "send", "connection": "main", "hex": "{reference}"},
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"
        types = [f["type"] for f in report["frames"]]
        assert types == [NOTIFICATION_TYPE, 0], "expected the notice, then the reply"
        verified = verify_capture(harness.root / "capture")["frames"]
        assert verified == report["frames"], "expected the replay to agree"

    def test_invalid_reply_match_is_rejected_before_io(self, harness: Harness) -> None:
        """Empty, out-of-range or unknown match keys are refused."""
        for match in [{}, {"id": -1}, {"type": 65536}, {"payload_hex": "00"}]:
            plan = harness.plan(FIRST_RESERVED_PORT, read_frame_step(match_frame=match))
            with pytest.raises(ValueError, match="Invalid frame match"):
                run_plan(plan, harness.binary, harness.root / "capture")
        assert not (harness.root / "capture").exists(), "expected no output"

    def test_reply_match_has_bounded_intervening_frame_count(
        self, harness: Harness
    ) -> None:
        """A flood of non-matching notifications stops at the observation bound."""
        notice = frame_of(b"\0\0", kind=NOTIFICATION_TYPE, identifier=3, is_reply=0)
        with peer(lambda c: c.sendall(notice * FRAME_BOUND)) as port:
            report = harness.capture(
                port, read_frame_step(match_frame={"is_reply": 1, "id": 10})
            )
        assert report["status"] == "failed", "expected failure at the bound"
        assert "256-frame observation bound" in report["error"], "expected the bound"
        assert len(report["frames"]) == FRAME_BOUND, "expected every frame kept"
        verified = verify_capture(harness.root / "capture")["frames"]
        assert verified == report["frames"], "expected the replay to agree"

    def test_saved_field_rejects_absent_duplicate_and_incomplete_values(
        self, harness: Harness
    ) -> None:
        """A missing, repeated or truncated field cannot be saved."""
        payloads = [
            bytes.fromhex("0000"),
            bytes.fromhex("0002006b000412345678006b000487654321"),
            bytes.fromhex("0002006b000412345678006c0002ff"),
        ]
        for index, payload in enumerate(payloads):
            frame = frame_of(payload)
            with peer(lambda c, frame=frame: c.sendall(frame)) as port:
                plan = harness.plan(
                    port,
                    read_frame_step(
                        save_field={"name": "reference", "id": FIELD_REFERENCE}
                    ),
                )
                output = harness.root / f"field-{index}"
                report = run_plan(plan, harness.binary, output)
            assert report["status"] == "failed", f"expected failure for {payload.hex()}"

    def test_multiple_saved_fields_drive_an_exact_length_read(
        self, harness: Harness
    ) -> None:
        """A saved length field sets the size of the next read."""
        payload = bytes.fromhex("0002006c00020003006b000412345678")
        with peer(lambda c: c.sendall(frame_of(payload) + b"abc")) as port:
            report = harness.capture(
                port,
                [
                    *read_frame_step(
                        save_fields={
                            "length": FIELD_LENGTH,
                            "reference": FIELD_REFERENCE,
                        }
                    ),
                    {
                        "op": "read",
                        "connection": "main",
                        "size_from": "length",
                        "expect_hex": "616263",
                    },
                ],
            )
        assert report["status"] == "completed", "expected the capture to complete"

    def test_dynamic_read_size_rejects_tool_bound_overflow(
        self, harness: Harness
    ) -> None:
        """A saved length above the tool's bound is refused."""
        payload = bytes.fromhex("0001006c0004ffffffff")
        with peer(lambda c: c.sendall(frame_of(payload))) as port:
            report = harness.capture(
                port,
                [
                    *read_frame_step(save_fields={"length": FIELD_LENGTH}),
                    {"op": "read", "connection": "main", "size_from": "length"},
                ],
            )
        assert report["status"] == "failed", "expected failure over the bound"
        assert "capture limit" in report["error"], "expected the limit to be named"
