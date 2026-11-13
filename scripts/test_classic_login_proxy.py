"""Offline frame and socket-pair controls for the Classic 161 proxy."""

import socket
import struct
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from classic_login_proxy import (
    Audit,
    namespace_guard,
    parse_frame,
    relay_data,
    relay_frames,
    transform_ack,
)


def frame(
    kind: int,
    identifier: int,
    fields: list[tuple[int, bytes]],
    *,
    reply: int = 0,
    error: int = 0,
    total: int | None = None,
) -> bytes:
    body = struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in fields
    )
    return (
        struct.pack(
            ">BBHIIII",
            0,
            reply,
            kind,
            identifier,
            error,
            len(body) if total is None else total,
            len(body),
        )
        + body
    )


class ClassicLoginProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = frame(
            0, 7, [(160, b"\x00\xbe"), (161, b"\x00\x00"), (162, b"Name")], reply=1
        )

    def test_variants_preserve_unmodified_fields_order_and_header(self) -> None:
        cases = {
            "baseline": b"\x00\x00",
            "omit-161": None,
            "one-byte-161": b"\x00",
            "four-byte-161": b"\x00" * 4,
        }
        for variant, value in cases.items():
            with self.subTest(variant=variant):
                output = transform_ack(self.source, 7, variant)
                parsed = parse_frame(output)
                expected = [(160, b"\x00\xbe"), (162, b"Name")]
                if value is not None:
                    expected.insert(1, (161, value))
                self.assertEqual(parsed["fields"], expected)
                self.assertEqual(
                    (parsed["type"], parsed["id"], parsed["is_reply"], parsed["error"]),
                    (0, 7, 1, 0),
                )
                self.assertEqual(parsed["total_size"], len(output) - 20)
                self.assertEqual(parsed["data_size"], parsed["total_size"])
                if variant == "baseline":
                    self.assertEqual(output, self.source)

    def test_unknown_header_flags_preserved_by_baseline(self) -> None:
        marked = b"\x80" + self.source[1:]
        self.assertEqual(transform_ack(marked, 7, "baseline"), marked)

    def test_wrong_native_value_id_and_status_fail(self) -> None:
        for raw in (
            frame(0, 7, [(161, b"\x00\x01")], reply=1),
            frame(0, 8, [(161, b"\x00\x00")], reply=1),
            frame(0, 7, [(161, b"\x00\x00")], reply=1, error=1),
            frame(109, 7, [(161, b"\x00\x00")]),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                transform_ack(raw, 7, "omit-161")

    def test_malformed_and_fragmented_frames_fail(self) -> None:
        for raw in (
            self.source[:-1],
            self.source[:16] + b"\x00\x00\x00\x03" + self.source[20:],
            frame(0, 7, [(161, b"\x00\x00")], reply=1, total=99),
            frame(0, 7, [(161, b"\x00\x00"), (161, b"\x00\x00")], reply=1),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                transform_ack(raw, 7, "baseline")

    def test_socketpair_passes_other_frames_and_halfclose(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        self.addCleanup(source.close)
        self.addCleanup(writer.close)
        self.addCleanup(sink.close)
        self.addCleanup(reader.close)
        source.settimeout(0.1)
        sink.settimeout(0.1)
        audit = Audit(time.monotonic() + 2)
        t = threading.Thread(
            target=relay_frames, args=(source, sink, audit, "client", None, "baseline")
        )
        t.start()
        raw = frame(300, 11, [])
        writer.sendall(raw)
        writer.shutdown(socket.SHUT_WR)
        self.assertEqual(reader.recv(1024), raw)
        self.assertEqual(reader.recv(1), b"")
        t.join(1)
        self.assertFalse(t.is_alive())
        self.assertEqual(audit.entries[0]["raw_hex"], raw.hex())

    def test_mismatched_first_ack_never_forwarded(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        reader.settimeout(0.05)
        writer.sendall(frame(0, 7, [(161, b"\x00\x01")], reply=1))
        with self.assertRaisesRegex(ValueError, "Native 161 source"):
            relay_frames(
                source, sink, Audit(time.monotonic() + 1), "server", 7, "omit-161"
            )
        with self.assertRaises(TimeoutError):
            reader.recv(1)

    def test_data_bytes_and_halfclose(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        audit = Audit(time.monotonic() + 2)
        thread = threading.Thread(
            target=relay_data, args=(source, sink, audit, "data-client")
        )
        thread.start()
        writer.sendall(b"HTXF\x00\x01")
        writer.shutdown(socket.SHUT_WR)
        self.assertEqual(reader.recv(16), b"HTXF\x00\x01")
        self.assertEqual(reader.recv(1), b"")
        thread.join(1)
        self.assertFalse(thread.is_alive())

    def test_host_network_namespace_rejected_before_listener(self) -> None:
        with (
            patch(
                "classic_login_proxy.os.stat", return_value=SimpleNamespace(st_ino=42)
            ),
            self.assertRaisesRegex(ValueError, "host network namespace"),
        ):
            namespace_guard()

    def test_deadline_and_log_bounds_fail(self) -> None:
        audit = Audit(time.monotonic() - 1)
        with self.assertRaises(TimeoutError):
            audit.record("test", b"x", b"x")
        audit = Audit(time.monotonic() + 2, max_log=50)
        with self.assertRaises(ValueError):
            audit.record("test", b"x" * 100, b"x" * 100)


if __name__ == "__main__":
    unittest.main()
