"""Exercise capture tooling against explicitly synthetic TCP peers."""

import contextlib
import hashlib
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import protocol_capture
from protocol_capture import run_plan, verify_capture


@contextlib.contextmanager
def peer(handler):
    """Run one bounded loopback peer and propagate failures to the test."""
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(2)

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    handler(connection)
            except (OSError, AssertionError) as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1]
        finally:
            thread.join(3)
            if thread.is_alive():
                raise AssertionError("Synthetic peer did not terminate")
            if errors:
                raise AssertionError(str(errors))


class CaptureTests(unittest.TestCase):
    """Keep local tooling results distinct from native-server evidence."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "synthetic.bin"
        self.binary.write_bytes(b"synthetic peer, not the native oracle")

    def plan(self, port, steps):
        path = self.root / "plan.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "profile": "synthetic-tool-test",
                    "operator": "capture unit test",
                    "oracle_sha256": hashlib.sha256(
                        self.binary.read_bytes()
                    ).hexdigest(),
                    "gap_ids": ["GAP-084"],
                    "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
                    "steps": [
                        {"op": "connect", "connection": "main", "endpoint": "control"},
                        *steps,
                    ],
                }
            )
        )
        return path

    def capture(self, port, steps):
        return run_plan(self.plan(port, steps), self.binary, self.root / "capture")

    def test_segmented_response_preserves_bytes_and_synthetic_identity(self):
        def respond(connection):
            self.assertEqual(connection.recv(12), b"TRTPHOTL\x00\x01\x00\x02")
            connection.sendall(b"TR")
            connection.sendall(b"TP\x00\x00\x00\x00")

        with peer(respond) as port:
            report = self.capture(
                port,
                [
                    {
                        "op": "send",
                        "connection": "main",
                        "hex": "54525450484f544c00010002",
                    },
                    {
                        "op": "read",
                        "connection": "main",
                        "size": 8,
                        "expect_hex": "5452545000000000",
                    },
                ],
            )
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["profile"], "synthetic-tool-test")
        self.assertFalse(report["native_conformance"])
        self.assertEqual(
            bytes.fromhex(report["streams"]["main"]["received_hex"]),
            b"TRTP\x00\x00\x00\x00",
        )
        verify_capture(self.root / "capture")

    def test_eof_preserves_partial_input_and_failure(self):
        with peer(lambda c: c.sendall(b"TR")) as port:
            report = self.capture(
                port, [{"op": "read", "connection": "main", "size": 8}]
            )
        self.assertEqual(report["status"], "failed")
        self.assertIn("EOF", report["error"])
        self.assertEqual(report["streams"]["main"]["received_hex"], "5452")
        verify_capture(self.root / "capture")

    def test_timeout_is_distinct_from_eof_and_keeps_received_prefix(self):
        def respond(connection):
            connection.sendall(b"T")
            self.assertEqual(connection.recv(1), b"")

        with peer(respond) as port:
            report = self.capture(
                port, [{"op": "read", "connection": "main", "size": 8, "timeout": 0.05}]
            )
        self.assertEqual(report["status"], "failed")
        self.assertIn("timed out", report["error"])
        self.assertEqual(report["streams"]["main"]["received_hex"], "54")

    def test_wrong_expected_bytes_do_not_become_a_success(self):
        with peer(lambda c: c.sendall(b"NO")) as port:
            report = self.capture(
                port,
                [{"op": "read", "connection": "main", "size": 2, "expect_hex": "4f4b"}],
            )
        self.assertEqual(report["status"], "failed")
        self.assertIn("Expected", report["error"])
        self.assertEqual(report["streams"]["main"]["received_hex"], "4e4f")

    def test_frame_decoding_and_saved_reference_use_real_received_bytes(self):
        payload = bytes.fromhex("0001006b000412345678")
        frame = (
            struct.pack(">BBHIIII", 0, 1, 0, 7, 0, len(payload), len(payload)) + payload
        )

        def respond(connection):
            connection.sendall(frame)
            self.assertEqual(connection.recv(4), bytes.fromhex("12345678"))

        with peer(respond) as port:
            report = self.capture(
                port,
                [
                    {
                        "op": "read_frame",
                        "connection": "main",
                        "save": {"name": "reference", "offset": 26, "size": 4},
                    },
                    {"op": "send", "connection": "main", "hex": "{reference}"},
                ],
            )
        self.assertEqual(report["status"], "completed")
        self.assertEqual(
            report["frames"][0]["fields"], [{"id": 107, "hex": "12345678"}]
        )
        self.assertEqual(report["frames"][0]["id"], 7)

    def test_recomputed_checksums_do_not_hide_a_wrong_decoded_view(self):
        payload = bytes.fromhex("0001006b000412345678")
        frame = (
            struct.pack(">BBHIIII", 0, 1, 0, 7, 0, len(payload), len(payload)) + payload
        )
        with peer(lambda c: c.sendall(frame)) as port:
            report = self.capture(port, [{"op": "read_frame", "connection": "main"}])
        directory = self.root / "capture"
        report["frames"][0]["id"] = 999
        (directory / "report.json").write_text(json.dumps(report))
        (directory / "checksums.sha256").write_text(
            "".join(
                f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ["plan.json", "report.json"]
            )
        )
        with self.assertRaisesRegex(ValueError, "Decoded frame mismatch"):
            verify_capture(directory)

    def test_oversized_advertised_frame_is_not_allocated(self):
        frame = struct.pack(">BBHIIII", 0, 1, 0, 7, 0, 0xFFFFFFFF, 0xFFFFFFFF)
        with peer(lambda c: c.sendall(frame)) as port:
            report = self.capture(port, [{"op": "read_frame", "connection": "main"}])
        self.assertEqual(report["status"], "failed")
        self.assertIn("capture limit", report["error"])

    def test_eof_expectation_records_tail_bytes(self):
        with peer(lambda c: c.sendall(b"tail")) as port:
            report = self.capture(port, [{"op": "read_eof", "connection": "main"}])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["streams"]["main"]["received_hex"], "7461696c")

    def test_malformed_plan_is_rejected_before_network_or_output(self):
        path = self.plan(1, [{"op": "send", "connection": "unknown", "hex": "00"}])
        with self.assertRaisesRegex(ValueError, "Unknown connection"):
            run_plan(path, self.binary, self.root / "capture")
        self.assertFalse((self.root / "capture").exists())

    def test_binary_mismatch_is_rejected_before_network_or_output(self):
        path = self.plan(1, [])
        self.binary.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "binary hash"):
            run_plan(path, self.binary, self.root / "capture")
        self.assertFalse((self.root / "capture").exists())

    def test_capture_limit_failure_keeps_the_chunk_already_received(self):
        with (
            peer(lambda c: c.sendall(b"abc")) as port,
            patch.object(protocol_capture, "MAX_CAPTURE_BYTES", 2),
        ):
            report = self.capture(port, [{"op": "read_eof", "connection": "main"}])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["streams"]["main"]["received_hex"], "616263")

    def test_connection_labels_cannot_conflate_separate_tcp_lifetimes(self):
        path = self.plan(
            1,
            [
                {"op": "close", "connection": "main"},
                {"op": "connect", "connection": "main", "endpoint": "control"},
            ],
        )
        with self.assertRaisesRegex(ValueError, "Invalid connection declaration"):
            run_plan(path, self.binary, self.root / "capture")
        self.assertFalse((self.root / "capture").exists())

    def test_existing_output_is_preserved(self):
        path = self.plan(1, [])
        output = self.root / "capture"
        output.mkdir()
        marker = output / "keep"
        marker.write_text("untouched")
        with self.assertRaises(FileExistsError):
            run_plan(path, self.binary, output)
        self.assertEqual(marker.read_text(), "untouched")

    def test_modified_capture_fails_hash_verification(self):
        with peer(lambda c: c.sendall(b"ok")) as port:
            self.capture(port, [{"op": "read", "connection": "main", "size": 2}])
        (self.root / "capture/report.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Checksum"):
            verify_capture(self.root / "capture")

    def test_connect_retains_addresses_for_packet_correlation(self):
        with peer(lambda c: c.sendall(b"x")) as port:
            report = self.capture(
                port, [{"op": "read", "connection": "main", "size": 1}]
            )
        event = report["events"][0]
        self.assertEqual(event["peer_address"], ["127.0.0.1", port])
        self.assertEqual(event["local_address"][0], "127.0.0.1")
        self.assertGreater(event["local_address"][1], 0)

    def test_half_close_preserves_receive_direction(self):
        def respond(connection):
            self.assertEqual(connection.recv(1), b"")
            connection.sendall(b"after-fin")

        with peer(respond) as port:
            report = self.capture(
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
        self.assertEqual(report["status"], "completed")
        self.assertIn("shutdown_write", [e["event"] for e in report["events"]])

    def test_quiet_window_is_bounded_and_connection_remains_usable(self):
        def respond(connection):
            self.assertEqual(connection.recv(1), b"x")
            connection.sendall(b"y")

        with peer(respond) as port:
            report = self.capture(
                port,
                [
                    {"op": "expect_quiet", "connection": "main", "timeout": 0.02},
                    {"op": "send", "connection": "main", "hex": "78"},
                    {"op": "read", "connection": "main", "size": 1, "expect_hex": "79"},
                ],
            )
        self.assertEqual(report["status"], "completed")
        self.assertIn("quiet", [e["event"] for e in report["events"]])

    def test_quiet_window_rejects_eof_and_keeps_unexpected_bytes(self):
        for value in [b"", b"unexpected"]:
            with (
                self.subTest(value=value),
                peer(lambda c, value=value: c.sendall(value)) as port,
            ):
                plan = self.plan(
                    port, [{"op": "expect_quiet", "connection": "main", "timeout": 0.2}]
                )
                report = run_plan(
                    plan, self.binary, self.root / ("quiet-" + value.hex())
                )
            self.assertEqual(report["status"], "failed")
            if value:
                self.assertTrue(report["streams"]["main"]["received_hex"])
            else:
                self.assertIn("eof", [e["event"] for e in report["events"]])

    def test_send_after_half_close_is_rejected_before_io(self):
        with self.assertRaisesRegex(ValueError, "write side"):
            run_plan(
                self.plan(
                    1,
                    [
                        {"op": "shutdown_write", "connection": "main"},
                        {"op": "send", "connection": "main", "hex": "78"},
                    ],
                ),
                self.binary,
                self.root / "invalid",
            )


if __name__ == "__main__":
    unittest.main()
