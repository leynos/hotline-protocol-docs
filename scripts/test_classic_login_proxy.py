"""Offline frame and socket-pair controls for the Classic 161 proxy."""

import hashlib
import socket
import struct
import subprocess
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from classic_login_proxy import (
    Audit,
    ObservationWatchdog,
    RosterState,
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
    flags: int = 0,
    error: int = 0,
    total: int | None = None,
) -> bytes:
    body = struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in fields
    )
    return (
        struct.pack(
            ">BBHIIII",
            flags,
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

    def test_server_name_162_has_canonical_fields_and_lengths(self) -> None:
        native = bytes.fromhex(
            "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
        )
        expected = bytes.fromhex(
            "0001000000000001000000000000002000000020000300a0000200be"
            "00a10002000000a2000e666978747572652d6e6174697665"
        )
        output = transform_ack(native, 1, "server-name-162")
        parsed = parse_frame(output)
        self.assertEqual(output, expected)
        self.assertEqual(len(output), 52)
        self.assertEqual(
            parsed["fields"],
            [
                (160, bytes.fromhex("00be")),
                (161, b"\0\0"),
                (162, b"fixture-native"),
            ],
        )
        self.assertEqual(
            (
                parsed["flags"],
                parsed["is_reply"],
                parsed["type"],
                parsed["id"],
                parsed["error"],
            ),
            (0, 1, 0, 1, 0),
        )
        self.assertEqual((parsed["total_size"], parsed["data_size"]), (32, 32))
        self.assertEqual(
            hashlib.sha256(output).hexdigest(),
            "3f5185b7bc222e684697fd2fce46ff0f625bc13ddf301e8a787bfe47594caedb",
        )

    def test_server_name_162_rejects_existing_native_field_without_forwarding(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "already contains field 162"):
            transform_ack(self.source, 7, "server-name-162")
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        reader.settimeout(0.05)
        writer.sendall(self.source)
        with self.assertRaisesRegex(ValueError, "already contains field 162"):
            relay_frames(
                source,
                sink,
                Audit(time.monotonic() + 1),
                "server",
                7,
                "server-name-162",
            )
        with self.assertRaises(TimeoutError):
            reader.recv(1)

    def test_existing_variant_ack_hashes_remain_frozen(self) -> None:
        native = bytes.fromhex(
            "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
        )
        expected = {
            "baseline": "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0",
            "omit-161": "4b6b35015db432791da28371985d8733859a78ffec32be679b9d7b073ec4b7a3",
            "one-byte-161": "904b105c30b784c1b2146cf4c86c04f3ce4f4651905822d76400ffd4d82dc1df",
            "four-byte-161": "32ce979fc0b1b2b23d13761324f09a2c0267d2f7e2898d9c4dc475fdcfeb5827",
        }
        for variant, expected_sha in expected.items():
            with self.subTest(variant=variant):
                self.assertEqual(
                    hashlib.sha256(transform_ack(native, 1, variant)).hexdigest(),
                    expected_sha,
                )

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

    def test_unprivileged_namespace_guard_uses_socket_view(self) -> None:
        def stat(path: str) -> SimpleNamespace:
            if path == "/proc/1/ns/net":
                raise PermissionError("UID1000 cannot inspect proc1")
            self.assertEqual(path, "/proc/self/ns/net")
            return SimpleNamespace(st_ino=42)

        with (
            patch("classic_login_proxy.os.stat", side_effect=stat),
            patch(
                "classic_login_proxy.Path.iterdir",
                return_value=iter((Path("lo"), Path("eth0"))),
            ),
            patch("classic_login_proxy.socket.if_nameindex", return_value=[(1, "lo")]),
            patch(
                "classic_login_proxy.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "[]", ""),
            ) as routes,
        ):
            self.assertEqual(namespace_guard(42, 1), 42)
            self.assertEqual(routes.call_count, 2)

    def test_namespace_guard_rejects_wrong_identity_and_interfaces(self) -> None:
        with self.assertRaises(ValueError):
            namespace_guard(42, 42)
        with (
            patch(
                "classic_login_proxy.os.stat", return_value=SimpleNamespace(st_ino=42)
            ),
            self.assertRaisesRegex(ValueError, "identity differs"),
        ):
            namespace_guard(43, 1)
        with (
            patch(
                "classic_login_proxy.os.stat", return_value=SimpleNamespace(st_ino=42)
            ),
            patch(
                "classic_login_proxy.socket.if_nameindex",
                return_value=[(1, "lo"), (2, "eth0")],
            ),
            self.assertRaisesRegex(ValueError, "non-loopback interface"),
        ):
            namespace_guard(42, 1)

    def test_namespace_guard_rejects_nonlocal_route(self) -> None:
        with (
            patch(
                "classic_login_proxy.os.stat", return_value=SimpleNamespace(st_ino=42)
            ),
            patch("classic_login_proxy.socket.if_nameindex", return_value=[(1, "lo")]),
            patch(
                "classic_login_proxy.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, '[{"dst":"default"}]', ""
                ),
            ),
            self.assertRaisesRegex(ValueError, "nonlocal route"),
        ):
            namespace_guard(42, 1)

    def test_watchdog_arms_once_after_ack_and_closes_owned_sockets(self) -> None:
        now = [1_000_000_000]
        control, control_peer = socket.socketpair()
        data, data_peer = socket.socketpair()
        for peer in (control, control_peer, data, data_peer):
            self.addCleanup(peer.close)
        audit = Audit(time.monotonic() + 2)
        watchdog = ObservationWatchdog(
            audit, lambda: (control.close(), data.close()), lambda: now[0]
        )
        self.assertFalse(watchdog.tick())
        watchdog.arm(self.source, self.source)
        timer = threading.Thread(target=watchdog.run)
        timer.start()
        with self.assertRaises(ValueError):
            watchdog.arm(self.source, self.source)
        now[0] += 27_000_000_000
        self.assertFalse(watchdog.tick())
        now[0] += 1_000_000_000
        timer.join(0.5)
        self.assertFalse(timer.is_alive())
        self.assertEqual(control_peer.recv(1), b"")
        self.assertEqual(data_peer.recv(1), b"")
        watchdog.mark_teardown()
        self.assertTrue(watchdog.receipt()["valid_30_seconds"])

    def test_watchdog_cancellation_and_late_cutoff(self) -> None:
        now = [1_000_000_000]
        audit = Audit(time.monotonic() + 2)
        closed = []
        watchdog = ObservationWatchdog(
            audit, lambda: closed.append(True), lambda: now[0]
        )
        watchdog.arm(self.source, self.source)
        watchdog.cancel()
        now[0] += 40_000_000_000
        self.assertFalse(watchdog.tick())
        self.assertEqual(closed, [])
        late = ObservationWatchdog(audit, lambda: closed.append(True), lambda: now[0])
        late.arm(self.source, self.source)
        now[0] += 31_000_000_000
        self.assertTrue(late.tick())
        late.mark_teardown()
        self.assertFalse(late.receipt()["valid_30_seconds"])

    def test_one_control_halfclose_does_not_cancel_watchdog(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        sink.settimeout(0.1)
        writer.settimeout(1)
        reader.settimeout(1)
        now = [1_000_000_000]
        watchdog = ObservationWatchdog(
            Audit(time.monotonic() + 2),
            lambda: (source.close(), sink.close()),
            lambda: now[0],
        )
        client_relay = threading.Thread(
            target=relay_frames,
            args=(source, sink, watchdog.audit, "client", None, "baseline"),
        )
        server_errors: list[Exception] = []

        def server_relay() -> None:
            try:
                relay_frames(
                    sink,
                    source,
                    watchdog.audit,
                    "server",
                    9,
                    "baseline",
                    on_ack=watchdog.arm,
                )
            except (OSError, RuntimeError) as exc:
                server_errors.append(exc)

        server_thread = threading.Thread(target=server_relay)
        client_relay.start()
        server_thread.start()
        request = frame(300, 9, [])
        writer.sendall(request)
        self.assertEqual(reader.recv(1024), request)
        ack = frame(0, 9, [(161, b"\x00\x00")], reply=1)
        reader.sendall(ack)
        self.assertEqual(writer.recv(1024), ack)
        writer.shutdown(socket.SHUT_WR)
        self.assertEqual(reader.recv(1), b"")
        client_relay.join(1)
        self.assertFalse(client_relay.is_alive())
        self.assertTrue(server_thread.is_alive())
        now[0] += 28_000_000_000
        self.assertTrue(watchdog.tick())
        server_thread.join(1)
        self.assertFalse(server_thread.is_alive())
        self.assertTrue(server_errors)
        self.assertEqual(watchdog.receipt()["state"], "fired")

    def test_late_relay_teardown_invalidates_earlier_socket_close(self) -> None:
        now = [1_000_000_000]
        watchdog = ObservationWatchdog(
            Audit(time.monotonic() + 2), lambda: None, lambda: now[0]
        )
        watchdog.arm(self.source, self.source)
        now[0] += 28_000_000_000
        self.assertTrue(watchdog.tick())
        now[0] += 3_000_000_000
        watchdog.mark_teardown()
        receipt = watchdog.receipt()
        self.assertEqual(receipt["last_owned_socket_close_ns"], 29_000_000_000)
        self.assertEqual(receipt["relay_teardown_ns"], 32_000_000_000)
        self.assertFalse(receipt["valid_30_seconds"])

    def test_failed_ack_write_never_arms_watchdog(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        reader.close()
        watchdog = ObservationWatchdog(Audit(time.monotonic() + 2), lambda: None)
        writer.sendall(self.source)
        with self.assertRaises(OSError):
            relay_frames(
                source,
                sink,
                watchdog.audit,
                "server",
                7,
                "baseline",
                on_ack=watchdog.arm,
            )
        self.assertIsNone(watchdog.receipt()["ack_sent_monotonic_ns"])

    def test_roster_variant_keeps_login_ack_byte_exact(self) -> None:
        native = frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1)
        self.assertEqual(transform_ack(native, 1, "roster-subject-115"), native)

    def test_roster_first_matching_ack_and_second_unchanged(self) -> None:
        state = RosterState()
        first = frame(300, 3, [])
        second = frame(300, 4, [])
        state.observe_client(first)
        state.observe_client(second)
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        wrong = frame(0, 4, [(300, packed)], reply=1)
        self.assertEqual(state.rewrite_reply(wrong), wrong)
        native = frame(0, 3, [(300, packed)], reply=1)
        expected = frame(0, 3, [(300, packed), (115, b"fixture-subject")], reply=1)
        self.assertEqual(state.rewrite_reply(native), expected)
        self.assertEqual(state.rewrite_reply(native), native)

    def test_roster_nonreply_or_error_stays_unchanged(self) -> None:
        state = RosterState()
        state.observe_client(frame(300, 3, []))
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        for raw in (
            frame(0, 3, [(300, packed)]),
            frame(0, 3, [(300, packed)], reply=1, error=1),
            frame(0, 3, [(300, packed)], reply=1, flags=1),
            frame(109, 3, [(300, packed)]),
        ):
            with self.subTest(raw=raw.hex()):
                self.assertEqual(state.rewrite_reply(raw), raw)

    def test_roster_duplicate_115_and_invalid_packed_record_rejected(self) -> None:
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        for fields in (
            [(300, packed), (115, b"already")],
            [(300, packed[:-1])],
            [(115, b"subject")],
        ):
            with self.subTest(fields=fields):
                state = RosterState()
                state.observe_client(frame(300, 3, []))
                with self.assertRaisesRegex(ValueError, "roster"):
                    state.rewrite_reply(frame(0, 3, fields, reply=1))

    def test_existing_115_fails_before_forwarding(self) -> None:
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        for peer in (source, writer, sink, reader):
            self.addCleanup(peer.close)
        source.settimeout(0.1)
        reader.settimeout(0.1)
        state = RosterState()
        state.observe_client(frame(300, 3, []))
        login_ack = frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1)
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        duplicate = frame(0, 3, [(300, packed), (115, b"already")], reply=1)
        writer.sendall(login_ack + duplicate)
        with self.assertRaisesRegex(ValueError, "already has 115"):
            relay_frames(
                source,
                sink,
                Audit(time.monotonic() + 2),
                "server",
                1,
                "roster-subject-115",
                roster=state,
            )
        self.assertEqual(reader.recv(1024), login_ack)
        with self.assertRaises(TimeoutError):
            reader.recv(1)

    def test_roster_preserves_repeated_records_and_other_fields(self) -> None:
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        records = [(300, packed), (108, b"\0*"), (300, packed)]
        state = RosterState()
        reply = frame(0, 3, records, reply=1)
        self.assertEqual(state.rewrite_reply(reply), reply)
        state.observe_client(frame(300, 3, []))
        result = parse_frame(state.rewrite_reply(reply))
        self.assertEqual(result["fields"], records + [(115, b"fixture-subject")])

    def test_frozen_b57_roster_reply_derives_expected_sha(self) -> None:
        import json

        corpus = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-14/classic-server-name-162-01"
        )
        report = json.loads((corpus / "b57/proxy/report.json").read_text())
        request = bytes.fromhex(report["entries"][9]["raw_hex"])
        native = bytes.fromhex(report["entries"][11]["raw_hex"])
        self.assertEqual(
            hashlib.sha256(native).hexdigest(),
            "0b294b5288d8875469cb8ff3e0985a3200b538c0caf30643869183774e9ad209",
        )
        state = RosterState()
        state.observe_client(request)
        forwarded = state.rewrite_reply(native)
        self.assertEqual(
            hashlib.sha256(forwarded).hexdigest(),
            "74b95dd00831a09c9ba59ba2633d05d5a739a70b9cea48c9c5bb5a7913f336fa",
        )

    def test_roster_socketpair_correlates_before_forwarding(self) -> None:
        client, client_writer = socket.socketpair()
        server, server_writer = socket.socketpair()
        for peer in (client, client_writer, server, server_writer):
            self.addCleanup(peer.close)
        client.settimeout(0.1)
        server.settimeout(0.1)
        client_writer.settimeout(1)
        server_writer.settimeout(1)
        audit = Audit(time.monotonic() + 2)
        state = RosterState()
        failures: list[Exception] = []

        def run(src: socket.socket, dst: socket.socket, label: str) -> None:
            try:
                relay_frames(
                    src,
                    dst,
                    audit,
                    label,
                    1 if label == "server" else None,
                    "roster-subject-115",
                    roster=state,
                )
            except Exception as exc:  # noqa: BLE001 - test captures thread failures
                failures.append(exc)

        client_thread = threading.Thread(target=run, args=(client, server, "client"))
        server_thread = threading.Thread(target=run, args=(server, client, "server"))
        client_thread.start()
        server_thread.start()
        login_ack = frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1)
        server_writer.sendall(login_ack)
        self.assertEqual(client_writer.recv(1024), login_ack)
        request = frame(300, 3, [])
        client_writer.sendall(request)
        self.assertEqual(server_writer.recv(1024), request)
        packed = bytes.fromhex("004c019e00120007756e6e616d6564")
        raw = frame(0, 3, [(300, packed)], reply=1)
        expected = frame(0, 3, [(300, packed), (115, b"fixture-subject")], reply=1)
        server_writer.sendall(raw)
        self.assertEqual(client_writer.recv(1024), expected)
        client_writer.shutdown(socket.SHUT_WR)
        server_writer.shutdown(socket.SHUT_WR)
        client_thread.join(1)
        server_thread.join(1)
        self.assertFalse(client_thread.is_alive() or server_thread.is_alive())
        self.assertEqual(failures, [])

    def test_deadline_and_log_bounds_fail(self) -> None:
        audit = Audit(time.monotonic() - 1)
        with self.assertRaises(TimeoutError):
            audit.record("test", b"x", b"x")
        audit = Audit(time.monotonic() + 2, max_log=50)
        with self.assertRaises(ValueError):
            audit.record("test", b"x" * 100, b"x" * 100)


if __name__ == "__main__":
    unittest.main()
