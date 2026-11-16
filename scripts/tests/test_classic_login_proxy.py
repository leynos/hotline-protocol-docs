"""Offline frame and socket-pair controls for the Classic 161 proxy."""

import hashlib
import json
import socket
import threading
import time
from pathlib import Path

import pytest
from classic_login_proxy import (
    Audit,
    ObservationWatchdog,
    RosterState,
    parse_frame,
    relay_frames,
    transform_ack,
)
from test_classic_login_proxy_checks import ClassicLoginProxyChecks, frame

ARMED_TWICE = "Observation watchdog armed twice"
LOG_BOUND = "Aggregate proxy log exceeds bound"
PACKED_ROSTER = bytes.fromhex("004c019e00120007756e6e616d6564")


class ClassicLoginProxyTests(ClassicLoginProxyChecks):
    """Offline controls for the Classic 161 proxy's watchdog, roster and bounds."""

    def test_watchdog_arms_once_after_ack_and_closes_owned_sockets(
        self, owned: list[socket.socket]
    ) -> None:
        """Arm the watchdog once, then close the owned sockets at the cutoff."""
        now = [1_000_000_000]
        control, control_peer = socket.socketpair()
        data, data_peer = socket.socketpair()
        owned.extend((control, control_peer, data, data_peer))

        def close_both() -> None:
            """Close the owned control and data sockets at the cutoff."""
            control.close()
            data.close()

        audit = Audit(time.monotonic() + 2)
        watchdog = ObservationWatchdog(audit, close_both, lambda: now[0])
        assert not watchdog.tick(), "the watchdog fired before arming"
        watchdog.arm(self.source, self.source)
        timer = threading.Thread(target=watchdog.run)
        timer.start()
        with pytest.raises(ValueError, match=ARMED_TWICE):
            watchdog.arm(self.source, self.source)
        now[0] += 27_000_000_000
        assert not watchdog.tick(), "the watchdog fired before its window"
        now[0] += 1_000_000_000
        timer.join(0.5)
        assert not timer.is_alive(), "the watchdog thread did not finish"
        assert control_peer.recv(1) == b"", "the control socket was not closed"
        assert data_peer.recv(1) == b"", "the data socket was not closed"
        watchdog.mark_teardown()
        assert watchdog.receipt()["valid_30_seconds"], "the window is invalid"

    def test_watchdog_cancellation_and_late_cutoff(self) -> None:
        """Keep a cancelled watchdog quiet and invalidate a late cutoff."""
        now = [1_000_000_000]
        audit = Audit(time.monotonic() + 2)
        closed: list[bool] = []
        watchdog = ObservationWatchdog(
            audit, lambda: closed.append(True), lambda: now[0]
        )
        watchdog.arm(self.source, self.source)
        watchdog.cancel()
        now[0] += 40_000_000_000
        assert not watchdog.tick(), "a cancelled watchdog fired"
        assert not closed, "a cancelled watchdog closed sockets"
        late = ObservationWatchdog(audit, lambda: closed.append(True), lambda: now[0])
        late.arm(self.source, self.source)
        now[0] += 31_000_000_000
        assert late.tick(), "the late cutoff did not fire"
        late.mark_teardown()
        assert not late.receipt()["valid_30_seconds"], "a late cutoff was valid"

    def test_one_control_halfclose_does_not_cancel_watchdog(
        self, owned: list[socket.socket]
    ) -> None:
        """Keep the watchdog armed when only one control direction half-closes."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        sink.settimeout(0.1)
        writer.settimeout(1)
        reader.settimeout(1)
        now = [1_000_000_000]

        def close_both() -> None:
            """Close the two relay sockets at the cutoff."""
            source.close()
            sink.close()

        watchdog = ObservationWatchdog(
            Audit(time.monotonic() + 2), close_both, lambda: now[0]
        )
        client_relay = threading.Thread(
            target=relay_frames,
            args=(source, sink, watchdog.audit, "client", None, "baseline"),
        )
        server_errors: list[Exception] = []

        def server_relay() -> None:
            """Relay the server side and keep any expected failure for the test."""
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
        writer.sendall(frame(300, 9, []))
        assert reader.recv(1024) == frame(300, 9, []), "the request differs"
        reader.sendall(frame(0, 9, [(161, b"\x00\x00")], reply=1))
        ack = frame(0, 9, [(161, b"\x00\x00")], reply=1)
        assert writer.recv(1024) == ack, "the controlled ACK was not forwarded"
        writer.shutdown(socket.SHUT_WR)
        assert reader.recv(1) == b"", "the client half-close did not propagate"
        client_relay.join(1)
        assert not client_relay.is_alive(), "the client relay did not finish"
        assert server_thread.is_alive(), "one half-close stopped the server relay"
        now[0] += 28_000_000_000
        assert watchdog.tick(), "the watchdog did not fire"
        server_thread.join(1)
        assert not server_thread.is_alive(), "the server relay did not stop"
        assert server_errors, "the server relay raised no failure"
        assert watchdog.receipt()["state"] == "fired", "the watchdog did not fire"

    def test_late_relay_teardown_invalidates_earlier_socket_close(self) -> None:
        """Invalidate the window when teardown happens after the socket close."""
        now = [1_000_000_000]
        watchdog = ObservationWatchdog(
            Audit(time.monotonic() + 2), lambda: None, lambda: now[0]
        )
        watchdog.arm(self.source, self.source)
        now[0] += 28_000_000_000
        assert watchdog.tick(), "the watchdog did not fire"
        now[0] += 3_000_000_000
        watchdog.mark_teardown()
        receipt = watchdog.receipt()
        assert receipt["last_owned_socket_close_ns"] == 29_000_000_000, "close time"
        assert receipt["relay_teardown_ns"] == 32_000_000_000, "teardown time"
        assert not receipt["valid_30_seconds"], "a late teardown was valid"

    def test_failed_ack_write_never_arms_watchdog(
        self, owned: list[socket.socket]
    ) -> None:
        """Leave the watchdog unarmed when the ACK cannot be written."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        reader.close()
        watchdog = ObservationWatchdog(Audit(time.monotonic() + 2), lambda: None)
        writer.sendall(self.source)
        with pytest.raises(OSError, match="Broken pipe"):
            relay_frames(
                source,
                sink,
                watchdog.audit,
                "server",
                7,
                "baseline",
                on_ack=watchdog.arm,
            )
        assert watchdog.receipt()["ack_sent_monotonic_ns"] is None, "ACK was armed"

    def test_roster_variant_keeps_login_ack_byte_exact(self) -> None:
        """Keep the login ACK of the roster variant byte for byte."""
        native = frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1)
        assert transform_ack(native, 1, "roster-subject-115") == native, "bytes differ"

    def test_roster_first_matching_ack_and_second_unchanged(self) -> None:
        """Rewrite only the first matching roster reply and leave a repeat alone."""
        state = RosterState()
        state.observe_client(frame(300, 3, []))
        state.observe_client(frame(300, 4, []))
        wrong = frame(0, 4, [(300, PACKED_ROSTER)], reply=1)
        assert state.rewrite_reply(wrong) == wrong, "a wrong reply was rewritten"
        native = frame(0, 3, [(300, PACKED_ROSTER)], reply=1)
        expected = frame(
            0, 3, [(300, PACKED_ROSTER), (115, b"fixture-subject")], reply=1
        )
        assert state.rewrite_reply(native) == expected, "the first match differs"
        assert state.rewrite_reply(native) == native, "the repeat was rewritten"

    def test_roster_nonreply_or_error_stays_unchanged(self) -> None:
        """Leave a roster frame unchanged unless it is a success reply."""
        state = RosterState()
        state.observe_client(frame(300, 3, []))
        for raw in (
            frame(0, 3, [(300, PACKED_ROSTER)]),
            frame(0, 3, [(300, PACKED_ROSTER)], reply=1, error=1),
            frame(0, 3, [(300, PACKED_ROSTER)], reply=1, flags=1),
            frame(109, 3, [(300, PACKED_ROSTER)]),
        ):
            assert state.rewrite_reply(raw) == raw, "a non-success frame changed"

    def test_roster_duplicate_115_and_invalid_packed_record_rejected(self) -> None:
        """Refuse a duplicate 115 field or a malformed packed 300 record."""
        for fields in (
            [(300, PACKED_ROSTER), (115, b"already")],
            [(300, PACKED_ROSTER[:-1])],
            [(115, b"subject")],
        ):
            state = RosterState()
            state.observe_client(frame(300, 3, []))
            with pytest.raises(ValueError, match="roster"):
                state.rewrite_reply(frame(0, 3, fields, reply=1))

    def test_existing_115_fails_before_forwarding(
        self, owned: list[socket.socket]
    ) -> None:
        """Refuse an existing 115 field before the roster reply is forwarded."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        reader.settimeout(0.1)
        state = RosterState()
        state.observe_client(frame(300, 3, []))
        login_ack = frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1)
        duplicate = frame(0, 3, [(300, PACKED_ROSTER), (115, b"already")], reply=1)
        writer.sendall(login_ack + duplicate)
        with pytest.raises(ValueError, match="already has 115"):
            relay_frames(
                source,
                sink,
                Audit(time.monotonic() + 2),
                "server",
                1,
                "roster-subject-115",
                roster=state,
            )
        assert reader.recv(1024) == login_ack, "the login ACK was not forwarded"
        with pytest.raises(TimeoutError):
            reader.recv(1)

    def test_roster_preserves_repeated_records_and_other_fields(self) -> None:
        """Keep repeated 300 records and other fields when adding 115."""
        records = [(300, PACKED_ROSTER), (108, b"\0*"), (300, PACKED_ROSTER)]
        state = RosterState()
        reply = frame(0, 3, records, reply=1)
        assert state.rewrite_reply(reply) == reply, "an unmatched reply changed"
        state.observe_client(frame(300, 3, []))
        result = parse_frame(state.rewrite_reply(reply))
        assert result["fields"] == [*records, (115, b"fixture-subject")], "fields"

    def test_frozen_b57_roster_reply_derives_expected_sha(self) -> None:
        """Reproduce the frozen roster reply hash from the retained capture."""
        # scripts/tests sits two levels below the root that holds evidence/.
        corpus = (
            Path(__file__).resolve().parents[2]
            / "evidence/gap-remediation/2026-11-14/classic-server-name-162-01"
        )
        report = json.loads((corpus / "b57/proxy/report.json").read_text())
        request = bytes.fromhex(report["entries"][9]["raw_hex"])
        native = bytes.fromhex(report["entries"][11]["raw_hex"])
        assert (
            hashlib.sha256(native).hexdigest()
            == "0b294b5288d8875469cb8ff3e0985a3200b538c0caf30643869183774e9ad209"
        ), "the retained native reply hash differs"
        state = RosterState()
        state.observe_client(request)
        forwarded = state.rewrite_reply(native)
        assert (
            hashlib.sha256(forwarded).hexdigest()
            == "74b95dd00831a09c9ba59ba2633d05d5a739a70b9cea48c9c5bb5a7913f336fa"
        ), "the derived roster reply hash differs"

    def test_roster_socketpair_correlates_before_forwarding(
        self, owned: list[socket.socket]
    ) -> None:
        """Correlate the roster request and reply across both relay directions."""
        client, client_writer = socket.socketpair()
        server, server_writer = socket.socketpair()
        owned.extend((client, client_writer, server, server_writer))
        client.settimeout(0.1)
        server.settimeout(0.1)
        client_writer.settimeout(1)
        server_writer.settimeout(1)
        audit = Audit(time.monotonic() + 2)
        state = RosterState()
        failures: list[Exception] = []

        def run(src: socket.socket, dst: socket.socket, label: str) -> None:
            """Relay one direction and record any failure for the test."""
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
            except Exception as exc:  # ruff: ignore[blind-except]  # pylint: disable=broad-exception-caught  # the test records every thread failure so that none passes unseen
                failures.append(exc)

        client_thread = threading.Thread(target=run, args=(client, server, "client"))
        server_thread = threading.Thread(target=run, args=(server, client, "server"))
        client_thread.start()
        server_thread.start()
        server_writer.sendall(frame(0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1))
        assert client_writer.recv(1024) == frame(
            0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1
        ), "the login ACK differs"
        client_writer.sendall(frame(300, 3, []))
        assert server_writer.recv(1024) == frame(300, 3, []), "the request differs"
        server_writer.sendall(frame(0, 3, [(300, PACKED_ROSTER)], reply=1))
        expected = frame(
            0, 3, [(300, PACKED_ROSTER), (115, b"fixture-subject")], reply=1
        )
        assert client_writer.recv(1024) == expected, "the roster reply differs"
        client_writer.shutdown(socket.SHUT_WR)
        server_writer.shutdown(socket.SHUT_WR)
        client_thread.join(1)
        server_thread.join(1)
        assert not client_thread.is_alive(), "the client relay did not finish"
        assert not server_thread.is_alive(), "the server relay did not finish"
        assert not failures, "a relay thread failed"

    def test_deadline_and_log_bounds_fail(self) -> None:
        """Refuse a record after the deadline and an entry over the log bound."""
        audit = Audit(time.monotonic() - 1)
        with pytest.raises(TimeoutError):
            audit.record("test", b"x", b"x")
        audit = Audit(time.monotonic() + 2, max_log=50)
        with pytest.raises(ValueError, match=LOG_BOUND):
            audit.record("test", b"x" * 100, b"x" * 100)
