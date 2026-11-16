"""Frame builder, fixtures and the first half of the Classic 161 proxy controls."""

import hashlib
import socket
import struct
import threading
import time
import typing as typ
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from classic_login_proxy import (
    Audit,
    namespace_guard,
    parse_frame,
    relay_data,
    relay_frames,
    transform_ack,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

MALFORMED = "Fragmented, oversized or malformed control frame"
NOT_LOGIN_ACK = "First server frame is not successful Login107 ACK"
ZERO_161 = "Native 161 source is not exactly two zero bytes"
DISTINCT = "Expected and host namespace inodes must be distinct"
NATIVE_ACK = bytes.fromhex(
    "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
)


def frame(
    kind: int, identifier: int, fields: list[tuple[int, bytes]], **header: int
) -> bytes:
    """Build one control frame from its header keywords and its field list.

    Returns
    -------
    bytes
        The frame, whose total size is its body length unless ``total`` is given.
    """
    body = struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in fields
    )
    return (
        struct.pack(
            ">BBHIIII",
            header.get("flags", 0),
            header.get("reply", 0),
            kind,
            identifier,
            header.get("error", 0),
            header.get("total", len(body)),
            len(body),
        )
        + body
    )


class ClassicLoginProxyChecks:
    """Offline checks of the Classic 161 proxy's frames, namespace and relays.

    The methods are collected through ``ClassicLoginProxyTests``, which inherits
    them. This class is not named as a test class, so pytest does not collect it
    on its own.
    """

    @pytest.fixture
    def owned(self) -> cabc.Iterator[list[socket.socket]]:
        """Register the sockets that a test owns, then close them however it ends.

        Yields
        ------
        list[socket.socket]
            The list to which the test adds its sockets.
        """
        peers: list[socket.socket] = []
        yield peers
        for peer in peers:
            peer.close()

    def setup_method(self) -> None:
        """Build the native ACK that most controls start from."""
        self.source = frame(
            0, 7, [(160, b"\x00\xbe"), (161, b"\x00\x00"), (162, b"Name")], reply=1
        )

    def test_variants_preserve_unmodified_fields_order_and_header(self) -> None:
        """Keep the unmodified fields, their order and the header of each variant."""
        cases = {
            "baseline": b"\x00\x00",
            "omit-161": None,
            "one-byte-161": b"\x00",
            "four-byte-161": b"\x00" * 4,
        }
        for variant, value in cases.items():
            output = transform_ack(self.source, 7, variant)
            parsed = parse_frame(output)
            expected = [(160, b"\x00\xbe"), (162, b"Name")]
            if value is not None:
                expected.insert(1, (161, value))
            assert parsed["fields"] == expected, f"{variant}: fields differ"
            header = (parsed["type"], parsed["id"], parsed["is_reply"], parsed["error"])
            assert header == (0, 7, 1, 0), f"{variant}: header differs"
            assert parsed["total_size"] == len(output) - 20, f"{variant}: size differs"
            assert parsed["data_size"] == parsed["total_size"], f"{variant}: data size"
            if variant == "baseline":
                assert output == self.source, "baseline output differs from its input"

    def test_server_name_162_has_canonical_fields_and_lengths(self) -> None:
        """Rebuild the server-name variant to its canonical bytes and lengths."""
        expected = bytes.fromhex(
            "0001000000000001000000000000002000000020000300a0000200be"
            "00a10002000000a2000e666978747572652d6e6174697665"
        )
        output = transform_ack(NATIVE_ACK, 1, "server-name-162")
        parsed = parse_frame(output)
        assert output == expected, "the rebuilt ACK bytes differ"
        assert len(output) == 52, "the rebuilt ACK length differs"
        assert parsed["fields"] == [
            (160, bytes.fromhex("00be")),
            (161, b"\0\0"),
            (162, b"fixture-native"),
        ], "the rebuilt fields differ"
        header = (
            parsed["flags"],
            parsed["is_reply"],
            parsed["type"],
            parsed["id"],
            parsed["error"],
        )
        assert header == (0, 1, 0, 1, 0), "the rebuilt header differs"
        assert (parsed["total_size"], parsed["data_size"]) == (32, 32), "sizes differ"
        assert (
            hashlib.sha256(output).hexdigest()
            == "3f5185b7bc222e684697fd2fce46ff0f625bc13ddf301e8a787bfe47594caedb"
        ), "the rebuilt ACK hash differs"

    def test_server_name_162_rejects_existing_native_field_without_forwarding(
        self, owned: list[socket.socket]
    ) -> None:
        """Refuse a 162 rewrite that would duplicate a native 162 field."""
        with pytest.raises(ValueError, match="already contains field 162"):
            transform_ack(self.source, 7, "server-name-162")
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        reader.settimeout(0.05)
        writer.sendall(self.source)
        with pytest.raises(ValueError, match="already contains field 162"):
            relay_frames(
                source,
                sink,
                Audit(time.monotonic() + 1),
                "server",
                7,
                "server-name-162",
            )
        with pytest.raises(TimeoutError):
            reader.recv(1)

    def test_existing_variant_ack_hashes_remain_frozen(self) -> None:
        """Keep the output hash of each existing variant unchanged."""
        expected = {
            "baseline": (
                "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0"
            ),
            "omit-161": (
                "4b6b35015db432791da28371985d8733859a78ffec32be679b9d7b073ec4b7a3"
            ),
            "one-byte-161": (
                "904b105c30b784c1b2146cf4c86c04f3ce4f4651905822d76400ffd4d82dc1df"
            ),
            "four-byte-161": (
                "32ce979fc0b1b2b23d13761324f09a2c0267d2f7e2898d9c4dc475fdcfeb5827"
            ),
        }
        for variant, expected_sha in expected.items():
            digest = hashlib.sha256(transform_ack(NATIVE_ACK, 1, variant)).hexdigest()
            assert digest == expected_sha, f"{variant}: frozen hash differs"

    def test_unknown_header_flags_preserved_by_baseline(self) -> None:
        """Forward an ACK with unknown header flags unchanged under baseline."""
        marked = b"\x80" + self.source[1:]
        assert transform_ack(marked, 7, "baseline") == marked, "flags were not kept"

    def test_wrong_native_value_id_and_status_fail(self) -> None:
        """Refuse an ACK with the wrong 161 value, ID, status or type."""
        cases = (
            (frame(0, 7, [(161, b"\x00\x01")], reply=1), ZERO_161),
            (frame(0, 8, [(161, b"\x00\x00")], reply=1), NOT_LOGIN_ACK),
            (frame(0, 7, [(161, b"\x00\x00")], reply=1, error=1), NOT_LOGIN_ACK),
            (frame(109, 7, [(161, b"\x00\x00")]), NOT_LOGIN_ACK),
        )
        for raw, message in cases:
            with pytest.raises(ValueError, match=message):
                transform_ack(raw, 7, "omit-161")

    def test_malformed_and_fragmented_frames_fail(self) -> None:
        """Refuse short, fragmented, size-mismatched and duplicated frames."""
        cases = (
            (self.source[:-1], MALFORMED),
            (self.source[:16] + b"\x00\x00\x00\x03" + self.source[20:], MALFORMED),
            (frame(0, 7, [(161, b"\x00\x00")], reply=1, total=99), MALFORMED),
            (
                frame(0, 7, [(161, b"\x00\x00"), (161, b"\x00\x00")], reply=1),
                ZERO_161,
            ),
        )
        for raw, message in cases:
            with pytest.raises(ValueError, match=message):
                transform_ack(raw, 7, "baseline")

    def test_socketpair_passes_other_frames_and_halfclose(
        self, owned: list[socket.socket]
    ) -> None:
        """Relay an unrelated frame across a socket pair, then the half-close."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        sink.settimeout(0.1)
        audit = Audit(time.monotonic() + 2)
        thread = threading.Thread(
            target=relay_frames, args=(source, sink, audit, "client", None, "baseline")
        )
        thread.start()
        raw = frame(300, 11, [])
        writer.sendall(raw)
        writer.shutdown(socket.SHUT_WR)
        assert reader.recv(1024) == raw, "the relayed frame differs"
        assert reader.recv(1) == b"", "the half-close did not propagate"
        thread.join(1)
        assert not thread.is_alive(), "the relay did not finish"
        assert audit.entries[0]["raw_hex"] == raw.hex(), "the audit entry differs"

    def test_mismatched_first_ack_never_forwarded(
        self, owned: list[socket.socket]
    ) -> None:
        """Refuse a mismatched first ACK before anything reaches the client."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        reader.settimeout(0.05)
        writer.sendall(frame(0, 7, [(161, b"\x00\x01")], reply=1))
        with pytest.raises(ValueError, match="Native 161 source"):
            relay_frames(
                source, sink, Audit(time.monotonic() + 1), "server", 7, "omit-161"
            )
        with pytest.raises(TimeoutError):
            reader.recv(1)

    def test_data_bytes_and_halfclose(self, owned: list[socket.socket]) -> None:
        """Relay raw data bytes and propagate the half-close."""
        source, writer = socket.socketpair()
        sink, reader = socket.socketpair()
        owned.extend((source, writer, sink, reader))
        source.settimeout(0.1)
        audit = Audit(time.monotonic() + 2)
        thread = threading.Thread(
            target=relay_data, args=(source, sink, audit, "data-client")
        )
        thread.start()
        writer.sendall(b"HTXF\x00\x01")
        writer.shutdown(socket.SHUT_WR)
        assert reader.recv(16) == b"HTXF\x00\x01", "the data bytes differ"
        assert reader.recv(1) == b"", "the half-close did not propagate"
        thread.join(1)
        assert not thread.is_alive(), "the relay did not finish"

    def test_unprivileged_namespace_guard_uses_socket_view(self) -> None:
        """Check the namespace through the socket view, never through proc1."""

        def stat(path: object, *, follow_symlinks: bool = True) -> SimpleNamespace:
            """Answer the stat of the calling process's network namespace.

            Returns
            -------
            types.SimpleNamespace
                The namespace inode of the calling process.
            """
            assert str(path) == "/proc/self/ns/net", "proc1 was inspected"
            return SimpleNamespace(st_ino=42)

        with (
            mock.patch("os.stat", side_effect=stat),
            mock.patch(
                "classic_login_proxy.Path.iterdir",
                return_value=iter((Path("lo"), Path("eth0"))),
            ),
            mock.patch(
                "classic_login_proxy.socket.if_nameindex", return_value=[(1, "lo")]
            ),
            mock.patch(
                "classic_login_proxy.subprocess.run",
                return_value=SimpleNamespace(stdout="[]"),
            ) as routes,
        ):
            assert namespace_guard(42, 1) == 42, "the namespace inode differs"
            assert routes.call_count == 2, "the route checks differ in number"

    def test_namespace_guard_rejects_wrong_identity_and_interfaces(self) -> None:
        """Refuse equal inodes, a wrong identity and a non-loopback interface."""
        with pytest.raises(ValueError, match=DISTINCT):
            namespace_guard(42, 42)
        with (
            mock.patch("os.stat", return_value=SimpleNamespace(st_ino=42)),
            pytest.raises(ValueError, match="identity differs"),
        ):
            namespace_guard(43, 1)
        with (
            mock.patch("os.stat", return_value=SimpleNamespace(st_ino=42)),
            mock.patch(
                "classic_login_proxy.socket.if_nameindex",
                return_value=[(1, "lo"), (2, "eth0")],
            ),
            pytest.raises(ValueError, match="non-loopback interface"),
        ):
            namespace_guard(42, 1)

    def test_namespace_guard_rejects_nonlocal_route(self) -> None:
        """Refuse a namespace that has a nonlocal route."""
        with (
            mock.patch("os.stat", return_value=SimpleNamespace(st_ino=42)),
            mock.patch(
                "classic_login_proxy.socket.if_nameindex", return_value=[(1, "lo")]
            ),
            mock.patch(
                "classic_login_proxy.subprocess.run",
                return_value=SimpleNamespace(stdout='[{"dst":"default"}]'),
            ),
            pytest.raises(ValueError, match="nonlocal route"),
        ):
            namespace_guard(42, 1)
