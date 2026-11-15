"""Reject identity, byte-preservation and fork-completion overclaims."""

import copy
import dataclasses as dc
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_plan import packet, payload
from native_wire_names import FIELD_VERSION, FRAME_HEADER_BYTES, HANDSHAKE_REPLY_BYTES
from pcap_tcp import read_packets
from shx_syscalls import socket_io
from verify_native_shx import CHAT, check_packets, check_semantics, frames, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-shx-01"
)
CASES = 5
PAIRED_CONNECTIONS = 7
GUEST_CONTROL_PORT = 5500  # the control port, 15500, as the guest sees it
ERROR_BYTE = HANDSHAKE_REPLY_BYTES + 11  # the last byte of the first reply's error word
REPLY_LENGTH = HANDSHAKE_REPLY_BYTES + FRAME_HEADER_BYTES

type Connections = list[dict[str, typ.Any]]


@dc.dataclass(frozen=True, slots=True)
class Peer:
    """The packet captures and agreement text of the retained shx corpus.

    Attributes
    ----------
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    agreement : bytes
        The native agreement text.
    """

    host: list[dict[str, typ.Any]]
    guest: list[dict[str, typ.Any]]
    agreement: bytes

    def connections(self, name: str) -> Connections:
        """Pair the connections of one retained capture with the packets.

        Returns
        -------
        list[dict[str, typing.Any]]
            The paired connections of the capture.
        """
        return check_packets(BATCH / "captures" / name, self.host, self.guest)


@pytest.fixture(scope="module")
def peer() -> Peer:
    """Read the packet captures and the agreement of the retained corpus.

    Returns
    -------
    Peer
        The captures and the agreement text.
    """
    agreement = (
        (BATCH.parent / "native-agreement-01/original-agreement.data")
        .read_bytes()
        .replace(b"\r\n", b"\r")
    )
    return Peer(
        read_packets(BATCH / "host.pcap"), read_packets(BATCH / "guest.pcap"), agreement
    )


class FullPeerTests:
    """Reject identity, byte-preservation and fork-completion overclaims."""

    def test_complete_full_process_corpus(self) -> None:
        """The retained corpus verifies, with its cases and paired connections."""
        result = verify(BATCH)
        assert (result["cases"], result["paired_connections"]) == (
            CASES,
            PAIRED_CONNECTIONS,
        ), "expected five cases and seven paired connections"

    def test_omitted_native161_cannot_pass_as_extra_field_tolerance(
        self, peer: Peer
    ) -> None:
        """A login reply that omits field 161 is refused."""
        name = "basic-empty-name"
        connections = peer.connections(name)
        original = connections[0]["received"]
        ack = frames(original[HANDSHAKE_REPLY_BYTES:])[0]
        boundary = REPLY_LENGTH + ack["data_size"]
        changed = bytes.fromhex(
            packet(0, 1, payload([(FIELD_VERSION, b"\0\xbe")]), reply=1)
        )
        connections[0]["received"] = (
            original[:HANDSHAKE_REPLY_BYTES] + changed + original[boundary:]
        )
        with pytest.raises(ValueError, match="login extras differ"):
            check_semantics(BATCH / "captures" / name, connections, peer.agreement)

    def test_high_bytes_cannot_be_replaced_by_ascii(self, peer: Peer) -> None:
        """Chat bytes whose high bytes became ASCII are refused."""
        name = "ambiguous-text"
        connections = peer.connections(name)
        original = connections[0]["received"]
        assert CHAT in original, "expected the chat bytes in the received stream"
        connections[0]["received"] = original.replace(CHAT, CHAT.replace(b"\x80", b"?"))
        with pytest.raises(ValueError, match="ambiguous chat bytes changed"):
            check_semantics(BATCH / "captures" / name, connections, peer.agreement)

    def test_wrong_password_is_not_reported_as_success(self, peer: Peer) -> None:
        """A failed login whose error is cleared is refused."""
        name = "wrong-password"
        connections = peer.connections(name)
        changed = bytearray(connections[0]["received"])
        changed[ERROR_BYTE] = 0
        connections[0]["received"] = bytes(changed)
        with pytest.raises(ValueError, match="login error differs"):
            check_semantics(BATCH / "captures" / name, connections, peer.agreement)

    def test_terminal_completion_does_not_replace_saved_resource_verification(
        self, peer: Peer, tmp_path: Path
    ) -> None:
        """A wrong saved resource fork is refused although the terminal completed."""
        source = BATCH / "captures/fork-download"
        connections = peer.connections(source.name)
        case = tmp_path / source.name
        shutil.copytree(source, case)
        (case / "work/.resource/mothra-fork-fixture").write_bytes(b"wrong")
        with pytest.raises(ValueError, match="Saved resource fork differs"):
            check_semantics(case, connections, peer.agreement)

    def test_syscall_bytes_must_match_the_independent_guest_capture(
        self, peer: Peer
    ) -> None:
        """A changed guest packet is refused against the traced bytes."""
        changed = copy.deepcopy(peer.guest)
        case = BATCH / "captures/basic-empty-name"
        port = socket_io((case / "syscalls.log").read_text())[0]["client_port"]
        target = next(
            p
            for p in changed
            if p["dst_port"] == GUEST_CONTROL_PORT
            and p["src_port"] == port
            and p["payload_hex"].startswith("54525450")
        )
        target["payload_hex"] = "00" + target["payload_hex"][2:]
        with pytest.raises(ValueError, match="guest peer input differs"):
            check_packets(case, peer.host, changed)

    def test_missing_required_peer_session_is_rejected(self, tmp_path: Path) -> None:
        """A manifest without the wrong-password case is refused."""
        manifest = json.loads((BATCH / "manifest.json").read_text())
        manifest["cases"].remove("wrong-password")
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="corpus inventory differs"):
            verify(tmp_path)

    def test_truncated_strace_strings_are_not_treated_as_complete_bytes(self) -> None:
        """A truncated strace string is refused as an incomplete call."""
        trace = (
            "1 123.000001 read(3<TCP:[127.0.0.1:12345->127.0.0.1:15500]>,"
            ' "\\x61"..., 100) = 20'
        )
        with pytest.raises(ValueError, match="incomplete TCP syscall"):
            socket_io(trace)

    def test_partial_write_uses_only_the_returned_prefix(self) -> None:
        """A partial write contributes only the bytes that were written."""
        trace = (
            "1 123.000001 write(3<TCP:[127.0.0.1:12345->127.0.0.1:15500]>,"
            ' "\\x61\\x62", 2) = 1'
        )
        assert socket_io(trace)[0]["bytes"] == b"a", "expected the one written byte"
