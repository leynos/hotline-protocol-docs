"""Reject conflated native/fixture evidence and unsupported receiver claims."""

import copy
import dataclasses as dc
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_plan import packet, payload
from native_wire_names import (
    FIELD_SERVER_NAME,
    FIELD_USER_RECORD,
    FRAME_HEADER_BYTES,
    HANDSHAKE_REPLY_BYTES,
)
from pcap_tcp import read_packets
from serve_shx_fixture import fixture_frames
from shx_syscalls import socket_io
from verify_native_shx import check_packets, check_semantics, fields, frames, sha
from verify_native_shx_extras import receiver, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-shx-02"
)
NATIVE_SESSIONS = 3
RECEIVER_SESSIONS = 4
RECEIVER_PORT = frozenset({15510})
REPLY_LENGTH = HANDSHAKE_REPLY_BYTES + FRAME_HEADER_BYTES
CHAT_LINE = b"mothra-shx-basic-chat"


@dc.dataclass(frozen=True, slots=True)
class Extras:
    """The packet captures, replayed native frames and source hashes of the corpus.

    Attributes
    ----------
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    original : dict[str, bytes]
        The native frames that the fixture replays.
    sources : set[str]
        The hashes of the capture sources.
    """

    host: list[dict[str, typ.Any]]
    guest: list[dict[str, typ.Any]]
    original: dict[str, bytes]
    sources: set[str]

    def receive(
        self,
        case: Path,
        server: Path,
        original: dict[str, bytes] | None = None,
    ) -> dict[str, typ.Any]:
        """Check a receiver session against this corpus.

        Returns
        -------
        dict[str, typing.Any]
            The observation of the receiver session.
        """
        return receiver(
            case,
            server,
            self.host,
            self.original if original is None else original,
            self.sources,
        )


@pytest.fixture(scope="module")
def extras() -> Extras:
    """Read the packet captures, replayed frames and source hashes of the corpus.

    Returns
    -------
    Extras
        The corpus inputs that the tests share.
    """
    return Extras(
        read_packets(BATCH / "host.pcap"),
        read_packets(BATCH / "guest.pcap"),
        fixture_frames(BATCH.parent),
        {sha(p) for p in (BATCH / "sources").iterdir()},
    )


class PeerExtraTests:
    """Reject conflated native/fixture evidence and unsupported receiver claims."""

    def test_all_native_and_controlled_receiver_cases(self) -> None:
        """The retained corpus verifies, with its native and receiver sessions."""
        result = verify(BATCH)
        assert (
            result["native_sessions"],
            result["controlled_receiver_sessions"],
        ) == (NATIVE_SESSIONS, RECEIVER_SESSIONS), "expected three and four sessions"

    def test_actual_native162_is_not_utf8_reencoded(self, extras: Extras) -> None:
        """A server name re-encoded as UTF-8 is refused as a login extra."""
        case = BATCH / "captures/macroman"
        connections = check_packets(case, extras.host, extras.guest)
        original = connections[0]["received"]
        ack = frames(original[HANDSHAKE_REPLY_BYTES:])[0]
        values = fields(ack)
        values[FIELD_SERVER_NAME] = b"mothra-peer-" + "ö".encode()
        changed = bytes.fromhex(packet(0, 1, payload(list(values.items())), reply=1))
        connections[0]["received"] = (
            original[:HANDSHAKE_REPLY_BYTES]
            + changed
            + original[REPLY_LENGTH + ack["data_size"] :]
        )
        agreement = (
            (BATCH.parent / "native-agreement-01/original-agreement.data")
            .read_bytes()
            .replace(b"\r\n", b"\r")
        )
        with pytest.raises(ValueError, match="login extras differ"):
            check_semantics(
                case,
                connections,
                agreement,
                kind="basic-empty-name",
                login_name=b"mothra-peer-\x9a",
            )

    def test_unknown_banner_must_be_dumped_exactly(
        self, extras: Extras, tmp_path: Path
    ) -> None:
        """A banner dump that is not the exact native frame is refused."""
        case = tmp_path / "banner"
        shutil.copytree(BATCH / "receivers/banner", case)
        (case / "work/hx.dump").write_bytes(b"not the banner")
        with pytest.raises(ValueError, match="banner dump differs"):
            extras.receive(case, BATCH / "fixture-servers/banner")

    def test_subject_addition_does_not_replace_native_roster_records(
        self, extras: Extras
    ) -> None:
        """A roster that replaces a native record with the subject is refused."""
        original = copy.deepcopy(extras.original)
        roster = frames(original["roster"])[0]
        value = bytes.fromhex(roster["fields"][0]["hex"])
        original["roster"] = bytes.fromhex(
            packet(0, 2, payload([(FIELD_USER_RECORD, b"\0\0" + value[2:])]), reply=1)
        )
        with pytest.raises(ValueError, match="native roster bytes differ"):
            extras.receive(
                BATCH / "receivers/subject", BATCH / "fixture-servers/subject", original
            )

    def test_controlled_listener_cannot_be_claimed_as_native_execution(
        self, extras: Extras, tmp_path: Path
    ) -> None:
        """A fixture report labelled as the native oracle is refused."""
        report = json.loads((BATCH / "fixture-servers/control/report.json").read_text())
        report["profile"] = "native-mac-oracle"
        (tmp_path / "report.json").write_text(json.dumps(report))
        with pytest.raises(ValueError, match="controlled fixture report"):
            extras.receive(BATCH / "receivers/control", tmp_path)

    def test_control_session_cannot_be_dropped_from_the_matrix(
        self, tmp_path: Path
    ) -> None:
        """A manifest without the control receiver case is refused."""
        manifest = json.loads((BATCH / "manifest.json").read_text())
        manifest["receiver_cases"].remove("control")
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
        for name in manifest["native_cases"]:
            (tmp_path / "captures" / name).mkdir(parents=True)
        with pytest.raises(ValueError, match="receiver inventory differs"):
            verify(tmp_path)

    def test_fixture_port_requires_explicit_analysis_scope(self) -> None:
        """The fixture port is refused unless the analysis names it."""
        trace = (BATCH / "receivers/control/syscalls.log").read_text()
        with pytest.raises(ValueError, match="Unexpected TCP fixture endpoint"):
            socket_io(trace)
        assert socket_io(trace, server_ports=RECEIVER_PORT), "expected socket records"

    def test_post_banner_chat_must_match_independent_packets(
        self, extras: Extras, tmp_path: Path
    ) -> None:
        """A changed chat byte in the trace is refused against the host packets."""
        case = tmp_path / "banner"
        shutil.copytree(BATCH / "receivers/banner", case)
        path = case / "syscalls.log"
        text = path.read_text()
        marker = "".join(f"\\x{b:02x}" for b in CHAT_LINE)
        lines = text.splitlines(keepends=True)
        found = False
        for index, line in enumerate(lines):
            if all(token in line for token in ("write(", "<TCP:", marker)):
                lines[index] = line.replace(marker, marker[:-2] + "55")
                found = True
        assert found, "expected a traced write of the chat line"
        path.write_text("".join(lines))
        with pytest.raises(
            ValueError, match="Independent receiver packet bytes differ"
        ):
            extras.receive(case, BATCH / "fixture-servers/banner")
