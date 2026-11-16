"""Check the native storage and the stopped-server witness of the live accounts.

The stopped witness shows that the server refused a connection while it was
down; the storage checks tie the stored account records and the catalogue to
the accounts before and after the restart.
"""

import datetime as dt
import json
import typing as typ

import native_live_account_cases as cases
from native_auth_cases import complement
from native_packet_evidence import (
    GUEST_CLIENT_HOST,
    GUEST_SERVER_BASE,
    GUEST_SERVER_HOST,
    MICROSECONDS_PER_SECOND,
    NANOSECONDS_PER_MICROSECOND,
    TCP_RST,
)
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_ATTRIBUTE_LENGTH_OFFSET,
    ACCOUNT_LOGIN_LENGTH_OFFSET,
    ACCOUNT_NAME_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_RECORD_BYTES,
    HANDSHAKE_REQUEST_HEX,
)
from pcap_tcp import direction, lifetime, stream
from protocol_capture import ORACLE_SHA256
from verify_native_core import require
from verify_native_shx import sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

RECORD_VERSION = b"\0\1"
LENGTH_WORD_BYTES = 2
TCP_SYN = 2
STOPPED_ACTIONS = 2
REFUSAL_TEXT = b"No listener"
PRE_RESTART_PATHS = {
    "/Hotline19/Users/m-live27",
    "/Hotline19/Users/m-live27/UserData",
    "/Trash/m-delete27",
    "/Trash/m-delete27/UserData",
    "/Hotline19/Files/m-live27-flush",
}
PHASES = [("native-after-restart", 5), ("native-cleanup", 5), ("native-published", 6)]
PUBLISHED_PATH = "/Hotline19/Files/m-live27-publish"
SERVER_APPLICATION = "/Hotline19/HLserver19"
APPLICATION_PATHS = {SERVER_APPLICATION, "/Hotline19/Prefs"}
RESOURCE_FORK_SHA256 = (
    "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
)


def check_host_handshake(report: Report, host: Packets) -> tuple[Report, int]:
    """Check that the stopped server's host-side bytes are the handshake alone.

    Returns
    -------
    tuple[dict, int]
        The connect event, and the microsecond time of the connection.
    """
    event = next(e for e in report["events"] if e["event"] == "connect")
    source, target = tuple(event["local_address"]), tuple(event["peer_address"])
    when = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
        + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND
    )
    host_packets = lifetime(host, source, target, when)
    require(
        stream(host_packets, source, target).hex()
        == report["streams"]["main"]["sent_hex"]
        == HANDSHAKE_REQUEST_HEX
        and stream(host_packets, target, source) == b"",
        "Stopped host handshake bytes differ",
    )
    return event, when


def stopped(report: Report, host: Packets, guest: Packets) -> None:
    """Check that the stopped native witness failed with a reset and no bytes."""
    require(
        report["status"] == "failed"
        and "ConnectionResetError" in report["error"]
        and report["completed_actions"] == STOPPED_ACTIONS
        and report["frames"] == [],
        "Stopped native witness must remain a reset failure",
    )
    event, when = check_host_handshake(report, host)
    source = tuple(event["local_address"])
    guest_source = (GUEST_CLIENT_HOST, source[1])
    guest_target = (GUEST_SERVER_HOST, GUEST_SERVER_BASE)
    packets = lifetime(guest, guest_source, guest_target, when)
    outgoing = direction(packets, guest_target, guest_source)
    require(
        any(p["flags"] & TCP_RST for p in outgoing)
        and not any(p["flags"] & TCP_SYN for p in outgoing)
        and all(
            p["payload_hex"] == (REFUSAL_TEXT.hex() if p["flags"] & TCP_RST else "")
            for p in packets
        ),
        "Stopped guest must reject SYN without application bytes",
    )


def native_record(deleted: bool) -> bytes:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    """Build the stored account record that the live case leaves for an account.

    Returns
    -------
    bytes
        The 734-byte record of the deleted account, or of the edited one.
    """
    value = bytearray(ACCOUNT_RECORD_BYTES)
    value[: len(RECORD_VERSION)] = RECORD_VERSION
    end = ACCOUNT_ACCESS_OFFSET + ACCESS_BITMAP_BYTES
    value[ACCOUNT_ACCESS_OFFSET:end] = (
        cases.ACCESS if deleted else bytes(ACCESS_BITMAP_BYTES)
    )
    for offset, data in [
        (
            ACCOUNT_NAME_LENGTH_OFFSET,
            b"Delete Target27" if deleted else b"Stored Beta27",
        ),
        (
            ACCOUNT_ATTRIBUTE_LENGTH_OFFSET,
            b"live27" if deleted else b"attribute-only27",
        ),
        (ACCOUNT_LOGIN_LENGTH_OFFSET, b"m-delete27" if deleted else b"m-live27"),
        (
            ACCOUNT_PASSWORD_LENGTH_OFFSET,
            complement(b"delete-pass27" if deleted else b"live-final27"),
        ),
    ]:
        start = offset + LENGTH_WORD_BYTES
        value[offset:start] = len(data).to_bytes(LENGTH_WORD_BYTES, "big")
        value[start : start + len(data)] = data
    return bytes(value)


def check_pre_restart(before: Path) -> list[Report]:
    """Check the catalogue and the stored records before the restart.

    Returns
    -------
    list[dict[str, typing.Any]]
        The catalogue records.
    """
    rows = json.loads((before / "extraction.json").read_text())["records"]
    require(
        {r["path"] for r in rows} == PRE_RESTART_PATHS,
        "Live pre-restart catalogue differs",
    )
    for row in rows:
        if row["path"].endswith("/UserData"):
            require(
                (before / (row["key"] + ".data")).read_bytes()
                == native_record("m-delete27" in row["path"]),
                "Live stored account bytes differ",
            )
    return rows


def check_moved_row(
    stores: tuple[Path, Path], row: Report, moved: dict[str, Report], phase: str
) -> None:
    """Check that one object kept its identity, path and forks through a phase.

    ``stores`` holds the pre-restart directory and the phase's directory.
    """
    before, base = stores
    target = moved[row["catalog"]]
    path = (
        row["path"]
        if phase == "native-after-restart"
        else row["path"]
        .replace("/Hotline19/Users/", "/Trash/")
        .replace("/Hotline19/Files/", "/Trash/")
    )
    require(
        target["path"] == path and target["directory"] == row["directory"],
        "Live persistence/Trash path differs",
    )
    if not row["directory"]:
        for fork in ["data", "rsrc"]:
            require(
                (before / (row["key"] + "." + fork)).read_bytes()
                == (base / (target["key"] + "." + fork)).read_bytes(),
                "Server restart/cleanup changed stored fork",
            )


def check_phase(
    directory: Path, before: Path, rows: list[Report], spec: tuple[str, int]
) -> None:
    """Check one later phase of the catalogue against the pre-restart rows."""
    phase, count = spec
    base = directory / phase
    moved = {
        r["catalog"]: r
        for r in json.loads((base / "extraction.json").read_text())["records"]
    }
    require(
        len(moved) == count and {r["catalog"] for r in rows} <= set(moved),
        "Live post-restart/cleanup identities differ",
    )
    if phase == "native-published":
        extra = [
            r
            for identifier, r in moved.items()
            if identifier not in {r["catalog"] for r in rows}
        ]
        require(
            len(extra) == 1 and extra[0]["path"] == PUBLISHED_PATH,
            "Separate live publisher differs",
        )
    for row in rows:
        check_moved_row((before, base), row, moved, phase)


def check_application(directory: Path) -> None:
    """Check that the restart left the server application and its prefs alone."""
    identities = json.loads(
        (directory / "restart-application-identities.json").read_text()
    )
    require(
        identities["before"] == identities["after"]
        and identities["before"][SERVER_APPLICATION]["data_sha256"] == ORACLE_SHA256
        and identities["before"][SERVER_APPLICATION]["rsrc_sha256"]
        == RESOURCE_FORK_SHA256,
        "Restart application fork identities differ",
    )
    for phase in ["before", "after"]:
        base = directory / ("native-application-" + phase)
        records = json.loads((base / "extraction.json").read_text())["records"]
        require(
            {r["path"] for r in records} == APPLICATION_PATHS,
            "Application metadata inventory differs",
        )
        for row in records:
            require(
                identities[phase][row["path"]]["catalog"] == row["catalog"],
                "Application catalogue identity differs",
            )
            if row["path"].endswith("/Prefs"):
                require(
                    all(
                        sha(base / (row["key"] + "." + fork))
                        == identities[phase][row["path"]][fork + "_sha256"]
                        for fork in ["data", "rsrc"]
                    ),
                    "Restart changed recorded Prefs bytes",
                )


def storage(directory: Path) -> None:
    """Check the native storage across the restart, cleanup and publisher stages."""
    before = directory / "native-before-restart"
    rows = check_pre_restart(before)
    for spec in PHASES:
        check_phase(directory, before, rows, spec)
    check_application(directory)
