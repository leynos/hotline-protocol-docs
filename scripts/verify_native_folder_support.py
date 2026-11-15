"""Shared records, reply lookups and constants of the folder verifiers.

The folder verifier is split by responsibility: downloads, uploads, probes and
the entry point each import these names from here, so that no module depends
on the entry point.
"""

import dataclasses as dc
import typing as typ

from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]
# The reconciliation of one transcript: its connections, by name.
type Connections = dict[str, Report]
type Cases = dict[str, tuple[list[Report], Report]]

# The frame ID of the folder request in every transcript of the corpus.
FOLDER_REQUEST_ID = 10
# A folder reference is four bytes; its bit zero is set for a folder download.
REFERENCE_BYTES = 4
ODD_REFERENCE_MASK = 1


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The retained folder corpus, read once and shared by the checks.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    timer_host : list[dict[str, typing.Any]]
        The host packet capture of the timed cases.
    timer_guest : list[dict[str, typing.Any]]
        The guest packet capture of the timed cases.
    source_hashes : set[str]
        The SHA-256 digests of the retained driver sources.
    unread : dict[str, typing.Any]
        The unread output that each probe may leave.
    expected : dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The plan of every transcript case, by name.
    """

    directory: Path
    host: Packets
    guest: Packets
    timer_host: Packets
    timer_guest: Packets
    source_hashes: set[str]
    unread: Report
    expected: Cases


def response(report: Report, identifier: int = FOLDER_REQUEST_ID) -> Report:
    """Return the only reply on connection a to the request ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    frames = [
        f
        for f in report["frames"]
        if f["connection"] == "a" and f["is_reply"] and f["id"] == identifier
    ]
    require(len(frames) == 1, "Missing folder request ACK")
    return frames[0]


def summarize(items: list[Report]) -> list[Report]:
    """Describe each parsed item by its path, action and bytes.

    Returns
    -------
    list[dict[str, typing.Any]]
        One summary per item, in order.
    """
    return [
        {
            "path": b"/".join(item["path"]).decode("ascii"),
            "directory": item["directory"],
            "action": item["action"],
            "stream_size": item.get("stream_size"),
            "received_body_bytes": len(item.get("body", b"")),
            "complete": item.get("complete", True),
            "next_ready": item.get("next_ready"),
        }
        for item in items
    ]


def folder_streams(report: Report) -> tuple[bytes, bytes]:
    """Return the client and server bytes of the folder data connection.

    Returns
    -------
    tuple[bytes, bytes]
        The bytes sent by the client and the bytes received by it.
    """
    recorded = report["streams"]["folder"]
    return bytes.fromhex(recorded["sent_hex"]), bytes.fromhex(recorded["received_hex"])
