"""Read the frames and identities of a retained shx peer capture."""

import dataclasses as dc
import hashlib
import typing as typ

from native_wire_names import (
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    HANDSHAKE_REQUEST_HEX,
    MAX_FRAME_BYTES,
)
from protocol_capture import decode_frame
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

# The peer under test: its compiled binary and the source revision it was built from.
PEER = "8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0"
REVISION = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
CHAT = b"mothra-peer-byte-\x80-\x9a-\xc3\xb6-\xff-END"
DATA = b"data-fork\r\n\0\xff"
NAME = b"mothra-fork-fixture"
LOGIN = "/server -o -l admin -p mothra19 -n shx-peer-a -i 500 127.0.0.1:15500"
HANDSHAKE_REQUEST_BYTES = len(bytes.fromhex(HANDSHAKE_REQUEST_HEX))  # then the frames


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a shx corpus holds besides its captures.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    sources : set[str]
        The hashes of the capture sources.
    agreement : bytes
        The native agreement text.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    build : dict[str, typing.Any]
        The build manifest of the peer.
    """

    directory: Path
    sources: set[str]
    agreement: bytes
    host: list[Report]
    guest: list[Report]
    build: Report


def sha(path: Path) -> str:
    """Hash a file with SHA-256.

    Returns
    -------
    str
        The hexadecimal digest of the file.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_agreement(directory: Path) -> bytes:
    """Read the native agreement text that the corpus was captured against.

    Returns
    -------
    bytes
        The agreement, with its line ends as the server sends them.
    """
    path = directory.parent / "native-agreement-01/original-agreement.data"
    return path.read_bytes().replace(b"\r\n", b"\r")


def fields(frame: Report) -> dict[int, bytes]:
    """Map the fields of a frame by ID, refusing a repeated one.

    Returns
    -------
    dict[int, bytes]
        The value of each field.
    """
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(values) == len(frame["fields"]), "Unexpected repeated scalar field")
    return values


def frames(data: bytes) -> list[Report]:
    """Split a peer byte stream into its complete, unfragmented frames.

    Returns
    -------
    list[dict[str, typing.Any]]
        The decoded frames, in order.
    """
    result = []
    while data:
        require(len(data) >= FRAME_HEADER_BYTES, "Incomplete peer frame header")
        size = int.from_bytes(data[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big")
        require(
            size <= MAX_FRAME_BYTES and FRAME_HEADER_BYTES + size <= len(data),
            "Incomplete peer frame",
        )
        frame = decode_frame(data[: FRAME_HEADER_BYTES + size])
        require(
            frame["flags"] == 0 and frame["total_size"] == size,
            "Unexpected peer fragmentation",
        )
        require(
            "fields" in frame and "payload_error" not in frame, "Malformed peer fields"
        )
        require(
            len(frame["fields"]) == frame["declared_field_count"]
            and not frame["unconsumed_hex"],
            "Incomplete or trailing peer fields",
        )
        result.append(frame)
        data = data[FRAME_HEADER_BYTES + size :]
    return result
