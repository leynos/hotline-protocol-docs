"""Constants and the descriptor builder shared by the resume planners."""

import struct
import typing as typ

from native_plan import (
    Action,
)
from native_wire_names import (
    RFLT_ENTRY_PADDING,
    RFLT_HEADER_PADDING,
    RFLT_MAGIC,
    RFLT_VERSION,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Entries = list[tuple[bytes, int]]

FORK_NAME = b"mothra-fork-fixture"
FORK_DATA = b"data-fork\r\n\x00\xff"
RESUME_PARTIAL_NAME = b"mothra-resume-partial"
RESUME_INCONSISTENT_NAME = b"mothra-resume-inconsistent"
MISSING_NAME = b"mothra-missing-partial"
# transfer-contracts.md, "Captured RFLT download boundaries": DATA is 13 bytes
# and MACR 317, so these offsets are the two end-of-fork resume points.
DATA_BYTES = 13
MACR_BYTES = 317
# The seeded upload stops with all of INFO and DATA and five bytes of MACR.
MACR_RETAINED_BYTES = 5
UINT32_MAX = 0xFFFFFFFF
REQUEST_ID = 10
FOLLOWUP_ID = 11
DOWNLOAD_ID = 12
READ_SECONDS = 30
PAUSE_SECONDS = 3
SEED_PAUSE_SECONDS = 2
SIZE_BYTES = 4
OFFSET_BYTES = 4
RFLT_UPGRADE_VERSION = b"\0\2"  # a descriptor version that the consumer rejects
HTXF_DOWNLOAD_TAIL = "0000000000000000"  # size word, selector and reserved word
HTXF_UPLOAD_TAIL = "00000000"  # selector and reserved word, after the size
ENTRY_COUNT = struct.Struct(">H")


def rflt(entries: Entries) -> bytes:
    """Build complete version1 records; unexamined reserved words are zero.

    Returns
    -------
    bytes
        The descriptor: header, entry count and one record for each entry.
    """
    return (
        RFLT_MAGIC
        + RFLT_VERSION
        + bytes(RFLT_HEADER_PADDING)
        + ENTRY_COUNT.pack(len(entries))
        + b"".join(
            tag + offset.to_bytes(OFFSET_BYTES, "big") + bytes(RFLT_ENTRY_PADDING)
            for tag, offset in entries
        )
    )
