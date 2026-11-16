"""Decode the fresh ordinary-file grammar emitted by the native oracle."""

from verify_native_core import require

FILP_HEADER = b"FILP\0\1" + bytes(16) + b"\0\3"
FORK_TAGS = [b"INFO", b"DATA", b"MACR"]
FORK_HEADER_BYTES = 16
FORK_TAG_BYTES = 4
FORK_RESERVED = bytes(8)
INFO_MIN_BYTES = 74
INFO_NAME_SIZE_AT = 70
INFO_NAME_AT = 72


def decode(data: bytes) -> dict[str, bytes]:
    """Reject incomplete/trailing bytes; this is not native upload tolerance.

    Parameters
    ----------
    data : bytes
        A flattened file: the 24-byte header, then the INFO, DATA and MACR forks
        in that order.

    Returns
    -------
    dict[str, bytes]
        The fork values by tag name, in fork order.
    """
    require(
        data[: len(FILP_HEADER)] == FILP_HEADER,
        "Unexpected fresh FILP header",
    )
    position = len(FILP_HEADER)
    forks = {}
    for tag in FORK_TAGS:
        header = data[position : position + FORK_HEADER_BYTES]
        require(
            len(header) == FORK_HEADER_BYTES
            and header[:FORK_TAG_BYTES] == tag
            and header[FORK_TAG_BYTES:12] == FORK_RESERVED,
            "Missing or unexpected fork header",
        )
        size = int.from_bytes(header[12:16], "big")
        position += FORK_HEADER_BYTES
        require(position + size <= len(data), "Truncated fork value")
        forks[tag.decode()] = data[position : position + size]
        position += size
    require(position == len(data), "Trailing flattened-file bytes")
    return forks


def metadata(info: bytes) -> dict[str, bytes]:
    """Decode exact emitted INFO boundaries while preserving raw date bytes.

    Parameters
    ----------
    info : bytes
        The INFO fork's value, beginning ``AMAC``.

    Returns
    -------
    dict[str, bytes]
        The type, creator, flags, created and modified dates (raw), name and
        comment.
    """
    require(
        len(info) >= INFO_MIN_BYTES and info[:4] == b"AMAC",
        "Short or non-AMAC INFO",
    )
    name_size = int.from_bytes(info[INFO_NAME_SIZE_AT:INFO_NAME_AT], "big")
    comment_offset = INFO_NAME_AT + name_size
    require(comment_offset + 2 <= len(info), "Truncated INFO name")
    comment_size = int.from_bytes(info[comment_offset : comment_offset + 2], "big")
    require(
        comment_offset + 2 + comment_size == len(info), "INFO comment length differs"
    )
    return {
        "type": info[4:8],
        "creator": info[8:12],
        "flags": info[16:20],
        "created": info[52:60],
        "modified": info[60:68],
        "name": info[INFO_NAME_AT:comment_offset],
        "comment": info[comment_offset + 2 :],
    }
