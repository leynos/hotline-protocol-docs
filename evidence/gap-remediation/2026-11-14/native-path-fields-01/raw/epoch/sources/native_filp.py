"""Decode the fresh ordinary-file grammar emitted by the native oracle."""

from verify_native_core import require


def decode(data: bytes) -> dict[str, bytes]:
    """Reject incomplete/trailing bytes; this is not native upload tolerance."""
    require(
        data[:24] == b"FILP\0\1" + bytes(16) + b"\0\3",
        "Unexpected fresh FILP header",
    )
    position = 24
    forks = {}
    for tag in [b"INFO", b"DATA", b"MACR"]:
        header = data[position : position + 16]
        require(
            len(header) == 16 and header[:4] == tag and header[4:12] == bytes(8),
            "Missing or unexpected fork header",
        )
        size = int.from_bytes(header[12:16], "big")
        position += 16
        require(position + size <= len(data), "Truncated fork value")
        forks[tag.decode()] = data[position : position + size]
        position += size
    require(position == len(data), "Trailing flattened-file bytes")
    return forks


def metadata(info: bytes) -> dict[str, bytes]:
    """Decode exact emitted INFO boundaries while preserving raw date bytes."""
    require(len(info) >= 74 and info[:4] == b"AMAC", "Short or non-AMAC INFO")
    name_size = int.from_bytes(info[70:72], "big")
    comment_offset = 72 + name_size
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
        "name": info[72:comment_offset],
        "comment": info[comment_offset + 2 :],
    }
