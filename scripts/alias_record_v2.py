#!/usr/bin/env python3
"""Decode reviewed v2 AliasRecord payloads as recorded identity only.

The caller proves a unique `alis` resource ID 0 and Finder alias flag. This
module neither parses a resource fork nor resolves an Alias Manager target.
"""

import struct
import typing as typ

HEADER_SIZE = 150
SUPPORTED_TAGS = {0, 1, 2}
RECORD_VERSION = 2  # the only Alias Record version that this module decodes
TAG_HEADER_BYTES = 4  # the signed tag and the unsigned value size
CNID_PATH_TAG = 1  # the tag whose value is a sequence of 4-byte CNIDs
CNID_BYTES = 4


def require(condition: bool, reason: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the public signature takes the condition positionally
    """Raise a ValueError with ``reason`` unless ``condition`` holds.

    Raises
    ------
    ValueError
        When the condition does not hold.
    """
    if not condition:
        raise ValueError(reason)


def pascal(payload: bytes, offset: int, width: int) -> bytes:
    """Return the Pascal string that starts at ``offset`` inside its fixed slot.

    Returns
    -------
    bytes
        The string bytes, without the length byte.
    """
    size = payload[offset]
    require(size < width, "Alias Pascal name exceeds fixed slot")
    return payload[offset + 1 : offset + 1 + size]


def _tags(payload: bytes, declared: int) -> dict[int, str]:
    """Decode the tag, length and value records that follow the fixed header.

    Returns
    -------
    dict[int, str]
        The hex value of each supported tag.
    """
    offset = HEADER_SIZE
    tags: dict[int, str] = {}
    terminated = False
    while offset < declared:
        require(offset + TAG_HEADER_BYTES <= declared, "Truncated Alias tag header")
        tag, size = struct.unpack_from(">hH", payload, offset)
        offset += TAG_HEADER_BYTES
        if tag == -1:
            require(size == 0, "Alias terminator has a value")
            require(offset == declared, "Alias has trailing bytes after terminator")
            terminated = True
            break
        require(tag in SUPPORTED_TAGS, "Unsupported Alias tag")
        require(tag not in tags, "Duplicate Alias tag")
        require(offset + size <= declared, "Alias tag value exceeds record")
        value = payload[offset : offset + size]
        offset += size
        if size & 1:
            require(offset < declared, "Missing Alias alignment byte")
            require(payload[offset] == 0, "Invalid Alias alignment byte")
            offset += 1
        if tag == CNID_PATH_TAG:
            require(size % CNID_BYTES == 0, "Alias CNID path length is not aligned")
        tags[tag] = value.hex()
    require(terminated, "Missing Alias terminator")
    return tags


def decode(payload: bytes) -> dict[str, typ.Any]:
    """Return bounded, JSON-serialisable v2 fields without resolving them.

    Returns
    -------
    dict[str, typing.Any]
        The recorded identity fields, with every tag value in hex.
    """
    require(len(payload) >= HEADER_SIZE, "Alias record shorter than v2 header")
    declared = struct.unpack_from(">H", payload, 4)[0]
    require(declared == len(payload), "Alias declared size differs from payload")
    version, kind = struct.unpack_from(">HH", payload, 6)
    require(version == RECORD_VERSION, "Unsupported Alias Record version")
    require(kind in {0, 1}, "Unsupported Alias Record kind")
    volume = pascal(payload, 10, 28)
    name = pascal(payload, 50, 64)
    parent_cnid = struct.unpack_from(">I", payload, 46)[0]
    target_cnid = struct.unpack_from(">I", payload, 114)[0]
    tags = _tags(payload, declared)
    return {
        "identity_scope": "recorded identity only",
        "version": version,
        "kind": kind,
        "record_size": declared,
        "user_type_hex": payload[:4].hex(),
        "volume_hex": volume.hex(),
        "name_hex": name.hex(),
        "parent_cnid": parent_cnid,
        "target_cnid": target_cnid,
        "path_hex": tags.get(2),
        "tag_0_hex": tags.get(0),
        "tag_1_hex": tags.get(1),
    }


def compare_recorded(
    record: dict[str, typ.Any], volume: bytes, name: bytes, full_carbon_path: bytes
) -> dict[str, typ.Any]:
    """Require the caller's exact expected recorded volume, leaf and path.

    Returns
    -------
    dict[str, typing.Any]
        The record, unchanged, when every expected identity field matches.
    """
    require(
        bool(volume and name and full_carbon_path), "Expected Alias identity is empty"
    )
    require(
        record.get("identity_scope") == "recorded identity only",
        "Identity scope differs",
    )
    require(record.get("version") == RECORD_VERSION, "Unsupported Alias Record version")
    require(record.get("volume_hex") == volume.hex(), "Recorded volume differs")
    require(record.get("name_hex") == name.hex(), "Recorded target name differs")
    require(
        record.get("path_hex") is not None
        and record["path_hex"] == full_carbon_path.hex(),
        "Recorded Carbon path absent or differs",
    )
    return record
