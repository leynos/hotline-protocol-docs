#!/usr/bin/env python3
"""Decode reviewed v2 AliasRecord payloads as recorded identity only.

The caller proves a unique `alis` resource ID 0 and Finder alias flag. This
module neither parses a resource fork nor resolves an Alias Manager target.
"""

from __future__ import annotations

import struct
from typing import Any

HEADER_SIZE = 150
SUPPORTED_TAGS = {0, 1, 2}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def pascal(payload: bytes, offset: int, width: int) -> bytes:
    size = payload[offset]
    require(size < width, "Alias Pascal name exceeds fixed slot")
    return payload[offset + 1 : offset + 1 + size]


def decode(payload: bytes) -> dict[str, Any]:
    """Return bounded, JSON-serialisable v2 fields without resolving them."""
    require(len(payload) >= HEADER_SIZE, "Alias record shorter than v2 header")
    declared = struct.unpack_from(">H", payload, 4)[0]
    require(declared == len(payload), "Alias declared size differs from payload")
    version, kind = struct.unpack_from(">HH", payload, 6)
    require(version == 2, "Unsupported Alias Record version")
    require(kind in (0, 1), "Unsupported Alias Record kind")
    volume = pascal(payload, 10, 28)
    name = pascal(payload, 50, 64)
    parent_cnid = struct.unpack_from(">I", payload, 46)[0]
    target_cnid = struct.unpack_from(">I", payload, 114)[0]

    offset = HEADER_SIZE
    tags: dict[int, str] = {}
    terminated = False
    while offset < declared:
        require(offset + 4 <= declared, "Truncated Alias tag header")
        tag, size = struct.unpack_from(">hH", payload, offset)
        offset += 4
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
        if tag == 1:
            require(size % 4 == 0, "Alias CNID path length is not aligned")
        tags[tag] = value.hex()
    require(terminated, "Missing Alias terminator")
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
    record: dict[str, Any], volume: bytes, name: bytes, full_carbon_path: bytes
) -> dict[str, Any]:
    """Require the caller's exact expected recorded volume, leaf and path."""
    require(
        bool(volume and name and full_carbon_path), "Expected Alias identity is empty"
    )
    require(
        record.get("identity_scope") == "recorded identity only",
        "Identity scope differs",
    )
    require(record.get("version") == 2, "Unsupported Alias Record version")
    require(record.get("volume_hex") == volume.hex(), "Recorded volume differs")
    require(record.get("name_hex") == name.hex(), "Recorded target name differs")
    require(
        record.get("path_hex") is not None
        and record["path_hex"] == full_carbon_path.hex(),
        "Recorded Carbon path absent or differs",
    )
    return record
