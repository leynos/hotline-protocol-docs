#!/usr/bin/env python3
"""Prepare the hashed Mac server with SheepShaver-compatible resource metadata."""

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path

ORACLE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"


def appledouble(data: bytes) -> dict[int, bytes]:
    """Extract bounded entries from an AppleDouble v2 resource sidecar."""
    if len(data) < 26 or data[:8] != bytes.fromhex("0005160700020000"):
        raise ValueError("Expected AppleDouble v2")
    count = int.from_bytes(data[24:26], "big")
    if 26 + count * 12 > len(data):
        raise ValueError("Truncated AppleDouble entry table")
    entries = {}
    for index in range(count):
        tag, offset, size = struct.unpack_from(">III", data, 26 + index * 12)
        if offset < 26 + count * 12 or offset + size > len(data) or tag in entries:
            raise ValueError("Invalid AppleDouble entry bounds or duplicate ID")
        entries[tag] = data[offset : offset + size]
    if len(entries.get(9, b"")) != 32 or not entries.get(2):
        raise ValueError("Finder information and resource fork are required")
    return entries


def prepare(source: Path, destination: Path) -> None:
    """Copy one exact oracle into a new shared-folder location, preserving forks."""
    binary = (source / "HLserver19").read_bytes()
    if hashlib.sha256(binary).hexdigest() != ORACLE_SHA256:
        raise ValueError("Source is not the recorded Ghidra oracle")
    sidecar = (source / "._HLserver19").read_bytes()
    entries = appledouble(sidecar)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "HLserver19").write_bytes(binary)
    for folder, tag in [(".finf", 9), (".rsrc", 2)]:
        (destination / folder).mkdir()
        (destination / folder / "HLserver19").write_bytes(entries[tag])
    if (source / "Agreement.txt").exists():
        shutil.copyfile(source / "Agreement.txt", destination / "Agreement.txt")
    (destination / "source-manifest.json").write_text(
        json.dumps(
            {
                "oracle_sha256": ORACLE_SHA256,
                "appledouble_sha256": hashlib.sha256(sidecar).hexdigest(),
                "finder_info_sha256": hashlib.sha256(entries[9]).hexdigest(),
                "resource_fork_sha256": hashlib.sha256(entries[2]).hexdigest(),
                "method": "AppleDouble entries9/2 copied to .finf/.rsrc; data fork unchanged",
            },
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    """Prepare a shared folder; existing destinations are never overwritten."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    prepare(args.source, args.destination)
    print(args.destination)


if __name__ == "__main__":
    main()
