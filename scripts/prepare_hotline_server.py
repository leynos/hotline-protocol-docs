#!/usr/bin/env python3
"""Prepare the hashed Mac server with SheepShaver-compatible resource metadata."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

from script_cli import run

ORACLE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"

# AppleDouble v2 layout: a 26-byte header whose last two bytes give the entry
# count, then 12-byte entries of (ID, offset, length), all big-endian.
APPLEDOUBLE_MAGIC = bytes.fromhex("0005160700020000")
APPLEDOUBLE_HEADER_BYTES = 26
APPLEDOUBLE_ENTRY_BYTES = 12
FINDER_INFO_ENTRY = 9
RESOURCE_FORK_ENTRY = 2
FINDER_INFO_BYTES = 32


def appledouble(data: bytes) -> dict[int, bytes]:
    """Extract bounded entries from an AppleDouble v2 resource sidecar.

    Parameters
    ----------
    data : bytes
        The contents of the ``._`` sidecar file.

    Returns
    -------
    dict[int, bytes]
        The payload of each entry, keyed by entry ID.

    Raises
    ------
    ValueError
        If the header, the entry table or a required entry is malformed.
    """
    if len(data) < APPLEDOUBLE_HEADER_BYTES or data[:8] != APPLEDOUBLE_MAGIC:
        message = "Expected AppleDouble v2"
        raise ValueError(message)
    count = int.from_bytes(data[24:26], "big")
    table_end = APPLEDOUBLE_HEADER_BYTES + count * APPLEDOUBLE_ENTRY_BYTES
    if table_end > len(data):
        message = "Truncated AppleDouble entry table"
        raise ValueError(message)
    entries: dict[int, bytes] = {}
    for index in range(count):
        tag, offset, size = struct.unpack_from(
            ">III", data, APPLEDOUBLE_HEADER_BYTES + index * APPLEDOUBLE_ENTRY_BYTES
        )
        if offset < table_end or offset + size > len(data):
            message = "Invalid AppleDouble entry bounds or duplicate ID"
            raise ValueError(message)
        if tag in entries:
            message = "Invalid AppleDouble entry bounds or duplicate ID"
            raise ValueError(message)
        entries[tag] = data[offset : offset + size]
    if len(entries.get(FINDER_INFO_ENTRY, b"")) != FINDER_INFO_BYTES or not entries.get(
        RESOURCE_FORK_ENTRY
    ):
        message = "Finder information and resource fork are required"
        raise ValueError(message)
    return entries


def prepare(source: Path, destination: Path) -> None:
    """Copy one exact oracle into a new shared-folder location, preserving forks.

    Parameters
    ----------
    source : Path
        The folder that holds the oracle, its ``._`` sidecar and, optionally,
        ``Agreement.txt``.
    destination : Path
        The folder to create; it must not exist.

    Raises
    ------
    ValueError
        If the oracle does not match the recorded hash or the sidecar is invalid.
    """
    binary = (source / "HLserver19").read_bytes()
    if hashlib.sha256(binary).hexdigest() != ORACLE_SHA256:
        message = "Source is not the recorded Ghidra oracle"
        raise ValueError(message)
    sidecar = (source / "._HLserver19").read_bytes()
    entries = appledouble(sidecar)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "HLserver19").write_bytes(binary)
    for folder, tag in [(".finf", FINDER_INFO_ENTRY), (".rsrc", RESOURCE_FORK_ENTRY)]:
        (destination / folder).mkdir()
        (destination / folder / "HLserver19").write_bytes(entries[tag])
    if (source / "Agreement.txt").exists():
        shutil.copyfile(source / "Agreement.txt", destination / "Agreement.txt")
    (destination / "source-manifest.json").write_text(
        json.dumps(
            {
                "oracle_sha256": ORACLE_SHA256,
                "appledouble_sha256": hashlib.sha256(sidecar).hexdigest(),
                "finder_info_sha256": hashlib.sha256(
                    entries[FINDER_INFO_ENTRY]
                ).hexdigest(),
                "resource_fork_sha256": hashlib.sha256(
                    entries[RESOURCE_FORK_ENTRY]
                ).hexdigest(),
                "method": "AppleDouble entries9/2 copied to .finf/.rsrc; "
                "data fork unchanged",
            },
            indent=2,
        )
        + "\n"
    )


def main(source: str, destination: str) -> None:
    """Prepare a shared folder; existing destinations are never overwritten.

    Parameters
    ----------
    source : str
        The folder that holds the recorded oracle.
    destination : str
        The shared folder to create. Its path is printed once it exists.
    """
    destination_path = Path(destination)
    prepare(Path(source), destination_path)
    print(destination_path)


if __name__ == "__main__":
    run(main, __doc__)
