#!/usr/bin/env python3
"""Reproduce the saved SynHX RCS trunk-head snapshots and check their hashes.

This deliberately extracts the full trunk head, not the archive's default
vendor branch. It does not apply RCS deltas or claim to be a general checkout.
"""

import hashlib
import json
import re
from pathlib import Path


def sha256(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def trunk_snapshot(archive: bytes, revision: str) -> bytes | None:
    """Extract the full text of one revision from an RCS archive.

    The archive is read as Latin-1. The text of a revision sits between ``@``
    marks, each ``@`` inside it doubled.

    Parameters
    ----------
    archive : bytes
        The archive's bytes.
    revision : str
        The revision whose text to extract, such as ``1.1``.

    Returns
    -------
    bytes | None
        The text, or ``None`` when the archive has no such block.
    """
    pattern = (
        r"\n" + re.escape(revision) + r"\s*\nlog\s*\n@(?:@@|[^@])*@"
        r"\s*\ntext\s*\n@((?:@@|[^@])*)@"
    )
    match = re.search(pattern, archive.decode("latin1"))
    if match is None:
        return None
    return match.group(1).replace("@@", "@").encode("latin1")


def verify_record(directory: Path, record: dict[str, str]) -> None:
    """Check one manifest record, then print its snapshot and revision.

    The checks run in a fixed order, so the first failure decides the error:
    the saved archive's hash, the presence of the revision's text, the hash of
    the extraction, and the saved snapshot file.

    Parameters
    ----------
    directory : pathlib.Path
        The directory that holds the manifest and the saved files.
    record : dict[str, str]
        The manifest record.

    Raises
    ------
    ValueError
        If any check fails.
    """
    archive = (directory / record["saved_archive"]).read_bytes()
    if sha256(archive) != record["archive_sha256"]:
        message = f"Archive changed: {record['saved_archive']}"
        raise ValueError(message)
    snapshot = trunk_snapshot(archive, record["selected_revision"])
    if snapshot is None:
        message = f"Full trunk text not found: {record['saved_archive']}"
        raise ValueError(message)
    if sha256(snapshot) != record["snapshot_sha256"]:
        message = f"Extraction mismatch: {record['snapshot']}"
        raise ValueError(message)
    if (directory / record["snapshot"]).read_bytes() != snapshot:
        message = f"Snapshot changed: {record['snapshot']}"
        raise ValueError(message)
    print(record["snapshot"], record["selected_revision"], "verified")


def verify_snapshots(directory: Path) -> None:
    """Verify every record of the manifest in ``directory``, in order.

    Parameters
    ----------
    directory : pathlib.Path
        The directory that holds ``manifest.json`` and the saved files.
    """
    for record in json.loads((directory / "manifest.json").read_text()):
        verify_record(directory, record)


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    verify_snapshots(root / "evidence/hotline-server-1.9/synhxd-source")
