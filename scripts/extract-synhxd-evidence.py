#!/usr/bin/env python3
"""Reproduce the saved SynHX RCS trunk-head snapshots and check their hashes.

This deliberately extracts the full trunk head, not the archive's default
vendor branch. It does not apply RCS deltas or claim to be a general checkout.
"""

import hashlib
import json
import re
from pathlib import Path


def verify_snapshots(directory: Path) -> None:
    for record in json.loads((directory / "manifest.json").read_text()):
        archive = (directory / record["saved_archive"]).read_bytes()
        if hashlib.sha256(archive).hexdigest() != record["archive_sha256"]:
            raise ValueError(f"Archive changed: {record['saved_archive']}")
        text = archive.decode("latin1")
        revision = re.escape(record["selected_revision"])
        pattern = (
            r"\n" + revision + r"\s*\nlog\s*\n@(?:@@|[^@])*@"
            r"\s*\ntext\s*\n@((?:@@|[^@])*)@"
        )
        match = re.search(pattern, text)
        if match is None:
            raise ValueError(f"Full trunk text not found: {record['saved_archive']}")
        snapshot = match.group(1).replace("@@", "@").encode("latin1")
        if hashlib.sha256(snapshot).hexdigest() != record["snapshot_sha256"]:
            raise ValueError(f"Extraction mismatch: {record['snapshot']}")
        if (directory / record["snapshot"]).read_bytes() != snapshot:
            raise ValueError(f"Snapshot changed: {record['snapshot']}")
        print(record["snapshot"], record["selected_revision"], "verified")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    verify_snapshots(root / "evidence/hotline-server-1.9/synhxd-source")
