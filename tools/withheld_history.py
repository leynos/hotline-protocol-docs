"""Scan every object in a repository for withheld content."""

import dataclasses as dc
import hashlib
import typing as typ

from git_lossless import git_text

if typ.TYPE_CHECKING:
    from pathlib import Path

    from withheld_model import Manifest

PEF_MAGIC = b"Joy!peffpwpc"
LARGE_BLOB = 100_000
LISTING_FIELDS = 3


@dc.dataclass(frozen=True, slots=True)
class HistoryScan:
    """The outcome of a history scan.

    Attributes
    ----------
    blobs : int
        How many blobs were examined.
    found : tuple[str, ...]
        One ``<object id>: <reason>`` line per withheld object.
    """

    blobs: int
    found: tuple[str, ...]


def _judge(repository: Path, blob: tuple[str, int], manifest: Manifest) -> str | None:
    """Say why a blob is a withheld object, if it is.

    Parameters
    ----------
    repository : pathlib.Path
        The repository that holds the blob.
    blob : tuple[str, int]
        The object identifier and size.
    manifest : Manifest
        The withheld entries.

    Returns
    -------
    str | None
        The reason, or ``None`` for an unremarkable blob. Only a blob of a
        withheld size is hashed, and only a large blob is read for the magic.
    """
    oid, size = blob
    hashed = size in manifest.sizes
    if not hashed and size <= LARGE_BLOB:
        return None
    content = git_text(repository, "cat-file", "blob", oid).encode("latin-1")
    if hashed and hashlib.sha256(content).hexdigest() in manifest.hashes:
        return "sha256 equals a withheld file"
    if size > LARGE_BLOB and content.startswith(PEF_MAGIC):
        return "begins with the PEF container magic"
    return None


def scan_history(repository: Path, manifest: Manifest) -> HistoryScan:
    """Find blobs that are withheld files, by hash or by container magic.

    Parameters
    ----------
    repository : pathlib.Path
        The repository whose every object is examined.
    manifest : Manifest
        The withheld entries.

    Returns
    -------
    HistoryScan
        The blob count and the withheld objects found.
    """
    listing = git_text(repository, "cat-file", "--batch-all-objects", "--batch-check")
    blobs = 0
    found: list[str] = []
    for line in listing.splitlines():
        fields = line.split(" ")
        if len(fields) != LISTING_FIELDS or fields[1] != "blob":
            continue
        blobs += 1
        reason = _judge(repository, (fields[0], int(fields[2])), manifest)
        if reason:
            found.append(f"{fields[0]}: {reason}")
    return HistoryScan(blobs=blobs, found=tuple(found))
