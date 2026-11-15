"""Parse the lines of a ``SHA256SUMS`` file.

A line is ``<sha256>  <path>`` or ``<sha256> *<path>``. A leading backslash
marks a name whose backslash, newline and carriage return are written as
backslash escapes. Names are kept as file-system text so that bytes that are
not UTF-8 survive.
"""

import dataclasses as dc
import os
import re

ENTRY = re.compile(rb"(\\?)([0-9a-f]{64}) [ *](.*)", re.DOTALL)
ESCAPES = re.compile(rb"\\([\\nr])")
UNESCAPED = {b"\\": b"\\", b"n": b"\n", b"r": b"\r"}


@dc.dataclass(frozen=True, slots=True)
class SumsEntry:
    """One parsed line of a sums file.

    Attributes
    ----------
    line : int
        The line number.
    digest : str
        The recorded SHA-256.
    name : str
        The listed path, unescaped, as file-system text.
    """

    line: int
    digest: str
    name: str


def unescape(name: bytes) -> bytes:
    """Undo the backslash escapes of a marked name.

    Returns
    -------
    bytes
        The name as it appears on disk.
    """
    return ESCAPES.sub(lambda match: UNESCAPED[match[1]], name)


def parse_sums(data: bytes) -> tuple[list[SumsEntry], list[int]]:
    """Parse a sums file.

    Parameters
    ----------
    data : bytes
        The file's content.

    Returns
    -------
    tuple[list[SumsEntry], list[int]]
        The entries in file order, and the numbers of the malformed lines.
    """
    entries: list[SumsEntry] = []
    malformed: list[int] = []
    for number, raw in enumerate(data.split(b"\n"), start=1):
        if not raw.strip():
            continue
        match = ENTRY.fullmatch(raw)
        if match is None:
            malformed.append(number)
            continue
        name = unescape(match[3]) if match[1] else match[3]
        entries.append(SumsEntry(number, match[2].decode("ascii"), os.fsdecode(name)))
    return entries, malformed
