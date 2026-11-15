"""Decode the two direction-specific folder stream grammars without guessing."""

import typing as typ

from native_wire_names import (
    FOLDER_CONTROL_FRESH,
    FOLDER_CONTROL_NEXT,
    FOLDER_CONTROL_RESUME,
    FOLDER_DIRECTORY_FLAG,
    RFLT_ENTRY_PADDING,
    RFLT_HEADER_PADDING,
    RFLT_MAGIC,
    RFLT_VERSION,
    SELECTOR_FOLDER,
)
from verify_native_core import require

type Item = dict[str, typ.Any]
type Report = dict[str, typ.Any]

# The HTXF header of a folder stream: the magic, the four-byte reference, a
# size word and the two-byte selector with its reserved word.
HTXF_HEADER_BYTES = 16
# Resume descriptor entry (transfer-contracts.md, "Resume data: RFLT"): a
# four-byte fork tag, a BE32 offset and eight bytes that are not read.
RFLT_ENTRY_BYTES = 16


class Cursor:
    """A read position over a byte string, with every read bounds-checked."""

    def __init__(self, data: bytes) -> None:
        """Start reading at the first byte of ``data``."""
        self.data = data
        self.position = 0

    def remaining(self) -> int:
        """Count the bytes that have not been read.

        Returns
        -------
        int
            The number of unread bytes.
        """
        return len(self.data) - self.position

    def take(self, size: int) -> bytes:
        """Read ``size`` bytes, refusing a read past the end.

        Returns
        -------
        bytes
            The bytes read.
        """
        require(0 <= size <= self.remaining(), "Truncated folder stream component")
        value = self.data[self.position : self.position + size]
        self.position += size
        return value

    def number(self, size: int) -> int:
        """Read ``size`` bytes as a big-endian unsigned integer.

        Returns
        -------
        int
            The integer read.
        """
        return int.from_bytes(self.take(size), "big")


def descriptor(cursor: Cursor) -> Item:
    """Read one item descriptor: its flags, its path and its component words.

    Returns
    -------
    dict[str, typing.Any]
        The flags, the directory state, the path, the words and the size.
    """
    size = cursor.number(2)
    value = Cursor(cursor.take(size))
    flags = value.number(2)
    count = value.number(2)
    parts: list[bytes] = []
    words: list[int] = []
    for _ in range(count):
        words.append(value.number(2))
        parts.append(value.take(value.number(1)))
    require(not value.remaining(), "Trailing folder descriptor bytes")
    return {
        "flags": flags,
        "directory": bool(flags & FOLDER_DIRECTORY_FLAG),
        "path": tuple(parts),
        "words": words,
        "descriptor_size": size,
    }


def rflt(data: bytes) -> list[tuple[bytes, int]]:
    """Read the fork offsets of a resume descriptor.

    Returns
    -------
    list[tuple[bytes, int]]
        The fork tag and the offset of each entry, in order.
    """
    cursor = Cursor(data)
    require(
        cursor.take(len(RFLT_MAGIC)) == RFLT_MAGIC
        and cursor.take(len(RFLT_VERSION)) == RFLT_VERSION,
        "Unexpected folder RFLT header",
    )
    cursor.take(RFLT_HEADER_PADDING)
    count = cursor.number(2)
    require(
        cursor.remaining() == count * RFLT_ENTRY_BYTES,
        "Folder RFLT count/length mismatch",
    )
    entries: list[tuple[bytes, int]] = []
    for _ in range(count):
        entries.append((cursor.take(4), cursor.number(4)))
        cursor.take(RFLT_ENTRY_PADDING)
    return entries


def check_htxf(client: Cursor) -> None:
    """Check the HTXF magic and the folder selector of a client stream."""
    require(client.take(4) == b"HTXF", "Missing folder HTXF")
    header = client.take(12)
    require(header[8:10] == SELECTOR_FOLDER.to_bytes(2, "big"), "Wrong folder selector")


def offer_item(server: Cursor, items: list[Item]) -> Item:
    """Read the next server descriptor and record it as a pending item.

    Returns
    -------
    dict[str, typing.Any]
        The descriptor, with its action.
    """
    current = descriptor(server)
    current["action"] = "directory" if current["directory"] else "pending"
    items.append(current)
    return current


def skip_selected(current: Item | None) -> None:
    """Mark the selected item as skipped.

    Raises
    ------
    ValueError
        When no item has been selected.
    """
    if current is None:
        message = "Missing selected folder item"
        raise ValueError(message)
    current["action"] = "skip"


def take_file(
    client: Cursor, server: Cursor, current: Item | None, control: int
) -> None:
    """Read the resume descriptor and the FILP body of the selected file.

    Raises
    ------
    ValueError
        When no file has been selected.
    """
    if current is None:
        message = "Missing selected folder file"
        raise ValueError(message)
    current["action"] = "resume" if control == FOLDER_CONTROL_RESUME else "fresh"
    if control == FOLDER_CONTROL_RESUME:
        current["rflt"] = rflt(client.take(client.number(2)))
    size = server.number(4)
    current["stream_size"] = size
    current["body"] = server.take(size)


def download(sent: bytes, received: bytes) -> Report:
    """Parse client choices against server descriptors and optional FILP bodies.

    Returns
    -------
    dict[str, typing.Any]
        The items in traversal order and the control pairs that were ignored.
    """
    client, server = Cursor(sent), Cursor(received)
    check_htxf(client)
    items: list[Item] = []
    ignored: list[Report] = []
    state = 0
    current: Item | None = None
    ended = False
    while client.remaining():
        control = client.number(2)
        if control == FOLDER_CONTROL_NEXT:
            if state == 1:
                skip_selected(current)
            if not server.remaining():
                ended = True
                break
            current = offer_item(server, items)
            state = 0 if current["directory"] else 1
        elif state == 1 and control in {FOLDER_CONTROL_FRESH, FOLDER_CONTROL_RESUME}:
            take_file(client, server, current, control)
            state = 0
        else:
            ignored.append({"state": state, "control": control})
    require(
        ended and not client.remaining() and not server.remaining(),
        "Folder download did not end on traversal exhaustion",
    )
    require(
        all(item["action"] != "pending" for item in items),
        "Unanswered folder file choice",
    )
    return {"items": items, "ignored": ignored}


def read_upload_file(client: Cursor, server: Cursor, item: Item) -> None:
    """Read the body of a file that the server asked for, possibly interrupted."""
    require(not item["directory"], "Directory unexpectedly requested file bytes")
    item["action"] = "resume" if item["control"] == FOLDER_CONTROL_RESUME else "fresh"
    if item["control"] == FOLDER_CONTROL_RESUME:
        item["rflt"] = rflt(server.take(server.number(2)))
    size = client.number(4)
    item["stream_size"] = size
    item["body"] = client.take(min(size, client.remaining()))
    if len(item["body"]) < size:
        item["complete"] = False
        require(
            not server.remaining(), "Interrupted upload has unexplained server control"
        )
    elif server.remaining():
        require(server.number(2) == FOLDER_CONTROL_NEXT, "Missing next-item readiness")
        item["next_ready"] = True
    else:
        item["next_ready"] = False


def upload(sent: bytes, received: bytes) -> Report:
    """Parse server item choices, retaining a genuinely interrupted final body.

    Returns
    -------
    dict[str, typing.Any]
        The items, with their choices and bodies, and the completed count.

    Raises
    ------
    ValueError
        When the server sends a control word that is not a folder-upload choice.
    """
    client, server = Cursor(sent), Cursor(received)
    check_htxf(client)
    require(
        server.number(2) == FOLDER_CONTROL_NEXT,
        "Missing initial folder-upload readiness",
    )
    items: list[Item] = []
    while client.remaining():
        item = descriptor(client)
        control = server.number(2)
        item["control"] = control
        item["complete"] = True
        if control not in {
            FOLDER_CONTROL_NEXT,
            FOLDER_CONTROL_FRESH,
            FOLDER_CONTROL_RESUME,
        }:
            message = "Unexpected folder-upload item choice"
            raise ValueError(message)
        if control == FOLDER_CONTROL_NEXT:
            item["action"] = "directory-or-conflict" if item["directory"] else "skip"
        else:
            read_upload_file(client, server, item)
        items.append(item)
    require(not server.remaining(), "Trailing folder-upload controls")
    return {"items": items, "completed": sum(item["complete"] for item in items)}
