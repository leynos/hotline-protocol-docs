"""Decode the two direction-specific folder stream grammars without guessing."""

from verify_native_core import require


class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    def remaining(self) -> int:
        return len(self.data) - self.position

    def take(self, size: int) -> bytes:
        require(0 <= size <= self.remaining(), "Truncated folder stream component")
        value = self.data[self.position : self.position + size]
        self.position += size
        return value

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")


def descriptor(cursor: Cursor) -> dict:
    size = cursor.number(2)
    value = Cursor(cursor.take(size))
    flags = value.number(2)
    count = value.number(2)
    parts, words = [], []
    for _ in range(count):
        words.append(value.number(2))
        parts.append(value.take(value.number(1)))
    require(not value.remaining(), "Trailing folder descriptor bytes")
    return {
        "flags": flags,
        "directory": bool(flags & 1),
        "path": tuple(parts),
        "words": words,
        "descriptor_size": size,
    }


def rflt(data: bytes) -> list[tuple[bytes, int]]:
    cursor = Cursor(data)
    require(
        cursor.take(4) == b"RFLT" and cursor.number(2) == 1,
        "Unexpected folder RFLT header",
    )
    cursor.take(34)
    count = cursor.number(2)
    require(cursor.remaining() == count * 16, "Folder RFLT count/length mismatch")
    entries = []
    for _ in range(count):
        entries.append((cursor.take(4), cursor.number(4)))
        cursor.take(8)
    return entries


def download(sent: bytes, received: bytes) -> dict:
    """Parse client choices against server descriptors and optional FILP bodies."""
    client, server = Cursor(sent), Cursor(received)
    require(client.take(4) == b"HTXF", "Missing folder HTXF")
    header = client.take(12)
    require(header[8:10] == b"\0\1", "Wrong folder selector")
    items, ignored = [], []
    state = 0
    current = None
    ended = False
    while client.remaining():
        control = client.number(2)
        if control == 3:
            if state == 1:
                if current is None:
                    raise ValueError("Missing selected folder item")
                current["action"] = "skip"
            if not server.remaining():
                ended = True
                break
            current = descriptor(server)
            current["action"] = "directory" if current["directory"] else "pending"
            items.append(current)
            state = 0 if current["directory"] else 1
        elif state == 1 and control in {1, 2}:
            if current is None:
                raise ValueError("Missing selected folder file")
            current["action"] = "resume" if control == 2 else "fresh"
            if control == 2:
                current["rflt"] = rflt(client.take(client.number(2)))
            size = server.number(4)
            current["stream_size"] = size
            current["body"] = server.take(size)
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


def upload(sent: bytes, received: bytes) -> dict:
    """Parse server item choices, retaining a genuinely interrupted final body."""
    client, server = Cursor(sent), Cursor(received)
    require(client.take(4) == b"HTXF", "Missing folder HTXF")
    header = client.take(12)
    require(header[8:10] == b"\0\1", "Wrong folder selector")
    require(server.number(2) == 3, "Missing initial folder-upload readiness")
    items = []
    while client.remaining():
        item = descriptor(client)
        control = server.number(2)
        item["control"] = control
        item["complete"] = True
        if control == 3:
            item["action"] = "directory-or-conflict" if item["directory"] else "skip"
        elif control in {1, 2}:
            require(
                not item["directory"], "Directory unexpectedly requested file bytes"
            )
            item["action"] = "resume" if control == 2 else "fresh"
            if control == 2:
                item["rflt"] = rflt(server.take(server.number(2)))
            size = client.number(4)
            item["stream_size"] = size
            item["body"] = client.take(min(size, client.remaining()))
            if len(item["body"]) < size:
                item["complete"] = False
                require(
                    not server.remaining(),
                    "Interrupted upload has unexplained server control",
                )
            elif server.remaining():
                require(server.number(2) == 3, "Missing next-item readiness")
                item["next_ready"] = True
            else:
                item["next_ready"] = False
        else:
            raise ValueError("Unexpected folder-upload item choice")
        items.append(item)
    require(not server.remaining(), "Trailing folder-upload controls")
    return {"items": items, "completed": sum(item["complete"] for item in items)}
