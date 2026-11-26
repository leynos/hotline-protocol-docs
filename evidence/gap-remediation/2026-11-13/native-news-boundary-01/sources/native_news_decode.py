"""Decode retained native news records with explicit bounds and opaque tails."""


def require(condition: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not condition:
        raise ValueError(message)


def categories(frame: dict) -> list[dict]:
    """Decode the categories of a news listing reply."""
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "News listing failed",
    )
    result = []
    for field in frame["fields"]:
        value = bytes.fromhex(field["hex"])
        if field["id"] == 320:
            require(
                bool(value) and value[0] in {1, 10, 255},
                "Legacy category kind/length differs",
            )
            result.append({"field": 320, "kind": value[0], "name": value[1:]})
            continue
        require(
            field["id"] == 323 and len(value) >= 6,
            "Modern category field/length differs",
        )
        kind = int.from_bytes(value[:2], "big")
        require(kind in {2, 3}, "Modern category kind differs")
        offset = 4 if kind == 2 else 28
        require(len(value) > offset, "Truncated category name length")
        length = value[offset]
        tail = 1 if kind == 2 else 3
        require(
            len(value) == offset + 1 + length + tail,
            "Modern category exact length differs",
        )
        item = {
            "field": 323,
            "kind": kind,
            "aux": int.from_bytes(value[2:4], "big"),
            "name": value[offset + 1 : offset + 1 + length],
            "tail": value[-tail:],
        }
        if kind == 3:
            item.update(
                {
                    "metadata": value[4:20],
                    "word20": int.from_bytes(value[20:24], "big"),
                    "word24": int.from_bytes(value[24:28], "big"),
                }
            )
        result.append(item)
    return result


def articles(value: bytes) -> list[dict]:
    """Decode the article records of a news article list."""
    offset = 0

    def take(size: int) -> bytes:
        """Take the next bytes of the article list, requiring that they exist."""
        nonlocal offset
        require(0 <= size <= len(value) - offset, "Truncated article record")
        result = value[offset : offset + size]
        offset += size
        return result

    def integer(size: int) -> int:
        """Take a big-endian unsigned integer of the given size."""
        return int.from_bytes(take(size), "big")

    def pascal() -> bytes:
        """Take a length-prefixed byte string."""
        return take(integer(1))

    require(take(4) == bytes(4), "Article-list leading word differs")
    count = integer(4)
    require(
        take(2) == bytes(2) and count <= (len(value) - 10) // 24,
        "Article-list count/reserved bytes differ",
    )
    result = []
    for _ in range(count):
        item = {
            "id": integer(4),
            "date": take(8),
            "parent": integer(4),
            "flags": integer(4),
        }
        flavours = integer(2)
        item["title"], item["poster"] = pascal(), pascal()
        item["flavours"] = [(pascal(), integer(2)) for _ in range(flavours)]
        result.append(item)
    require(offset == len(value), "Unconsumed article-list bytes")
    require(len({r["id"] for r in result}) == len(result), "Repeated public article ID")
    return result
