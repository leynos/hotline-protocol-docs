"""Decode retained native news records with explicit bounds and opaque tails."""

# The field of a legacy category record, and the only kinds that it may carry.
LEGACY_CATEGORY_FIELD = 320
LEGACY_KINDS = frozenset({1, 10, 255})
# The field of a modern category record.
MODERN_CATEGORY_FIELD = 323
# A modern record starts with a kind word and an auxiliary word, then a name.
KIND_BYTES = 2
AUX_END = 4
MODERN_MIN_BYTES = 6
# A plain kind has its name at offset 4 and one tail byte. A kind with metadata
# has its name at offset 28, three tail bytes and a metadata block in between.
PLAIN_KIND = 2
METADATA_KIND = 3
PLAIN_NAME_OFFSET = 4
METADATA_NAME_OFFSET = 28
LENGTH_BYTES = 1
PLAIN_TAIL_BYTES = 1
METADATA_TAIL_BYTES = 3
METADATA_START = 4
METADATA_END = 20
WORD20_END = 24
WORD24_END = 28
# An article list starts with a leading word, a count word and two reserved bytes.
ARTICLE_LIST_HEADER_BYTES = 10
# An article header is 22 bytes; its two Pascal strings take at least a byte each.
MIN_ARTICLE_BYTES = 24
WORD_BYTES = 4
HALF_WORD_BYTES = 2
DATE_BYTES = 8
PASCAL_LENGTH_BYTES = 1


def require(condition: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the condition positionally
    """Raise a ValueError carrying ``message`` unless ``condition`` holds.

    Raises
    ------
    ValueError
        If ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def categories(frame: dict) -> list[dict]:
    """Decode the category records of a category-list reply.

    Returns
    -------
    list[dict]
        One record per category field, in the order of the reply.
    """
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "News listing failed",
    )
    result = []
    for field in frame["fields"]:
        value = bytes.fromhex(field["hex"])
        if field["id"] == LEGACY_CATEGORY_FIELD:
            require(
                bool(value) and value[0] in LEGACY_KINDS,
                "Legacy category kind/length differs",
            )
            result.append({
                "field": LEGACY_CATEGORY_FIELD,
                "kind": value[0],
                "name": value[1:],
            })
            continue
        require(
            field["id"] == MODERN_CATEGORY_FIELD and len(value) >= MODERN_MIN_BYTES,
            "Modern category field/length differs",
        )
        kind = int.from_bytes(value[:KIND_BYTES], "big")
        require(kind in {PLAIN_KIND, METADATA_KIND}, "Modern category kind differs")
        offset = PLAIN_NAME_OFFSET if kind == PLAIN_KIND else METADATA_NAME_OFFSET
        require(len(value) > offset, "Truncated category name length")
        length = value[offset]
        tail = PLAIN_TAIL_BYTES if kind == PLAIN_KIND else METADATA_TAIL_BYTES
        require(
            len(value) == offset + LENGTH_BYTES + length + tail,
            "Modern category exact length differs",
        )
        item = {
            "field": MODERN_CATEGORY_FIELD,
            "kind": kind,
            "aux": int.from_bytes(value[KIND_BYTES:AUX_END], "big"),
            "name": value[offset + LENGTH_BYTES : offset + LENGTH_BYTES + length],
            "tail": value[-tail:],
        }
        if kind == METADATA_KIND:
            item.update({
                "metadata": value[METADATA_START:METADATA_END],
                "word20": int.from_bytes(value[METADATA_END:WORD20_END], "big"),
                "word24": int.from_bytes(value[WORD20_END:WORD24_END], "big"),
            })
        result.append(item)
    return result


def articles(value: bytes) -> list[dict]:
    """Decode an article list, checking every length, count and reserved byte.

    Returns
    -------
    list[dict]
        One record per article, in the order of the list.
    """
    offset = 0

    def take(size: int) -> bytes:
        """Take the next ``size`` bytes, refusing a read past the end.

        Returns
        -------
        bytes
            The bytes taken.
        """
        nonlocal offset
        require(0 <= size <= len(value) - offset, "Truncated article record")
        result = value[offset : offset + size]
        offset += size
        return result

    def integer(size: int) -> int:
        """Take a big-endian unsigned integer of ``size`` bytes.

        Returns
        -------
        int
            The value of the bytes taken.
        """
        return int.from_bytes(take(size), "big")

    def pascal() -> bytes:
        """Take a Pascal string: a length byte, then that many bytes.

        Returns
        -------
        bytes
            The bytes of the string, without its length byte.
        """
        return take(integer(PASCAL_LENGTH_BYTES))

    require(take(WORD_BYTES) == bytes(WORD_BYTES), "Article-list leading word differs")
    count = integer(WORD_BYTES)
    require(
        take(HALF_WORD_BYTES) == bytes(HALF_WORD_BYTES)
        and count <= (len(value) - ARTICLE_LIST_HEADER_BYTES) // MIN_ARTICLE_BYTES,
        "Article-list count/reserved bytes differ",
    )
    result = []
    for _ in range(count):
        item = {
            "id": integer(WORD_BYTES),
            "date": take(DATE_BYTES),
            "parent": integer(WORD_BYTES),
            "flags": integer(WORD_BYTES),
        }
        flavours = integer(HALF_WORD_BYTES)
        item["title"], item["poster"] = pascal(), pascal()
        item["flavours"] = [
            (pascal(), integer(HALF_WORD_BYTES)) for _ in range(flavours)
        ]
        result.append(item)
    require(offset == len(value), "Unconsumed article-list bytes")
    require(len({r["id"] for r in result}) == len(result), "Repeated public article ID")
    return result
