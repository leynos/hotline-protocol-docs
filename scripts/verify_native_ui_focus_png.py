"""Decode the captured focus-event PNG without executing image code."""

import struct
import typing as typ
import zlib

if typ.TYPE_CHECKING:
    from pathlib import Path

from verify_native_ui_focus_core import (
    FILTER_AVERAGE,
    FILTER_PAETH,
    FILTER_SUB,
    FILTER_UP,
    GOLD_BLUE_MAX,
    GOLD_GREEN_MIN,
    GOLD_RED_MIN,
    PNG_CHANNELS,
    PNG_HEIGHT,
    PNG_STRIDE,
    PNG_WIDTH,
    require,
)


def png_chunks(data: bytes) -> tuple[tuple[int, ...] | None, list[bytes]]:
    """Read the chunks of a PNG file, checking the length and CRC of each.

    Returns
    -------
    tuple[tuple[int, ...] | None, list[bytes]]
        The fields of the header chunk, if one was read, and the body of
        each image-data chunk, in order.
    """
    pos, chunks, header = 8, [], None
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        require(
            len(body) == length and pos + length + 12 <= len(data),
            "Focus PNG chunk truncated",
        )
        crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        require(zlib.crc32(kind + body) == crc, "Focus PNG CRC differs")
        match kind:
            case b"IHDR":
                header = struct.unpack(">IIBBBBB", body)
            case b"IDAT":
                chunks.append(body)
            case b"IEND":
                break
        pos += 12 + length
    return header, chunks


def predict(mode: int, left: int, up: int, upper_left: int) -> int:
    """Return the predicted byte for one PNG filter type.

    Returns
    -------
    int
        The predictor, which is zero for the unfiltered type.
    """
    if mode == FILTER_SUB:
        return left
    if mode == FILTER_UP:
        return up
    if mode == FILTER_AVERAGE:
        return (left + up) // 2
    if mode == FILTER_PAETH:
        predictor = left + up - upper_left
        return min((left, up, upper_left), key=lambda v: abs(predictor - v))
    return 0


def unfilter_row(row: bytearray, previous: bytes, mode: int) -> None:
    """Reverse the filter of one row in place.

    Parameters
    ----------
    row : bytearray
        The filtered bytes of the row, replaced by the pixel bytes.
    previous : bytes
        The pixel bytes of the row above.
    mode : int
        The filter type of the row.
    """
    for index in range(PNG_STRIDE):
        left = row[index - PNG_CHANNELS] if index >= PNG_CHANNELS else 0
        up = previous[index]
        upper_left = previous[index - PNG_CHANNELS] if index >= PNG_CHANNELS else 0
        value = predict(mode, left, up, upper_left)
        row[index] = (row[index] + value) & 255


def png_rows(path: Path) -> list[bytes]:
    """Read the captured 1024x768 RGB PNG without executing image code.

    Returns
    -------
    list[bytes]
        The unfiltered pixel bytes of each row, top to bottom.
    """
    data = path.read_bytes()
    require(data[:8] == b"\x89PNG\r\n\x1a\n", "Focus PNG signature differs")
    header, chunks = png_chunks(data)
    require(
        header == (PNG_WIDTH, PNG_HEIGHT, 8, 2, 0, 0, 0),
        "Focus PNG format differs",
    )
    raw = zlib.decompress(b"".join(chunks))
    require(
        len(raw) == PNG_HEIGHT * (PNG_STRIDE + 1),
        "Focus PNG pixel length differs",
    )
    rows, previous, pos = [], bytes(PNG_STRIDE), 0
    for _ in range(PNG_HEIGHT):
        mode = raw[pos]
        row = bytearray(raw[pos + 1 : pos + 1 + PNG_STRIDE])
        require(mode in range(5), "Focus PNG filter differs")
        unfilter_row(row, previous, mode)
        previous = bytes(row)
        rows.append(previous)
        pos += PNG_STRIDE + 1
    return rows


def gold_count(rows: list[bytes], box: tuple[int, int, int, int]) -> int:
    """Count the gold pixels inside a box of rows.

    Returns
    -------
    int
        The number of pixels whose colour is gold.
    """
    x0, y0, x1, y1 = box
    return sum(
        rows[y][x * PNG_CHANNELS] > GOLD_RED_MIN
        and rows[y][x * PNG_CHANNELS + 1] > GOLD_GREEN_MIN
        and rows[y][x * PNG_CHANNELS + 2] < GOLD_BLUE_MAX
        for y in range(y0, y1)
        for x in range(x0, x1)
    )
