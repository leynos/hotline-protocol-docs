"""Prepare direction-specific native folder controls and per-file streams."""

import struct

from native_plan import close, connect, eof, packet, payload, read, send
from native_queue_cases import pump, session
from native_resume_cases import rflt
from native_transfer_cases import file_stream, resource_fork

ROOT = b"mothra-folder-source"
PARTIAL = b"mothra-folder-partial"
FILES = {
    (b"alpha",): (b"data-fork\r\n\x00\xff", resource_fork()),
    (b"zero",): (b"", b""),
    (b"inner", b"leaf"): (b"leaf\n", resource_fork()),
}
ORDER = [
    (False, (b"alpha",)),
    (True, (b"empty",)),
    (True, (b"inner",)),
    (False, (b"inner", b"leaf")),
    (False, (b"zero",)),
]


def path(parts: tuple[bytes, ...]) -> bytes:
    """Encode path components as a protocol path field."""
    return struct.pack(">H", len(parts)) + b"".join(
        b"\0\0" + bytes([len(p)]) + p for p in parts
    )


def descriptor(parts: tuple[bytes, ...], directory: bool) -> bytes:
    """Encode a folder item descriptor from its path and whether it is a directory."""
    value = struct.pack(">H", int(directory)) + path(parts)
    return struct.pack(">H", len(value)) + value


def word(value: int) -> dict:
    """Return the plan step that reads a two-byte word from the folder connection and expects its value."""
    return {
        "op": "read",
        "connection": "folder",
        "size": 2,
        "expect_hex": value.to_bytes(2, "big").hex(),
        "timeout": 30,
    }


def upload_start(
    root: bytes, count: int, size: int, resume: bool = False
) -> list[dict]:
    """Build the steps that open a folder upload and read the server's first reply."""
    values = [
        (201, root),
        (220, count.to_bytes(2, "big")),
        (108, size.to_bytes(4, "big")),
    ]
    if resume:
        values.append((204, b"\0\1"))
    steps = session("a") + [send(packet(213, 10, payload(values)), "a")]
    if count == 0:
        return steps + [read("a", match_frame={"is_reply": 1, "id": 10}), close("a")]
    return steps + [
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_field={"name": "reference", "id": 107},
        ),
        connect("folder", "data"),
        send("48545846{reference}0000000000010000", "folder"),
        word(3),
    ]


def upload_fresh() -> dict[str, tuple[list[dict], dict]]:
    """Build the plan that uploads a fresh folder tree item by item."""
    items = [
        (True, (b"empty",)),
        (True, (b"inner",)),
        (False, (b"alpha",)),
        (False, (b"zero",)),
        (False, (b"inner", b"leaf")),
    ]
    total = sum(len(file_stream(*value)) for value in FILES.values())
    steps = upload_start(ROOT, len(items), total)
    for index, (directory, parts) in enumerate(items):
        steps += [send(descriptor(parts, directory).hex(), "folder")]
        if directory:
            steps += [word(3)]
        else:
            body = file_stream(*FILES[parts])
            steps += [
                word(1),
                send((len(body).to_bytes(4, "big") + body).hex(), "folder"),
            ]
            if index < len(items) - 1:
                steps += [word(3)]
    steps += [eof("folder"), close("folder"), close("a")]
    return {
        "folder-upload-fresh": (
            steps,
            {
                "kind": "folder-upload-fresh",
                "root_hex": ROOT.hex(),
                "declared_items": len(items),
                "declared_bytes": total,
            },
        )
    }


def download_start(root: bytes, empty: bool = False) -> list[dict]:
    """Build the steps that open a folder download and connect its transfer channel."""
    steps = session("a") + [send(packet(210, 10, payload([(201, root)])), "a")]
    if empty:
        return steps + [read("a", match_frame={"is_reply": 1, "id": 10}), close("a")]
    return steps + [
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_fields={"reference": 107, "items": 220, "size": 108},
        ),
        connect("folder", "data"),
        send("48545846{reference}0000000000010000", "folder"),
    ]


def read_descriptor(index: int) -> list[dict]:
    """Build the steps that request and read one item descriptor of a folder download."""
    return [
        send("0003", "folder"),
        {
            "op": "read",
            "connection": "folder",
            "size": 2,
            "save": {"name": f"descriptor{index}", "offset": 0, "size": 2},
            "timeout": 30,
        },
        {
            "op": "read",
            "connection": "folder",
            "size_from": f"descriptor{index}",
            "timeout": 30,
        },
    ]


def skip_all() -> dict[str, tuple[list[dict], dict]]:
    """Build the plan that skips every item of a folder download."""
    steps = download_start(ROOT)
    for index in range(5):
        steps += read_descriptor(index)
    steps += [send("0003", "folder"), eof("folder"), close("folder"), close("a")]
    return {
        "folder-download-skip-all": (
            steps,
            {
                "kind": "folder-download-skip-all",
                "root_hex": ROOT.hex(),
                "descriptors": 5,
            },
        )
    }


def downloads() -> dict[str, tuple[list[dict], dict]]:
    """Build one plan per variant that downloads a folder, with full, resumed, mixed and unusual control sequences."""
    cases = {}
    for variant in ["full", "resume", "mixed", "unknown-control", "delayed-choice"]:
        steps = download_start(ROOT)
        if variant == "unknown-control":
            steps += [
                send("0000", "folder"),
                {"op": "expect_quiet", "connection": "folder", "timeout": 3},
            ]
        for index, (directory, parts) in enumerate(ORDER):
            item = read_descriptor(index)
            item[-1]["expect_hex"] = descriptor(parts, directory)[2:].hex()
            steps += item
            if directory or (variant == "mixed" and parts == (b"alpha",)):
                continue
            if variant == "unknown-control" and index == 0:
                steps += [
                    send("0000", "folder"),
                    {"op": "expect_quiet", "connection": "folder", "timeout": 3},
                ]
            if variant == "delayed-choice" and index == 0:
                for identifier, seconds in [(100, 35), (101, 35), (102, 30), (103, 30)]:
                    steps += pump("a", identifier, seconds)
            resume = variant == "resume" or (
                variant == "mixed" and parts == (b"inner", b"leaf")
            )
            if resume:
                entries = [
                    (b"DATA", 0 if parts == (b"zero",) else 3),
                    (b"MACR", 0 if parts == (b"zero",) else 4),
                ]
                value = rflt(entries)
                steps += [
                    send(
                        (b"\0\2" + len(value).to_bytes(2, "big") + value).hex(),
                        "folder",
                    )
                ]
            else:
                steps += [send("0001", "folder")]
            steps += [
                {
                    "op": "read",
                    "connection": "folder",
                    "size": 4,
                    "save": {"name": f"stream{index}", "offset": 0, "size": 4},
                    "timeout": 30,
                },
                {
                    "op": "read",
                    "connection": "folder",
                    "size_from": f"stream{index}",
                    "timeout": 30,
                },
            ]
        steps += [send("0003", "folder"), eof("folder"), close("folder"), close("a")]
        cases["folder-download-" + variant] = (
            steps,
            {"kind": "folder-download", "variant": variant, "root_hex": ROOT.hex()},
        )
    cases["folder-download-empty"] = (
        download_start(b"mothra-folder-empty", True),
        {"kind": "folder-download-empty"},
    )
    steps = (
        download_start(b"mothra-folder-dirlast")
        + read_descriptor(0)
        + [send("0003", "folder"), eof("folder"), close("folder"), close("a")]
    )
    cases["folder-download-dir-only"] = (steps, {"kind": "folder-download-dir-only"})
    return cases
