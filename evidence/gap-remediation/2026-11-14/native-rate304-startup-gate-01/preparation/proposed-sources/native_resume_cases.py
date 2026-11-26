"""Prepare bounded RFLT resume observations with complete entry records."""

import struct

from native_plan import close, connect, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream, resource_fork


def rflt(entries: list[tuple[bytes, int]]) -> bytes:
    """Build complete version1 records; unexamined reserved words are zero."""
    return (
        b"RFLT\0\1"
        + bytes(34)
        + struct.pack(">H", len(entries))
        + b"".join(
            tag + offset.to_bytes(4, "big") + bytes(8) for tag, offset in entries
        )
    )


def downloads() -> dict[str, tuple[list[dict], dict]]:
    """Build one plan per resume offset variant that downloads a file with a resume record."""
    cases = {}
    variants = {
        "zero-entries": [],
        "data-zero": [(b"DATA", 0)],
        "data-inside": [(b"DATA", 3)],
        "resource-inside": [(b"MACR", 4)],
        "both-inside": [(b"DATA", 3), (b"MACR", 4)],
        "both-eof": [(b"DATA", 13), (b"MACR", 317)],
        "both-beyond": [(b"DATA", 14), (b"MACR", 318)],
        "both-uint32-max": [(b"DATA", 0xFFFFFFFF), (b"MACR", 0xFFFFFFFF)],
        "unknown-tag": [(b"XXXX", 123)],
        "duplicate-data-3-4": [(b"DATA", 3), (b"DATA", 4)],
        "duplicate-data-4-3": [(b"DATA", 4), (b"DATA", 3)],
        "duplicate-data-beyond-inside": [(b"DATA", 14), (b"DATA", 1)],
        "duplicate-resource-3-4": [(b"MACR", 3), (b"MACR", 4)],
    }
    for name, entries in variants.items():
        filename = b"mothra-fork-fixture"
        encoded = rflt(entries)
        steps = login() + [
            send(packet(202, 10, payload([(201, filename), (203, encoded)]))),
            read(
                match_frame={"is_reply": 1, "id": 10},
                save_fields={"reference": 107, "size": 108},
            ),
            connect("download", "data"),
            send("48545846{reference}0000000000000000", "download"),
        ]
        if name == "both-uint32-max":
            steps += [eof("download")]
        else:
            steps += [
                {
                    "op": "read",
                    "connection": "download",
                    "size_from": "size",
                    "timeout": 30,
                },
                {"op": "expect_quiet", "connection": "download", "timeout": 3},
            ]
        steps += [
            close("download"),
            close(),
        ]
        cases["resume-download-" + name] = (
            steps,
            {
                "kind": "resume-data-error"
                if name == "both-uint32-max"
                else "resume-download",
                "name_hex": filename.hex(),
                "rflt_hex": encoded.hex(),
                "entries": [
                    {"tag": tag.decode(), "offset": offset} for tag, offset in entries
                ],
            },
        )
    for name, encoded in {
        "short-41": rflt([])[:41],
        "wrong-magic": b"XXXX" + rflt([])[4:],
        "wrong-version": rflt([])[:4] + b"\0\2" + rflt([])[6:],
    }.items():
        steps = login() + [
            send(
                packet(
                    202, 10, payload([(201, b"mothra-fork-fixture"), (203, encoded)])
                )
            ),
            {"op": "pause", "seconds": 3},
            send(packet(500, 11)),
            read(match_frame={"is_reply": 1, "id": 11}),
            close(),
        ]
        cases["resume-download-" + name] = (
            steps,
            {"kind": "resume-no-reply", "rflt_hex": encoded.hex()},
        )
    return cases


def seed_upload(filename: bytes) -> tuple[list[dict], dict]:
    """Leave DATA13/MACR5 under the native incomplete-file type."""
    body = file_stream(b"data-fork\r\n\x00\xff", resource_fork())
    prefix = body[:-312]
    steps = login() + [
        send(
            packet(
                203, 10, payload([(201, filename), (108, len(body).to_bytes(4, "big"))])
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": 10},
            save_field={"name": "reference", "id": 107},
        ),
        connect("upload", "data"),
        send(
            "48545846{reference}"
            + len(body).to_bytes(4, "big").hex()
            + "00000000"
            + prefix.hex(),
            "upload",
        ),
        {"op": "expect_quiet", "connection": "upload", "timeout": 3},
        close("upload"),
        {"op": "pause", "seconds": 2},
        send(packet(206, 11, payload([(201, filename)]))),
        read(match_frame={"is_reply": 1, "id": 11}),
        close(),
    ]
    return steps, {
        "kind": "upload-prefix",
        "name_hex": filename.hex(),
        "prefix_hex": prefix.hex(),
        "full_stream_hex": body.hex(),
    }


def upload_probes() -> dict[str, tuple[list[dict], dict]]:
    """Seed an interrupted native upload, then inspect resume negotiation."""
    filename = b"mothra-resume-partial"
    cases = {"resume-upload-seed": seed_upload(filename)}
    body = file_stream(b"data-fork\r\n\x00\xff", resource_fork())
    for name, target_name in [
        ("partial", filename),
        ("missing", b"mothra-missing-partial"),
        ("completed", b"mothra-fork-fixture"),
    ]:
        cases["resume-upload-probe-" + name] = (
            login()
            + [
                send(
                    packet(
                        203,
                        10,
                        payload(
                            [
                                (201, target_name),
                                (204, b"\0\1"),
                                (108, len(body).to_bytes(4, "big")),
                            ]
                        ),
                    )
                ),
                read(match_frame={"is_reply": 1, "id": 10}),
                close(),
            ],
            {"kind": "resume-upload-probe", "name_hex": target_name.hex()},
        )
    return cases


def finish_upload(filename: bytes, inconsistent: bool) -> tuple[list[dict], dict]:
    """Build the plan that completes a resumed upload with consistent or inconsistent forks."""
    data = b"data-fork\r\n\x00\xff" if inconsistent else b""
    resource = resource_fork() if inconsistent else resource_fork()[5:]
    body = file_stream(data, resource)
    fields = [(201, filename), (204, b"\0\1"), (108, len(body).to_bytes(4, "big"))]
    if inconsistent:
        fields.append((203, rflt([(b"DATA", 0), (b"MACR", 0)])))
    steps = login() + [
        send(packet(203, 10, payload(fields))),
        read(
            match_frame={"is_reply": 1, "id": 10},
            save_fields={"reference": 107, "offsets": 203},
        ),
        connect("upload", "data"),
        send(
            "48545846{reference}"
            + len(body).to_bytes(4, "big").hex()
            + "00000000"
            + body.hex(),
            "upload",
        ),
        eof("upload"),
        close("upload"),
        send(packet(206, 11, payload([(201, filename)]))),
        read(match_frame={"is_reply": 1, "id": 11}),
        send(packet(202, 12, payload([(201, filename)]))),
        read(
            match_frame={"is_reply": 1, "id": 12},
            save_fields={"download_reference": 107, "size": 108},
        ),
        connect("download", "data"),
        send("48545846{download_reference}0000000000000000", "download"),
        {"op": "read", "connection": "download", "size_from": "size", "timeout": 30},
        {"op": "expect_quiet", "connection": "download", "timeout": 3},
        close("download"),
        close(),
    ]
    return steps, {
        "kind": "resume-upload-completion",
        "name_hex": filename.hex(),
        "inconsistent": inconsistent,
        "stream_hex": body.hex(),
    }


def upload_continuations() -> dict[str, tuple[list[dict], dict]]:
    """Build the plans that continue a partial upload and an inconsistent one."""
    other = b"mothra-resume-inconsistent"
    return {
        "resume-upload-complete": finish_upload(b"mothra-resume-partial", False),
        "resume-upload-inconsistent-seed": seed_upload(other),
        "resume-upload-inconsistent-complete": finish_upload(other, True),
    }
