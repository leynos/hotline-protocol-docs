"""Prepare ordinary-fork upload and download observation cases."""

import struct

from native_plan import close, connect, eof, login, packet, payload, read, send


def resource_fork() -> bytes:
    """Build a small resource fork with one test resource."""
    value = b"native!"
    data = struct.pack(">I", len(value)) + value
    header = struct.pack(">IIII", 256, 256 + len(data), len(data), 50)
    resource_map = (
        header
        + bytes(8)
        + struct.pack(">HHH4sHHHHII", 28, 50, 0, b"TEST", 0, 10, 128, 65535, 0, 0)
    )
    return header + bytes(240) + data + resource_map


def file_stream(data: bytes, resource: bytes) -> bytes:
    """Use a different embedded name to test that INFO does not rename files."""
    embedded = b"metadata-only-name"
    comment = b"fixture-comment"
    info = bytearray(74 + len(embedded) + len(comment))
    info[:12] = b"AMACTEXTMOTH"
    info[16:20] = (0x8100).to_bytes(4, "big")
    info[70:72] = len(embedded).to_bytes(2, "big")
    info[72 : 72 + len(embedded)] = embedded
    p = 72 + len(embedded)
    info[p : p + 2] = len(comment).to_bytes(2, "big")
    info[p + 2 :] = comment
    return (
        b"FILP\0\1"
        + bytes(16)
        + b"\0\3"
        + b"".join(
            tag + bytes(8) + len(value).to_bytes(4, "big") + value
            for tag, value in [
                (b"INFO", bytes(info)),
                (b"DATA", data),
                (b"MACR", resource),
            ]
        )
    )


def transfers() -> dict[str, tuple[list[dict], dict]]:
    """Build the plans that upload a file with forks and an empty file."""
    cases: dict[str, tuple[list[dict], dict]] = {}
    for name, data, resource in [
        (b"mothra-fork-fixture", b"data-fork\r\n\x00\xff", resource_fork()),
        (b"mothra-empty-fixture", b"", b""),
    ]:
        body = file_stream(data, resource)
        handover = name == b"mothra-empty-fixture"
        steps = login() + [
            send(
                packet(
                    203, 10, payload([(201, name), (108, len(body).to_bytes(4, "big"))])
                )
            ),
            read(save_field={"name": "upload_ref", "id": 107}),
            connect("upload", "control" if handover else "data"),
        ]
        if handover:
            steps += [
                {
                    "op": "send",
                    "connection": "upload",
                    "hex": "54525450484f544c00010003",
                },
                {
                    "op": "read",
                    "connection": "upload",
                    "size": 8,
                    "expect_hex": "5452545000000000",
                    "timeout": 10,
                },
            ]
        steps += [
            send(
                "48545846{upload_ref}"
                + len(body).to_bytes(4, "big").hex()
                + "00000000"
                + body.hex(),
                "upload",
            ),
            eof("upload"),
            close("upload"),
            send(packet(206, 11, payload([(201, name)]))),
            read(),
            close(),
        ]
        cases["upload-empty-handover" if handover else "upload-" + name.decode()] = (
            steps,
            {
                "kind": "upload",
                "name_hex": name.hex(),
                "data_hex": data.hex(),
                "resource_hex": resource.hex(),
                "stream_hex": body.hex(),
            },
        )
        if handover:
            cases["upload-empty-handover"][1]["handover"] = True
    return cases


def downloads() -> dict[str, tuple[list[dict], dict]]:
    """Build one plan per case that downloads a file raw, previewed or through a selector."""
    cases = {}
    for case, name, preview, handover, selector in [
        ("raw", b"mothra-fork-fixture", False, False, 0),
        ("handover", b"mothra-fork-fixture", False, True, 0),
        ("selector7", b"mothra-fork-fixture", False, False, 7),
        ("preview", b"mothra-fork-fixture", True, False, 0),
        ("empty", b"mothra-empty-fixture", False, False, 0),
        ("empty-preview", b"mothra-empty-fixture", True, False, 0),
        ("wrong-folder-selector", b"mothra-fork-fixture", False, False, 1),
        ("wrong-banner-selector", b"mothra-fork-fixture", False, False, 2),
    ]:
        fields = [(201, name)] + ([(204, b"\0\2")] if preview else [])
        steps = login() + [send(packet(202, 10, payload(fields)))]
        if case == "empty-preview":
            steps += [read(), close()]
        else:
            steps += [
                read(save_fields={"download_ref": 107, "download_size": 108}),
                connect("download", "control" if handover else "data"),
            ]
            if handover:
                steps += [
                    send("54525450484f544c00010003", "download"),
                    {
                        "op": "read",
                        "connection": "download",
                        "size": 8,
                        "expect_hex": "5452545000000000",
                        "timeout": 10,
                    },
                ]
            steps += [
                send(
                    "48545846{download_ref}00000000"
                    + selector.to_bytes(2, "big").hex()
                    + "0000",
                    "download",
                )
            ]
            if selector in {1, 2}:
                steps += [eof("download")]
            else:
                steps += [
                    {
                        "op": "read",
                        "connection": "download",
                        "size_from": "download_size",
                        "timeout": 30,
                    },
                    {"op": "expect_quiet", "connection": "download", "timeout": 3},
                ]
                if case == "raw":
                    steps += [
                        send(
                            packet(214, 11, payload([(107, b"REF!")])).replace(
                                b"REF!".hex(), "{download_ref}"
                            )
                        ),
                        read(),
                        eof("download"),
                    ]
            steps += [close("download"), close()]
        cases["download-" + case] = (
            steps,
            {
                "kind": "download",
                "name_hex": name.hex(),
                "preview": preview,
                "handover": handover,
                "selector": selector,
            },
        )
    return cases
