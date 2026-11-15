"""Build the fixture bodies and upload steps of the owned alias tree."""

import typing as typ

from native_filp import decode
from native_folder_cases import path
from native_plan import close, connect, eof, packet, payload, read, send
from native_transfer_cases import file_stream, resource_fork

type Steps = list[dict[str, typ.Any]]
type Case = tuple[Steps, dict[str, typ.Any]]
type FileSpec = tuple[bytes, tuple[bytes, ...], bytes, bytes, bytes, bytes, bytes]

ROOT = b"mothra-alias20"
BASE = path((ROOT,))
DATA = b"alias-target\r\n\0\xff"
FILES: list[FileSpec] = [
    (b"file", (), DATA, resource_fork(), b"TEXT", b"MOTH", b"alias-comment"),
    (b"empty", (), b"", b"", b"TEXT", b"MOTH", b""),
    (b"zero-tags", (), b"zero-tags", b"", bytes(4), bytes(4), b""),
    (b"unknown-tags", (), b"unknown-data", b"", b"XxYz", b"ZzQq", b"unknown-comment"),
    (b"same", (), b"same-source", b"", b"TEXT", b"MOTH", b"source-comment"),
    (b"self", (), b"self-source", b"", b"TEXT", b"MOTH", b"self-comment"),
    (b"hi-\x9a", (), b"high", b"", b"TEXT", b"MOTH", b""),
    *[
        (name, (), b"default-target", b"", b"TEXT", b"MOTH", b"")
        for name in [b"m-al20-absent", b"m-al20-empty", b"m-al20-zero"]
    ],
    (b"leaf", (b"dir",), b"dir-leaf", b"", b"TEXT", b"MOTH", b""),
    (
        b"same",
        (b"C",),
        b"collision-destination",
        b"",
        b"TEXT",
        b"MOTH",
        b"destination-comment",
    ),
    (b"keep", (b"C", b"dir"), b"keep", b"", b"TEXT", b"MOTH", b""),
]


def body(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    data: bytes, resource: bytes, kind: bytes, creator: bytes, comment: bytes
) -> bytes:
    """Build the FILP upload body of a file with the given forks and tags.

    Returns
    -------
    bytes
        The complete FILP stream, with INFO, DATA and MACR forks.
    """
    forks = decode(file_stream(data, resource))
    info = bytearray(forks["INFO"])
    info[4:12] = kind + creator
    info[16:20] = bytes(4)
    offset = 72 + int.from_bytes(info[70:72], "big")
    info = info[:offset] + len(comment).to_bytes(2, "big") + comment
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


def upload(
    identifier: int, name: bytes, parent: tuple[bytes, ...], value: bytes
) -> Steps:
    """Plan the upload of ``value`` as ``name`` into ``parent``, then close it.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps: the request, its reply, the data connection and its end.
    """
    channel, reference = f"up{identifier}", f"ref{identifier}"
    return [
        send(
            packet(
                203,
                identifier,
                payload([
                    (201, name),
                    (202, path((ROOT, *parent))),
                    (108, len(value).to_bytes(4, "big")),
                ]),
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": identifier},
            save_field={"name": reference, "id": 107},
        ),
        connect(channel, "data"),
        send(
            "48545846{"
            + reference
            + "}"
            + len(value).to_bytes(4, "big").hex()
            + "00000000"
            + value.hex(),
            channel,
        ),
        eof(channel),
        close(channel),
    ]
