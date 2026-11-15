"""Prepare banner metadata and raw-stream observations for recorded GUI phases."""

import typing as typ

from native_plan import (
    COMPLEMENT_MASK,
    LOGIN_REQUEST_ID,
    QUIET_WINDOW_SECONDS,
    READ_TIMEOUT_SECONDS,
    Action,
    close,
    connect,
    eof,
    login,
    packet,
    payload,
    quiet,
    read,
    send,
)
from native_queue_cases import cancel, pump
from native_transfer_cases import file_stream
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_VERSION,
    HTXF_MAGIC_HEX,
    SELECTOR_BANNER,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_DOWNLOAD_BANNER,
    TYPE_GET_FILE_INFO,
    TYPE_LOGIN,
    TYPE_UPLOAD_FILE,
)

type Case = tuple[list[Action], dict[str, typ.Any]]

URL = b"https://example.invalid/mothra-banner"
LINK = URL
GIF_A = bytes.fromhex(
    "47494638396101000100800000000000ffffff21fe040d0a00ff00"
    "2c00000000010001000002024401003b"
)
GIF_B = GIF_A.replace(b"\r\n\x00\xff", b"B\n\x00\xfe") + b"native-banner-b"

# A native success reply carries version 190 (native_wire_names, FIELD_VERSION).
NATIVE_VERSION = 190
# The reported versions that the metadata cases sweep.
METADATA_VERSIONS = (150, 151, NATIVE_VERSION)
VERSION_BYTES = 2  # the reported version is a two-byte big-endian word
LENGTH_BYTES = 4  # the four-byte size word of a transfer
# The HTXF greeting is the magic, the reference, a four-byte size word, a
# two-byte selector and a reserved word (native_wire_names, HTXF_MAGIC_HEX).
HTXF_SIZE_HEX = "00000000"  # the size word of a banner greeting, which sends zero
HTXF_RESERVED_HEX = "0000"  # the reserved word after the selector
# The selector word and the reserved word of an upload greeting, both zero.
HTXF_UPLOAD_TAIL_HEX = "00000000"
GUI_PAUSE_SECONDS = 45  # the pause for the documented GUI switch between fixtures
AGING_PUMP_SECONDS = 45  # each pump keeps the owner responsive while an entry ages
EXPIRY_PAUSE_SECONDS = 540  # the planned total of the twelve aging pumps


def delayed(version: int = NATIVE_VERSION) -> list[Action]:
    """Omit settings at 107 so 121 performs completion and optional 122 emission.

    Returns
    -------
    list[native_plan.Action]
        The login that reports ``version``, then the accept step and the reads of
        their replies.
    """
    fields = [
        (FIELD_LOGIN, bytes(x ^ COMPLEMENT_MASK for x in b"admin")),
        (FIELD_PASSWORD, bytes(x ^ COMPLEMENT_MASK for x in b"mothra19")),
        (FIELD_VERSION, version.to_bytes(VERSION_BYTES, "big")),
    ]
    return [
        *login()[:3],
        send(packet(TYPE_LOGIN, LOGIN_REQUEST_ID, payload(fields))),
        read(),
        read(),
        send(
            packet(
                TYPE_ACCEPT_AGREEMENT,
                2,
                payload([(FIELD_NAME, b"banner-fixture"), (FIELD_ICON, b"\0\1")]),
            )
        ),
        read(),
        read(),
    ]


def metadata(phase: str, tag: bytes | None, link: bytes | None) -> dict[str, Case]:
    """Use a matched 500 reply to preserve all preceding 122 frames.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The metadata, early and request cases of ``phase``, by name.
    """
    cases: dict[str, Case] = {}
    for version in METADATA_VERSIONS:
        cases[f"{phase}-metadata-{version}"] = (
            [*delayed(version), *pump("main", 90, seconds=0), close()],
            {
                "kind": "metadata",
                "phase": phase,
                "version": version,
                "type_hex": tag.hex() if tag is not None else None,
                "link_hex": link.hex() if link is not None else None,
            },
        )
    cases[phase + "-early"] = (
        [*login(), *pump("main", 90, seconds=0), close()],
        {"kind": "early", "phase": phase},
    )
    if tag in {None, b"URL "}:
        cases[phase + "-request212"] = (
            [
                *login(),
                send(packet(TYPE_DOWNLOAD_BANNER, 10)),
                quiet(),
                *pump("main", 90, seconds=0),
                close(),
            ],
            {
                "kind": "no-reply-212",
                "phase": phase,
                "window_seconds": QUIET_WINDOW_SECONDS,
            },
        )
    return cases


def request() -> list[Action]:
    """Plan a banner download request and the read of its reply.

    Returns
    -------
    list[native_plan.Action]
        The send of request 212 and a reply read that saves the reference and the
        size.
    """
    return [
        send(packet(TYPE_DOWNLOAD_BANNER, 10)),
        read(
            save_fields={"ref": FIELD_TRANSFER_REFERENCE, "size": FIELD_TRANSFER_SIZE},
            match_frame={"is_reply": 1, "id": 10},
        ),
    ]


def attach(reference: str = "{ref}", selector: int = SELECTOR_BANNER) -> list[Action]:
    """Plan opening a banner data connection and its greeting.

    Returns
    -------
    list[native_plan.Action]
        The connect, then the greeting that names the reference and the selector.
    """
    return [
        connect("banner", "data"),
        send(
            HTXF_MAGIC_HEX
            + reference
            + HTXF_SIZE_HEX
            + f"{selector:04x}"
            + HTXF_RESERVED_HEX,
            "banner",
        ),
    ]


def image() -> dict[str, Case]:
    """Plan the banner image cases: selectors, unknown and zero references, cancel.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The metadata cases and the raw, reject and cancel cases, by name.
    """
    cases = metadata("local-a", b"GIFf", LINK)
    for name, selector, reference in [
        ("raw", 2, "{ref}"),
        ("selector0", 0, "{ref}"),
        ("selector1", 1, "{ref}"),
        ("selector7", 7, "{ref}"),
        ("unknown", 2, "ffffffff"),
        ("zero", 2, "00000000"),
    ]:
        accepted = name == "raw"
        steps = login() + request() + attach(reference, selector)
        steps += (
            [
                {
                    "op": "read",
                    "connection": "banner",
                    "size_from": "size",
                    "timeout": READ_TIMEOUT_SECONDS,
                },
                {
                    "op": "expect_quiet",
                    "connection": "banner",
                    "timeout": QUIET_WINDOW_SECONDS,
                },
            ]
            if accepted
            else [eof("banner")]
        )
        steps += [close("banner"), *pump("main", 90), close()]
        cases["local-a-" + name] = (
            steps,
            {"kind": "raw" if accepted else "reject", "selector": selector},
        )
    steps = login() + request() + cancel("main", 11, "ref") + attach()
    steps += [
        {
            "op": "read",
            "connection": "banner",
            "size_from": "size",
            "timeout": READ_TIMEOUT_SECONDS,
        }
    ]
    steps += [
        *cancel("main", 12, "ref"),
        {"op": "expect_quiet", "connection": "banner", "timeout": QUIET_WINDOW_SECONDS},
        close("banner"),
        close(),
    ]
    cases["local-a-cancel214"] = (steps, {"kind": "cancel-does-not-close"})
    return cases


def changed() -> dict[str, Case]:
    """Pause for the documented GUI switch from the 43-byte A fixture to 58-byte B.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The ``changed-buffer`` case.
    """
    steps = delayed() + pump("main", 9, seconds=0) + request()
    steps += [{"op": "pause", "seconds": GUI_PAUSE_SECONDS}, *attach()]
    steps += [
        {
            "op": "read",
            "connection": "banner",
            "size": len(GIF_B),
            "timeout": READ_TIMEOUT_SECONDS,
        },
        {"op": "expect_quiet", "connection": "banner", "timeout": QUIET_WINDOW_SECONDS},
        close("banner"),
    ]
    steps += [*pump("main", 90, seconds=0), close()]
    return {
        "changed-buffer": (
            steps,
            {"kind": "changed", "advertised": len(GIF_A), "delivered": len(GIF_B)},
        )
    }


def seed() -> dict[str, Case]:
    """Upload binary Finder types so the loader preserves CRLF bytes.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The upload case of each GIF fixture, by name.
    """
    cases: dict[str, Case] = {}
    for name, raw in [(b"mothra-banner-a.gif", GIF_A), (b"mothra-banner-b.gif", GIF_B)]:
        body = file_stream(raw, b"").replace(b"AMACTEXTMOTH", b"AMACGIFfMOTH", 1)
        size = len(body).to_bytes(LENGTH_BYTES, "big")
        steps = [
            *login(),
            send(
                packet(
                    TYPE_UPLOAD_FILE,
                    10,
                    payload([(FIELD_FILE_NAME, name), (FIELD_TRANSFER_SIZE, size)]),
                )
            ),
            read(save_field={"name": "ref", "id": FIELD_TRANSFER_REFERENCE}),
            connect("upload", "data"),
            send(
                HTXF_MAGIC_HEX
                + "{ref}"
                + size.hex()
                + HTXF_UPLOAD_TAIL_HEX
                + body.hex(),
                "upload",
            ),
            eof("upload"),
            close("upload"),
            send(packet(TYPE_GET_FILE_INFO, 11, payload([(FIELD_FILE_NAME, name)]))),
            read(),
            close(),
        ]
        cases["seed-" + name.decode()] = (
            steps,
            {"kind": "seed", "data_hex": raw.hex()},
        )
    return cases


def absent_restored() -> dict[str, Case]:
    """Attach after a failed load, then restore B during the second 45-second pause.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The ``absent-restored`` case.
    """
    steps = [
        *login(),
        *request(),
        {"op": "pause", "seconds": GUI_PAUSE_SECONDS},
        *attach(),
    ]
    steps += [
        {"op": "expect_quiet", "connection": "banner", "timeout": QUIET_WINDOW_SECONDS},
        {"op": "pause", "seconds": GUI_PAUSE_SECONDS},
    ]
    steps += pump("main", 80, seconds=0)
    steps += [
        {
            "op": "read",
            "connection": "banner",
            "size": len(GIF_B),
            "timeout": READ_TIMEOUT_SECONDS,
        },
        {"op": "expect_quiet", "connection": "banner", "timeout": QUIET_WINDOW_SECONDS},
        close("banner"),
    ]
    steps += [*pump("main", 90, seconds=0), close()]
    return {
        "absent-restored": (
            steps,
            {
                "kind": "absent-restored",
                "advertised": len(GIF_B),
                "delivered": len(GIF_B),
            },
        )
    }


def expired() -> dict[str, Case]:
    """Keep the owner responsive while an unattached banner entry ages.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The ``expired-reference`` case.
    """
    steps = login() + request()
    for identifier in range(20, 32):
        steps += pump("main", identifier, seconds=AGING_PUMP_SECONDS)
    steps += [*attach(), eof("banner"), close("banner"), close()]
    return {
        "expired-reference": (
            steps,
            {"kind": "expired", "planned_pause_seconds": EXPIRY_PAUSE_SECONDS},
        )
    }
