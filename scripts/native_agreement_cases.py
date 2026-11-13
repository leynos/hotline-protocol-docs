"""Prepare agreement-content controls using the observed native login paths."""

import hashlib

from native_auth_cases import PASSWORD, authentication, complement, roster
from native_auth_cases import states as auth_states
from native_folder_cases import descriptor, upload_start, word
from native_plan import close, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream

PHASES = [
    "original",
    "absent",
    "empty",
    "directory",
    "text",
    "binary",
    "text-limit",
    "text-over-limit",
    "binary-over-limit",
    "binary-field-over-limit",
    "nontext",
    "nontext-over-limit",
    "nontext-field-over-limit",
    "restored",
]
TEXT = b"Agreement\r\nsecond\nline\r\nbyte:\x80\x00end"
FILES = {
    "empty": (b"m-agree-empty", b"TEXT", b""),
    "text": (b"m-agree-text", b"TEXT", TEXT),
    "binary": (b"m-agree-binary", b"BINA", TEXT),
    "text-limit": (b"m-agree-t-limit", b"TEXT", b"T" * 65535),
    "text-over-limit": (b"m-agree-t-over", b"TEXT", b"T" * 65536),
    "binary-over-limit": (b"m-agree-b-over", b"BINA", b"B" * 262141),
    "binary-field-over-limit": (b"m-agree-b-field", b"BINA", b"B" * 65536),
}
NON_TEXT_FILES = {
    # One GUI setup retyped BINA Agreement.txt as TEXT. Verify the installed type;
    # recognized BMP supplies a separate non-TEXT control with raw content.
    "nontext": (b"m-agree-nontext", b"BMP ", TEXT),
    "nontext-over-limit": (b"m-agree-n-over", b"BMP ", b"B" * 262141),
    "nontext-field-over-limit": (b"m-agree-n-field", b"BMP ", b"B" * 65536),
}
ORIGINAL_AGREEMENT_SHA256 = (
    "52f3930366ef00471568a7de275c4b7d7e826274604c058e2fdf0bc6976cc91a"
)


def restore_stage(data: bytes) -> dict:
    if hashlib.sha256(data).hexdigest() != ORIGINAL_AGREEMENT_SHA256:
        raise ValueError("Restoration requires the retained original agreement")
    return {
        "stage-agreement-restored": staged_file(
            b"m-agr-restored", b"Agreement.txt", b"TEXT", data
        )
    }


def staged_file(root: bytes, filename: bytes, kind: bytes, data: bytes) -> tuple:
    """Upload a correctly named child so Finder need only move/replace it."""
    if len(kind) != 4:
        raise ValueError("Finder type must contain four bytes")
    body = bytearray(file_stream(data, b""))
    body[44:48] = kind
    steps = upload_start(root, 1, len(body)) + [
        send(descriptor((filename,), False).hex(), "folder"),
        word(1),
        send((len(body).to_bytes(4, "big") + body).hex(), "folder"),
        {"op": "read_eof", "connection": "folder", "timeout": 30, "expect_hex": ""},
        close("folder"),
        {"op": "pause", "seconds": 2},
        close("a"),
    ]
    return steps, {
        "kind": "agreement-staged-file",
        "root_hex": root.hex(),
        "filename_hex": filename.hex(),
        "finder_type_hex": kind.hex(),
        "data_hex": data.hex(),
    }


def stages() -> dict:
    cases = {
        "stage-agreement-" + name: staged_file(
            b"m-agr-" + name.encode(), b"Agreement.txt", kind, data
        )
        for name, (_, kind, data) in (FILES | NON_TEXT_FILES).items()
    }
    cases["stage-agreement-directory"] = (
        upload_start(b"m-agr-directory", 1, 0)
        + [
            send(descriptor((b"Agreement.txt",), True).hex(), "folder"),
            word(3),
            eof("folder"),
            close("folder"),
            close("a"),
        ],
        {"kind": "agreement-staged-directory"},
    )
    return cases


def preflight() -> dict:
    return {
        "preflight-bypass-absence": (
            login()
            + [
                send(packet(352, 10, payload([(105, b"m-auth-bypass")]))),
                read(),
                close(),
            ],
            {"kind": "agreement-account-preflight"},
        )
    }


def seed() -> dict:
    steps = login() + [
        send(
            packet(
                350,
                10,
                payload(
                    [
                        (105, complement(b"m-auth-bypass")),
                        (106, complement(PASSWORD)),
                        (102, b"Agreement bypass"),
                        (110, bytes.fromhex("0000003000000000")),
                    ]
                ),
            )
        ),
        read(),
    ]
    for identifier, (filename, kind, data) in enumerate(FILES.values(), 20):
        body = bytearray(file_stream(data, b""))
        body[44:48] = kind
        variable = f"ref{identifier}"
        steps += [
            send(
                packet(
                    203,
                    identifier,
                    payload([(201, filename), (108, len(body).to_bytes(4, "big"))]),
                )
            ),
            read(
                match_frame={"is_reply": 1, "id": identifier},
                save_field={"name": variable, "id": 107},
            ),
            {
                "op": "connect",
                "connection": variable,
                "endpoint": "data",
                "timeout": 10,
            },
            {
                "op": "send",
                "connection": variable,
                "hex": "48545846{"
                + variable
                + "}"
                + len(body).to_bytes(4, "big").hex()
                + "00000000"
                + body.hex(),
                "timeout": 30,
            },
            {"op": "read_eof", "connection": variable, "timeout": 30, "expect_hex": ""},
            close(variable),
        ]
    steps += [{"op": "pause", "seconds": 3}, close()]
    return {"seed-agreement-files": (steps, {"kind": "agreement-seed"})}


def phase(name: str) -> dict:
    if name not in PHASES:
        raise ValueError("Unknown agreement phase")
    if name.endswith("field-over-limit"):
        return field_overflow(name)
    return {
        name + "-" + label: (steps, {**expected, "phase": name})
        for label, (steps, expected) in auth_states().items()
        if label in {"early-admin", "delayed-admin", "early-bypass", "delayed-bypass"}
    }


def field_overflow(name: str) -> dict:
    """Observe partial login after a loaded buffer exceeds the TLV field cap."""
    cases = {}
    for early in [False, True]:
        steps = [{**s, "connection": "observer"} for s in login()[:3]]
        steps += [
            authentication(b"m-auth-bypass", PASSWORD, connection="observer"),
            read("observer"),
            read("observer"),
            read("observer"),
        ] + roster(10)
        steps += [{**s, "connection": "subject"} for s in login()[:3]]
        steps += [
            authentication(
                b"admin",
                b"mothra19",
                name=b"auth-visible" if early else None,
                icon=b"\0\1" if early else None,
                connection="subject",
            ),
            read("subject"),
        ]
        if early:
            steps += [read("subject")]
        steps += [
            {"op": "expect_quiet", "connection": "subject", "timeout": 3},
            send(packet(500, 91), "subject"),
        ]
        if early:
            steps += [read("subject", match_frame={"is_reply": 1, "id": 91})] + roster(
                12
            )
            for kind, identifier in [(121, 2), (107, 3)]:
                steps += [
                    send(packet(kind, identifier), "subject"),
                    read("subject", match_frame={"is_reply": 1, "id": identifier}),
                ]
            steps += roster(13)
        else:
            steps += [eof("subject")] + roster(12)
        steps += [close("subject"), {"op": "pause", "seconds": 3}]
        steps += roster(14 if early else 13)
        steps += [close("observer")]
        label = "early" if early else "delayed"
        cases[name + "-" + label] = (
            steps,
            {"kind": "agreement-field-overflow", "phase": name, "early": early},
        )
    return cases


def cleanup() -> dict:
    return {
        "remove-agreement-bypass-account": (
            login()
            + [
                send(packet(351, 10, payload([(105, complement(b"m-auth-bypass"))]))),
                read(),
                send(packet(352, 11, payload([(105, b"m-auth-bypass")]))),
                read(),
                close(),
            ],
            {"kind": "agreement-account-cleanup"},
        )
    }
