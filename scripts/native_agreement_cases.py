"""Prepare agreement-content controls using the observed native login paths."""

from native_auth_cases import PASSWORD, complement
from native_auth_cases import states as auth_states
from native_plan import close, login, packet, payload, read, send
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
    return {
        name + "-" + label: (steps, {**expected, "phase": name})
        for label, (steps, expected) in auth_states().items()
        if label in {"early-admin", "delayed-admin", "early-bypass", "delayed-bypass"}
    }


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
