"""Prepare native transaction-ID, collision and reply-envelope observations."""

from native_plan import close, login, packet, payload, quiet, read, send


def probe(identifier: int) -> list[dict]:
    return [
        send(packet(500, identifier)),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def correlation() -> dict:
    cases = {}

    def add(name: str, steps: list[dict], expectation: dict) -> None:
        cases[name] = (login() + steps + [close()], expectation)

    ids = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0, 1]
    add(
        "client-id-boundaries-and-reuse",
        [step for identifier in ids for step in probe(identifier)],
        {"kind": "acks", "ids": ids},
    )
    add(
        "pipelined-duplicate-id",
        [send(packet(500, 10) * 2), read(), quiet()] + probe(11),
        {"kind": "acks", "ids": [10, 11]},
    )
    add(
        "pipelined-distinct-ids",
        [send(packet(500, 10) + packet(500, 11)), read(), read(), quiet()],
        {"kind": "acks", "ids": [10, 11]},
    )
    add(
        "duplicate-id-after-dispatch-pause",
        [
            send(packet(500, 10)),
            {"op": "pause", "seconds": 3},
            send(packet(500, 10)),
            read(),
            read(),
            quiet(),
        ],
        {"kind": "acks", "ids": [10, 10]},
    )
    add(
        "pipelined-id-collision-last-type",
        [
            send(
                packet(500, 10)
                + packet(304, 10, payload([(102, b"collision-name"), (104, b"\0\x07")]))
            ),
            read(match_frame={"type": 301, "is_reply": 0}),
            quiet(),
        ]
        + probe(11),
        {
            "kind": "collision-notification",
            "ids": [11],
            "name_hex": b"***".hex(),
            "icon": 0,
        },
    )
    for reply in [1, 2, 255]:
        add(
            f"late-reply-{reply}-completed-client-id",
            probe(10)
            + [
                send(packet(65535, 10, flags=255, reply=reply, error=0xFFFFFFFF)),
                quiet(),
            ]
            + probe(10),
            {"kind": "acks", "ids": [10, 10]},
        )
        add(
            f"reply-{reply}-server-notification-id",
            [send(packet(65535, 1, flags=255, reply=reply, error=0xFFFFFFFF)), quiet()]
            + probe(1),
            {"kind": "acks", "ids": [1]},
        )
    name = b"correlation-name"
    add(
        "notification-and-direct-reply-id-spaces",
        probe(1)
        + [
            send(packet(304, 1, payload([(102, name), (104, b"\0\x07")]))),
            read(match_frame={"type": 301, "is_reply": 0}),
        ]
        + probe(1),
        {"kind": "notification", "ids": [1, 1], "name_hex": name.hex(), "icon": 7},
    )
    add(
        "partial-request-and-wide-reply-same-id",
        [
            send(packet(500, 10, b"\0\0", total=4)),
            quiet(),
            send(packet(65535, 10, reply=255, flags=255, error=0xFFFFFFFF)),
            quiet(),
            send(packet(500, 10, b"\0\0", total=4)),
            read(),
        ],
        {"kind": "acks", "ids": [10]},
    )
    add(
        "incomplete-request-id-reused-with-smaller-total",
        [
            send(packet(500, 10, b"\0", total=100)),
            quiet(),
            send(packet(500, 10)),
            read(),
        ]
        + probe(10),
        {"kind": "acks", "ids": [10, 10]},
    )
    for kind in [0, 65535]:
        add(
            f"unsupported-request-type-{kind}",
            [send(packet(kind, 10, flags=255, error=0xFFFFFFFF)), read()] + probe(11),
            {"kind": "unsupported", "request_type": kind},
        )
    for flags in [1, 128]:
        add(
            f"request-flags-{flags}-error-ffffffff",
            [send(packet(500, 10, flags=flags, error=0xFFFFFFFF)), read()],
            {"kind": "acks", "ids": [10]},
        )
    for reply in [1, 255]:
        add(
            f"reply-{reply}-zero-size-rejection",
            [
                send(packet(65535, 1, b"", reply=reply, total=0, size=0)),
                {
                    "op": "read_eof",
                    "connection": "main",
                    "timeout": 30,
                    "expect_hex": "",
                },
            ],
            {"kind": "close"},
        )
    for name, raw in [
        ("partial-header-eof", packet(500, 10)[:18]),
        ("partial-frame-body-eof", packet(500, 10)[:-2]),
        ("underfilled-transaction-eof", packet(500, 10, b"\0\0", total=4)),
        (
            "interleaved-underfilled-transactions-eof",
            packet(500, 10, b"\0\0", total=4) + packet(500, 11, b"\0\0", total=4),
        ),
    ]:
        add(
            name,
            [
                send(raw),
                quiet(),
                {"op": "shutdown_write", "connection": "main"},
                {
                    "op": "read_eof",
                    "connection": "main",
                    "timeout": 30,
                    "expect_hex": "",
                },
            ],
            {"kind": "close"},
        )
    return cases
