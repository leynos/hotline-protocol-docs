"""Prepare multi-chunk native download cleanup and completion races."""

from native_plan import close, connect, eof, packet, payload, read, send
from native_queue_cases import attach, cancel, session
from native_transfer_cases import file_stream, resource_fork

FILENAME = b"mothra-race-fixture"


def data_fork() -> bytes:
    return bytes(range(256)) * 4096


def seed() -> dict[str, tuple[list[dict], dict]]:
    body = file_stream(data_fork(), resource_fork())
    steps = session("a") + [
        send(
            packet(
                203, 10, payload([(201, FILENAME), (108, len(body).to_bytes(4, "big"))])
            ),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_field={"name": "reference", "id": 107},
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
        send(packet(206, 11, payload([(201, FILENAME)])), "a"),
        read("a", match_frame={"is_reply": 1, "id": 11}),
        close("a"),
    ]
    return {
        "cleanup-seed": (
            steps,
            {"kind": "cleanup-seed", "data_bytes": len(data_fork())},
        )
    }


def upload_cleanup() -> dict[str, tuple[list[dict], dict]]:
    """Prove214 does not remove the pending ordinary-upload collection entry."""
    filename = b"mothra-214-upload"
    body = file_stream(b"data-fork\r\n\x00\xff", resource_fork())
    steps = (
        session("a")
        + [
            send(
                packet(
                    203,
                    10,
                    payload([(201, filename), (108, len(body).to_bytes(4, "big"))]),
                ),
                "a",
            ),
            read(
                "a",
                match_frame={"is_reply": 1, "id": 10},
                save_field={"name": "reference", "id": 107},
            ),
        ]
        + cancel("a", 11, "reference")
        + [
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
            send(packet(206, 12, payload([(201, filename)])), "a"),
            read("a", match_frame={"is_reply": 1, "id": 12}),
        ]
        + cancel("a", 13, "reference")
        + [close("a")]
    )
    return {
        "cleanup-pending-upload": (
            steps,
            {"kind": "cleanup-upload", "name_hex": filename.hex()},
        )
    }


def downloads() -> dict[str, tuple[list[dict], dict]]:
    cases = {}
    variants = (
        [("baseline", 0), ("nonowner", 0)]
        + [(f"immediate-{i}", 0) for i in range(1, 4)]
        + [(f"partial-{i}", 1024) for i in range(1, 4)]
    )
    for name, prefix_size in variants:
        steps = session("a")
        if name == "nonowner":
            steps += session("b")
        steps += [
            send(packet(202, 10, payload([(201, FILENAME)])), "a"),
            read(
                "a",
                match_frame={"is_reply": 1, "id": 10},
                save_fields={"reference": 107, "size": 108},
            ),
        ] + attach("reference")
        if name in {"baseline", "nonowner"}:
            if name == "nonowner":
                steps += cancel("b", 20, "reference")
            steps += [
                {
                    "op": "read",
                    "connection": "reference",
                    "size_from": "size",
                    "timeout": 30,
                },
                {"op": "expect_quiet", "connection": "reference", "timeout": 3},
            ]
        elif prefix_size:
            steps += [
                {
                    "op": "read",
                    "connection": "reference",
                    "size": prefix_size,
                    "timeout": 30,
                }
            ]
        steps += cancel("a", 21, "reference")
        steps += [
            {"op": "read_eof", "connection": "reference", "timeout": 30},
            close("reference"),
        ]
        steps += cancel("a", 22, "reference")
        steps += [
            connect("stale", "data"),
            send("48545846{reference}0000000000000000", "stale"),
            eof("stale"),
            close("stale"),
        ]
        if name == "nonowner":
            steps += [close("b")]
        steps += [close("a")]
        cases["cleanup-" + name] = (
            steps,
            {"kind": "cleanup-download", "variant": name, "prefix_size": prefix_size},
        )
    return cases
