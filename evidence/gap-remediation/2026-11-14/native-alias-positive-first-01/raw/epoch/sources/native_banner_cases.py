"""Prepare banner metadata and raw-stream observations for recorded GUI phases."""

from native_plan import close, connect, eof, login, packet, payload, quiet, read, send
from native_queue_cases import cancel, pump

URL = b"https://example.invalid/mothra-banner"
LINK = URL
GIF_A = bytes.fromhex(
    "47494638396101000100800000000000ffffff21fe040d0a00ff00"
    "2c00000000010001000002024401003b"
)
GIF_B = GIF_A.replace(b"\r\n\x00\xff", b"B\n\x00\xfe") + b"native-banner-b"


def delayed(version: int = 190) -> list[dict]:
    """Omit settings at107 so121 performs completion and optional122 emission."""
    fields = [
        (105, bytes(x ^ 255 for x in b"admin")),
        (106, bytes(x ^ 255 for x in b"mothra19")),
        (160, version.to_bytes(2, "big")),
    ]
    return login()[:3] + [
        send(packet(107, 1, payload(fields))),
        read(),
        read(),
        send(packet(121, 2, payload([(102, b"banner-fixture"), (104, b"\0\1")]))),
        read(),
        read(),
    ]


def metadata(phase: str, tag: bytes | None, link: bytes | None) -> dict:
    """Use a matched500 reply to preserve all preceding122 frames."""
    cases = {}
    for version in [150, 151, 190]:
        cases[f"{phase}-metadata-{version}"] = (
            delayed(version) + pump("main", 90, seconds=0) + [close()],
            {
                "kind": "metadata",
                "phase": phase,
                "version": version,
                "type_hex": tag.hex() if tag is not None else None,
                "link_hex": link.hex() if link is not None else None,
            },
        )
    cases[phase + "-early"] = (
        login() + pump("main", 90, seconds=0) + [close()],
        {"kind": "early", "phase": phase},
    )
    if tag in {None, b"URL "}:
        cases[phase + "-request212"] = (
            login()
            + [send(packet(212, 10)), quiet()]
            + pump("main", 90, seconds=0)
            + [close()],
            {"kind": "no-reply-212", "phase": phase, "window_seconds": 3},
        )
    return cases


def request() -> list[dict]:
    return [
        send(packet(212, 10)),
        read(
            save_fields={"ref": 107, "size": 108},
            match_frame={"is_reply": 1, "id": 10},
        ),
    ]


def attach(reference: str = "{ref}", selector: int = 2) -> list[dict]:
    return [
        connect("banner", "data"),
        send("48545846" + reference + "00000000" + f"{selector:04x}0000", "banner"),
    ]


def image() -> dict:
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
                    "timeout": 30,
                },
                {"op": "expect_quiet", "connection": "banner", "timeout": 3},
            ]
            if accepted
            else [eof("banner")]
        )
        steps += [close("banner")] + pump("main", 90) + [close()]
        cases["local-a-" + name] = (
            steps,
            {"kind": "raw" if accepted else "reject", "selector": selector},
        )
    steps = login() + request() + cancel("main", 11, "ref") + attach()
    steps += [
        {"op": "read", "connection": "banner", "size_from": "size", "timeout": 30}
    ]
    steps += cancel("main", 12, "ref") + [
        {"op": "expect_quiet", "connection": "banner", "timeout": 3},
        close("banner"),
        close(),
    ]
    cases["local-a-cancel214"] = (steps, {"kind": "cancel-does-not-close"})
    return cases


def changed() -> dict:
    """Pause for the documented GUI switch from the43-byte A fixture to58-byte B."""
    steps = delayed() + pump("main", 9, seconds=0) + request()
    steps += [{"op": "pause", "seconds": 45}] + attach()
    steps += [
        {"op": "read", "connection": "banner", "size": len(GIF_B), "timeout": 30},
        {"op": "expect_quiet", "connection": "banner", "timeout": 3},
        close("banner"),
    ]
    steps += pump("main", 90, seconds=0) + [close()]
    return {
        "changed-buffer": (
            steps,
            {"kind": "changed", "advertised": len(GIF_A), "delivered": len(GIF_B)},
        )
    }


def seed() -> dict:
    """Upload binary Finder types so the loader preserves CRLF bytes."""
    from native_transfer_cases import file_stream

    cases = {}
    for name, raw in [(b"mothra-banner-a.gif", GIF_A), (b"mothra-banner-b.gif", GIF_B)]:
        body = file_stream(raw, b"").replace(b"AMACTEXTMOTH", b"AMACGIFfMOTH", 1)
        steps = login() + [
            send(
                packet(
                    203, 10, payload([(201, name), (108, len(body).to_bytes(4, "big"))])
                )
            ),
            read(save_field={"name": "ref", "id": 107}),
            connect("upload", "data"),
            send(
                "48545846{ref}"
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
        cases["seed-" + name.decode()] = (
            steps,
            {"kind": "seed", "data_hex": raw.hex()},
        )
    return cases


def absent_restored() -> dict:
    """Attach after a failed load, then restoreB during the second45-second pause."""
    steps = login() + request() + [{"op": "pause", "seconds": 45}] + attach()
    steps += [
        {"op": "expect_quiet", "connection": "banner", "timeout": 3},
        {"op": "pause", "seconds": 45},
    ]
    steps += pump("main", 80, seconds=0)
    steps += [
        {"op": "read", "connection": "banner", "size": len(GIF_B), "timeout": 30},
        {"op": "expect_quiet", "connection": "banner", "timeout": 3},
        close("banner"),
    ]
    steps += pump("main", 90, seconds=0) + [close()]
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


def expired() -> dict:
    """Keep the owner responsive while an unattached banner entry ages."""
    steps = login() + request()
    for identifier in range(20, 32):
        steps += pump("main", identifier, seconds=45)
    steps += attach() + [eof("banner"), close("banner"), close()]
    return {
        "expired-reference": (steps, {"kind": "expired", "planned_pause_seconds": 540})
    }
