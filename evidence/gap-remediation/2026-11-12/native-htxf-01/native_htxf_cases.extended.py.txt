"""Prepare HTXF field, collection, reference-use and attachment observations."""

from native_banner_cases import GIF_B
from native_folder_cases import ROOT
from native_plan import close, connect, eof, packet, payload, read, send
from native_queue_cases import cancel, pump, session
from native_transfer_cases import file_stream


def low_session() -> list[dict]:
    steps = session("b")
    fields = [
        (105, bytes(v ^ 255 for v in b"fixture-low")),
        (106, bytes(v ^ 255 for v in b"next-pass")),
        (160, b"\0\xbe"),
        (102, b"htxf-low"),
        (104, b"\0\1"),
    ]
    steps[3] = send(packet(107, 1, payload(fields)), "b")
    return steps


def request(kind: int = 212) -> list[dict]:
    values = (
        [(201, b"mothra-fork-fixture")]
        if kind == 202
        else [(201, ROOT)]
        if kind == 210
        else []
    )
    return [
        send(packet(kind, 10, payload(values)), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_fields={"ref": 107, "size": 108},
        ),
    ]


def header(
    selector: int = 2,
    size: int = 0,
    reserved: int = 0,
    reference: str = "{ref}",
    magic: str = "48545846",
) -> str:
    return magic + reference + f"{size:08x}{selector:04x}{reserved:04x}"


def attach(name: str, **options) -> list[dict]:
    return [connect(name, "data"), send(header(**options), name)]


def data(name: str) -> list[dict]:
    return [
        {
            "op": "read",
            "connection": name,
            "size": len(GIF_B),
            "expect_hex": GIF_B.hex(),
            "timeout": 30,
        }
    ]


def quiet(name: str) -> dict:
    return {"op": "expect_quiet", "connection": name, "timeout": 3}


def banners() -> dict:
    cases = {}
    for name, size, reserved, magic in [
        ("size-ffffffff-reserved-ffff", 0xFFFFFFFF, 65535, "48545846"),
        ("size-one-reserved-1234", 1, 0x1234, "48545846"),
        ("bad-magic", 0, 0, "48545847"),
    ]:
        steps = (
            session("a")
            + request()
            + attach("data", size=size, reserved=reserved, magic=magic)
        )
        steps += (
            data("data") + [quiet("data")] if name != "bad-magic" else [eof("data")]
        )
        steps += [close("data")] + pump("a", 90) + [close("a")]
        cases["banner-" + name] = (
            steps,
            {
                "kind": "banner-header",
                "size": size,
                "reserved": reserved,
                "magic": magic,
                "accepted": name != "bad-magic",
            },
        )
    steps = (
        session("a")
        + request()
        + [
            connect("data", "data"),
            send(header(reserved=0x1234)[:-2], "data"),
            quiet("data"),
            send(header(reserved=0x1234)[-2:], "data"),
        ]
        + data("data")
        + [quiet("data"), close("data")]
        + pump("a", 90)
        + [close("a")]
    )
    cases["banner-split-15-plus-1"] = (steps, {"kind": "split-header"})
    steps = (
        session("a")
        + low_session()
        + request()
        + attach("foreign")
        + data("foreign")
        + [quiet("foreign"), close("foreign")]
        + pump("a", 90)
        + pump("b", 91, seconds=0)
        + [close("a")]
        + pump("b", 92)
        + [close("b")]
    )
    cases["banner-separate-low-privilege-session"] = (steps, {"kind": "cross-session"})
    steps = (
        session("a")
        + low_session()
        + request()
        + [close("a")]
        + pump("b", 90)
        + attach("stale")
        + [eof("stale"), close("stale"), close("b")]
    )
    cases["banner-owner-gone"] = (steps, {"kind": "owner-gone"})
    steps = (
        session("a")
        + request()
        + attach("first")
        + data("first")
        + [close("first")]
        + pump("a", 90)
        + attach("stale")
        + [eof("stale"), close("stale"), close("a")]
    )
    cases["banner-reuse-after-close"] = (steps, {"kind": "reuse-after-close"})
    steps = (
        session("a")
        + low_session()
        + request()
        + attach("first")
        + data("first")
        + [quiet("first")]
        + attach("second")
        + [quiet("second"), close("a")]
        + pump("b", 90)
        + [eof("second"), quiet("first"), close("second"), close("first"), close("b")]
    )
    cases["banner-duplicate-after-send"] = (steps, {"kind": "duplicate-after-send"})
    return cases


def collections() -> dict:
    cases = {}
    steps = (
        session("a")
        + request(202)
        + attach("download", selector=65535, size=0xFFFFFFFF, reserved=0xABCD)
        + [
            {
                "op": "read",
                "connection": "download",
                "size_from": "size",
                "timeout": 30,
            },
            quiet("download"),
        ]
        + cancel("a", 11, "ref")
        + [eof("download"), close("download"), close("a")]
    )
    cases["download-size-reserved-selector-ffff"] = (
        steps,
        {"kind": "ordinary-download"},
    )
    for selector in [0, 2, 65535]:
        steps = (
            session("a")
            + request(210)
            + attach("wrong", selector=selector)
            + [eof("wrong"), close("wrong"), close("a")]
        )
        cases[f"folder-download-wrong-selector-{selector}"] = (
            steps,
            {"kind": "folder-wrong-selector", "selector": selector},
        )
    for selector in [0, 2, 65535]:
        filename = f"m-htxf-u{selector}".encode()
        raw = b"header-routing-" + str(selector).encode()
        body = file_stream(raw, b"")
        advertised = len(body) + (37 if selector == 0 else 0)
        steps = (
            session("a")
            + [
                send(
                    packet(
                        203,
                        10,
                        payload(
                            [(201, filename), (108, advertised.to_bytes(4, "big"))]
                        ),
                    ),
                    "a",
                ),
                read(
                    "a",
                    match_frame={"is_reply": 1, "id": 10},
                    save_field={"name": "ref", "id": 107},
                ),
            ]
            + attach("upload", selector=selector, size=len(body), reserved=65535)
            + [
                send(body.hex(), "upload"),
                eof("upload"),
                close("upload"),
                send(packet(206, 11, payload([(201, filename)])), "a"),
                read("a", match_frame={"is_reply": 1, "id": 11}),
                close("a"),
            ]
        )
        cases[f"upload-nonfolder-selector-{selector}"] = (
            steps,
            {
                "kind": "ordinary-upload",
                "selector": selector,
                "filename_hex": filename.hex(),
                "data_hex": raw.hex(),
                "body_hex": body.hex(),
                "request_size": advertised,
            },
        )
    for gone in [False, True]:
        steps = session("a") + low_session() + request(202)
        if gone:
            steps += [close("a")] + pump("b", 90)
        steps += attach("download", selector=0)
        if gone:
            steps += [eof("download"), close("download"), close("b")]
        else:
            steps += [
                {"op": "read", "connection": "download", "size_from": "size"},
                quiet("download"),
            ]
            steps += cancel("a", 11, "ref")
            steps += [eof("download"), close("download"), close("a")]
            steps += pump("b", 90) + [close("b")]
        name = (
            "download-owner-gone" if gone else "download-separate-low-privilege-session"
        )
        cases[name] = (steps, {"kind": name})
    return cases


def htxf() -> dict:
    return banners() | collections()
