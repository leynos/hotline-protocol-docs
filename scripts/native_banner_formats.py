"""Build banner format fixtures and a recovery probe with protocol phase checks."""

from pathlib import Path

from native_banner_cases import GIF_A, GIF_B, URL, attach, delayed, request
from native_folder_cases import descriptor, upload_start, word
from native_plan import close, eof, login, send
from native_queue_cases import pump, session
from native_transfer_cases import file_stream

ASSETS = Path(__file__).resolve().parents[1] / "fixtures/banner"
# Native Finder type and advertised tag are deliberately kept separate.
FORMATS = {
    "empty": (b"m-img-e.gif", b"GIFf", b"GIFf", None),
    "jpeg": (b"m-img-j.jpg", b"JPEG", b"JPEG", "one.jpg"),
    "bmp": (b"m-img-b.bmp", b"BMP ", b"BMP ", "one.bmp"),
    "pict": (b"m-img-p.pct", b"PICT", b"PICT", "one.pct"),
    "fallback": (b"m-img-f.dat", b"PNGf", b"PNGf", "one.png"),
    "zero-type": (b"m-img-z.dat", bytes(4), None, "one.png"),
    "suffix-before-finder": (b"m-img-x.jpg", b"GIFf", b"JPEG", None),
    "text-conversion": (b"m-img-t", b"TEXT", b"TEXT", None),
}


def content(name: str) -> bytes:
    if name == "empty":
        return b""
    asset = FORMATS[name][3]
    return (ASSETS / asset).read_bytes() if asset else GIF_A


def seed_formats() -> dict:
    streams = {}
    for name, (filename, finder, _, _) in FORMATS.items():
        streams[filename] = file_stream(content(name), b"").replace(
            b"AMACTEXTMOTH", b"AMAC" + finder + b"MOTH", 1
        )
    steps = upload_start(
        b"mothra-banner-formats", len(streams), sum(map(len, streams.values()))
    )
    for index, (filename, body) in enumerate(streams.items()):
        steps += [
            send(descriptor((filename,), False).hex(), "folder"),
            word(1),
            send((len(body).to_bytes(4, "big") + body).hex(), "folder"),
        ]
        if index < len(streams) - 1:
            steps += [word(3)]
    steps += [eof("folder"), close("folder"), close("a")]
    return {
        "seed-formats": (
            steps,
            {"kind": "format-seed", "filenames_hex": [n.hex() for n in streams]},
        )
    }


def format_case(name: str) -> dict:
    filename, finder, tag, _ = FORMATS[name]
    expected = content(name)
    if finder == b"TEXT":
        expected = expected.replace(b"\r\n", b"\r")
    steps = delayed() + pump("main", 9, seconds=0) + request()
    if name == "empty":
        steps += (
            session("observer")
            + pump("main", 80, seconds=0)
            + pump("observer", 81, seconds=0)
        )
    steps += attach()
    if expected:
        steps += [
            {"op": "read", "connection": "banner", "size": len(expected), "timeout": 30}
        ]
    steps += (
        [{"op": "expect_quiet", "connection": "banner", "timeout": 3}]
        if expected
        else [eof("banner")]
    )
    steps += [close("banner")]
    if name == "empty":
        steps += [eof("main"), eof("observer"), close("observer"), close()]
    else:
        steps += pump("main", 90, seconds=0) + [close()]
    return {
        "format-" + name: (
            steps,
            {
                "kind": "format",
                "format": name,
                "filename_hex": filename.hex(),
                "finder_hex": finder.hex(),
                "tag_hex": tag.hex() if tag is not None else None,
                "data_hex": expected.hex(),
            },
        )
    }


def phase_check(connection: str, number: int) -> list[dict]:
    """Use a separately authenticated delayed session to observe loaded metadata."""
    steps = [{**s, "connection": connection} for s in delayed()]
    steps += pump(connection, number, seconds=0) + [close(connection)]
    return steps


def recovery(*, early: bool = False) -> dict:
    """Allow three minutes per GUI phase; confirm phases through fresh121 sessions."""
    steps = (login() if early else delayed() + pump("main", 9, seconds=0)) + request()
    for identifier in range(20, 26):
        steps += pump("main", identifier, seconds=30)
    steps += phase_check("absent", 91) + attach()
    steps += [{"op": "expect_quiet", "connection": "banner", "timeout": 3}]
    for identifier in range(30, 36):
        steps += pump("main", identifier, seconds=30)
    steps += phase_check("restored", 92) + pump("main", 80, seconds=0)
    steps += [
        {"op": "read", "connection": "banner", "size": len(GIF_B), "timeout": 30},
        {"op": "expect_quiet", "connection": "banner", "timeout": 3},
        close("banner"),
    ]
    steps += pump("main", 90, seconds=0) + [close()]
    return {
        ("phase-checked-early-recovery" if early else "phase-checked-recovery"): (
            steps,
            {
                "kind": "phase-checked-recovery",
                "initial_completion": "early" if early else "delayed",
                "advertised_bytes": len(GIF_B),
                "expected_bytes": GIF_B.hex(),
                "phases": {
                    "absent": None,
                    "restored": {"152": b"GIFf".hex(), "153": URL.hex()},
                },
                "planned_pause_seconds": 360,
            },
        )
    }
