"""Prepare owned native directory creation and path-boundary observations."""

from native_auth_cases import authentication
from native_folder_cases import path
from native_plan import close, connect, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream

ROOT = b"mothra-fs19"
BASE = path((ROOT,))


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[dict]:
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def seed() -> dict:
    steps = login() + exchange(200, 9, [(202, b"\0\0")])
    for identifier, name, parent in [
        (10, ROOT, b"\0\0"),
        (11, b"exists", BASE),
        (12, b"nest", BASE),
        (13, b"leaf", path((ROOT, b"nest"))),
    ]:
        steps += exchange(205, identifier, [(201, name), (202, parent)])
    body = file_stream(b"mkdir-fixture", b"")
    steps += [
        send(
            packet(
                203,
                14,
                payload(
                    [
                        (201, b"ordinary"),
                        (202, BASE),
                        (108, len(body).to_bytes(4, "big")),
                    ]
                ),
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": 14},
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
    ]
    steps += exchange(200, 15, [(202, BASE)]) + [close()]
    return {"seed-owned-root": (steps, {"kind": "mkdir-seed", "root_hex": ROOT.hex()})}


def specs() -> list[dict]:
    cases = []

    def add(
        label: str,
        name: bytes | None,
        parent: bytes | None = BASE,
        view: bytes = BASE,
        role: str = "admin",
    ) -> None:
        cases.append(
            {
                "case": label,
                "name_hex": None if name is None else name.hex(),
                "path_hex": None if parent is None else parent.hex(),
                "view_hex": view.hex(),
                "role": role,
            }
        )

    for label, name in [
        ("ascii", b"plain"),
        ("existing-directory", b"exists"),
        ("existing-file", b"ordinary"),
        ("case-collision", b"EXISTS"),
        ("name-absent", None),
        ("name-empty", b""),
        ("name-nul-only", b"\0"),
        ("name-nul-interior", b"nu\0l"),
        ("name-nul-leading", b"\0nul"),
        ("name-nul-trailing", b"nul\0"),
        ("name-colon", b"co:lon"),
        ("name-slash", b"sl/ash"),
        ("name-cr", b"cr\rname"),
        ("name-lf", b"lf\nname"),
        ("name-high-byte", b"hi-\x9a"),
        ("name31", b"n31-" + b"a" * 27),
        ("name32", b"n32-" + b"b" * 28),
        ("name255", b"n255-" + b"c" * 250),
        ("name256", b"n256-" + b"d" * 251),
        ("name65535", b"n65535-" + b"e" * (65535 - 7)),
        ("long-extension", b"ext-" + b"x" * 36 + b".txt"),
        ("dot-name", b"."),
        ("dotdot-name", b".."),
    ]:
        add(label, name)
    add(
        "nested",
        b"nested-child",
        path((ROOT, b"nest", b"leaf")),
        path((ROOT, b"nest", b"leaf")),
    )
    add("parent-file", b"no-file-parent", path((ROOT, b"ordinary")))
    add("parent-missing", b"no-missing-parent", path((ROOT, b"absent-parent")))
    for label, parent in [
        ("root-absent", None),
        ("root-empty", b""),
        ("root-zero-count", b"\0\0"),
        ("path-one-byte", b"\0"),
        ("path-count-only", b"\0\1"),
        ("path-five-bytes", b"\0\1\0\0\1"),
    ]:
        add(label, ("m-fs19-" + label).encode(), parent, b"\0\0")
    add("path-truncated-last", b"truncated-last", b"\0\2" + BASE[2:] + b"\0\0\5ab")
    add("path-empty-component", b"empty-component", b"\0\2" + BASE[2:] + b"\0\0\0")
    add("path-word-ffff", b"word-ffff", b"\0\1\xff\xff" + BASE[4:])
    add("path-trailing", b"trailing", BASE + b"\xde\xad")
    add(
        "path-count-zero-trailing", b"m-fs19-zero-trailing", b"\0\0" + BASE[2:], b"\0\0"
    )
    add("path-count-too-high", b"count-too-high", b"\0\2" + BASE[2:])
    add(
        "path-supplies-name",
        None,
        path((ROOT, b"nest", b"via-path")),
        path((ROOT, b"nest")),
    )
    add(
        "empty-name-path-supplies",
        b"",
        path((ROOT, b"nest", b"via-empty")),
        path((ROOT, b"nest")),
    )
    add("low-permission-new", b"denied-new", role="low")
    add("low-permission-conflict", b"exists", role="low")
    return cases


def creation() -> dict:
    cases = {}
    for expected in specs():
        steps = login()
        if expected["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        view = bytes.fromhex(expected["view_hex"])
        values = []
        for field, key in [(201, "name_hex"), (202, "path_hex")]:
            if expected[key] is not None:
                values.append((field, bytes.fromhex(expected[key])))
        steps += exchange(200, 10, [(202, view)])
        steps += exchange(205, 11, values)
        steps += exchange(200, 12, [(202, view)])
        steps += exchange(500, 90, [])
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        cases[expected["case"]] = (steps, {"kind": "mkdir-create", **expected})
    return cases
