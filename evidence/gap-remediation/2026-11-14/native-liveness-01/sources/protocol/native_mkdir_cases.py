"""Prepare owned native directory creation and path-boundary observations."""

from native_auth_cases import authentication
from native_folder_cases import path
from native_plan import close, connect, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream

ROOT = b"mothra-fs19"
BASE = path((ROOT,))


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[dict]:
    """Return the steps that send one request and read its reply."""
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def seed() -> dict:
    """Build the plan that creates the folders and file the cases use."""
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
    """Return the folder creation cases, each with its name, parent, view and role."""
    cases = []

    def add(
        label: str,
        name: bytes | None,
        parent: bytes | None = BASE,
        view: bytes = BASE,
        role: str = "admin",
    ) -> None:
        """Append one folder creation case to the list."""
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
    for label, parent, child in [
        ("path-dot-component", b".", b"literal-dot"),
        ("path-dotdot-component", b"..", b"literal-dotdot"),
        ("path-colon-component", b"co:lon", b"inside-colon"),
        ("path-high-component", b"hi-\x9a", b"inside-high"),
        ("path-nul-component", b"\0nul", b"inside-nul"),
    ]:
        view_parent = b"co-lon" if parent == b"co:lon" else parent
        add(label, child, path((ROOT, parent)), path((ROOT, view_parent)))
    return cases


def creation() -> dict:
    """Build one plan per case that creates a folder and reads the parent back."""
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


def finalization() -> dict:
    """Build the plan that uploads a flush file and reads back the folders the cases made."""
    body = file_stream(b"", b"")
    steps = login() + [
        send(
            packet(
                203,
                10,
                payload([(201, b"m-fs19-flush"), (108, len(body).to_bytes(4, "big"))]),
            )
        ),
        read(
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
    ]
    for identifier, parts in [
        (20, ()),
        (21, (ROOT,)),
        (22, (ROOT, b"nest")),
        (23, (ROOT, b"nest", b"leaf")),
        (24, (ROOT, b".")),
        (25, (ROOT, b"..")),
        (26, (ROOT, b"co-lon")),
        (27, (ROOT, b"hi-\x9a")),
        (28, (ROOT, b"\0nul")),
    ]:
        steps += exchange(200, identifier, [(202, path(parts))])
    steps += (
        exchange(206, 30, [(201, ROOT)])
        + exchange(206, 31, [(201, b"ordinary"), (202, BASE)])
        + [close()]
    )
    return {"final-inventory-and-flush": (steps, {"kind": "mkdir-final"})}


def cleanup() -> dict:
    """Build the plan that deletes the owned folders and the flush file."""
    names = (
        [ROOT]
        + [bytes.fromhex(c["name_hex"]) for c in specs() if c["view_hex"] == "0000"]
        + [b"m-fs19-flush"]
    )
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    for identifier, name in enumerate(names, 20):
        steps += exchange(204, identifier, [(201, name)])
    steps += exchange(200, 90, [(202, b"\0\0")]) + exchange(500, 91, [])
    steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
    return {
        "cleanup-owned-objects": (
            steps,
            {
                "kind": "mkdir-cleanup",
                "names_hex": [n.hex() for n in names],
                "scope": "Native204 moves owned objects to Trash; no permanent deletion or root outside Files requested.",
            },
        )
    }


def empty_root() -> dict:
    """Check absent/empty names against absent/empty/canonical-root paths."""
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    inputs = []
    for name in [None, b""]:
        for parent in [None, b"", b"\0\0"]:
            values = []
            if name is not None:
                values.append((201, name))
            if parent is not None:
                values.append((202, parent))
            identifier = 20 + len(inputs)
            inputs.append(
                {
                    "id": identifier,
                    "name_hex": None if name is None else name.hex(),
                    "path_hex": None if parent is None else parent.hex(),
                }
            )
            steps += exchange(205, identifier, values)
    steps += exchange(200, 90, [(202, b"\0\0")]) + exchange(500, 91, [])
    steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
    return {
        "empty-root-input-matrix": (
            steps,
            {"kind": "mkdir-empty-root", "inputs": inputs},
        )
    }
