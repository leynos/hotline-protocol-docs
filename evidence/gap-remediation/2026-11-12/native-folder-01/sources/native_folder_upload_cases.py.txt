"""Prepare empty, partial, resumed and conflicting native folder uploads."""

from native_folder_cases import PARTIAL, descriptor, path, upload_start, word
from native_plan import close, connect, eof, packet, payload, read, send
from native_queue_cases import session
from native_resume_cases import rflt
from native_transfer_cases import file_stream, resource_fork


def empty_uploads() -> dict[str, tuple[list[dict], dict]]:
    steps = upload_start(b"mothra-folder-dirlast", 1, 0)
    steps += [
        send(descriptor((b"only",), True).hex(), "folder"),
        word(3),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    return {
        "folder-upload-zero-items": (
            upload_start(b"mothra-folder-empty", 0, 0),
            {"kind": "folder-upload-zero-items"},
        ),
        "folder-upload-directory-last": (
            steps,
            {"kind": "folder-upload-directory-last"},
        ),
    }


def catalogue_flush() -> dict[str, tuple[list[dict], dict]]:
    """Finalize an independent file; INFO restoration invokes native FlushVol."""
    body = file_stream(b"", b"")
    steps = session("a") + [
        send(
            packet(
                203,
                10,
                payload(
                    [(201, b"mothra-folder-flush"), (108, len(body).to_bytes(4, "big"))]
                ),
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
        close("a"),
    ]
    return {
        "folder-catalogue-flush": (
            steps,
            {
                "kind": "folder-catalogue-flush",
                "scope": "Auxiliary finalization outside tested folder roots; native FlushVol return is unchecked",
            },
        )
    }


def partial_seed() -> dict[str, tuple[list[dict], dict]]:
    body = file_stream(b"data-fork\r\n\x00\xff", resource_fork())
    steps = upload_start(PARTIAL, 3, 2 * len(body))
    steps += [
        send(descriptor((b"alpha",), False).hex(), "folder"),
        word(1),
        send((len(body).to_bytes(4, "big") + body).hex(), "folder"),
        word(3),
    ]
    steps += [
        send(descriptor((b"part",), False).hex(), "folder"),
        word(1),
        send((len(body).to_bytes(4, "big") + body[:-312]).hex(), "folder"),
    ]
    steps += [
        {"op": "expect_quiet", "connection": "folder", "timeout": 3},
        close("folder"),
        {"op": "pause", "seconds": 2},
    ]
    for identifier, name in [(11, b"alpha"), (12, b"part")]:
        steps += [
            send(
                packet(
                    206, identifier, payload([(201, name), (202, path((PARTIAL,)))])
                ),
                "a",
            ),
            read("a", match_frame={"is_reply": 1, "id": identifier}),
        ]
    steps += [close("a")]
    return {
        "folder-upload-partial-seed": (
            steps,
            {
                "kind": "folder-upload-partial-seed",
                "declared_items": 3,
                "completed_items": 1,
                "partial_data": 13,
                "partial_resource": 5,
            },
        )
    }


def resumed_uploads() -> dict[str, tuple[list[dict], dict]]:
    body = file_stream(b"", resource_fork()[5:])
    steps = upload_start(PARTIAL, 3, 660, True)
    steps += [send(descriptor((b"alpha",), False).hex(), "folder"), word(3)]
    value = rflt([(b"DATA", 13), (b"MACR", 5)])
    steps += [
        send(descriptor((b"part",), False).hex(), "folder"),
        word(2),
        {
            "op": "read",
            "connection": "folder",
            "size": 2,
            "expect_hex": len(value).to_bytes(2, "big").hex(),
            "timeout": 30,
        },
        {
            "op": "read",
            "connection": "folder",
            "size": len(value),
            "expect_hex": value.hex(),
            "timeout": 30,
        },
    ]
    steps += [send((len(body).to_bytes(4, "big") + body).hex(), "folder"), word(3)]
    steps += [
        send(descriptor((b"finish",), True).hex(), "folder"),
        word(3),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    cases = {"folder-upload-resume": (steps, {"kind": "folder-upload-resume"})}
    for name, directory in [("completed-skip", False), ("directory-conflict", True)]:
        steps = upload_start(PARTIAL, 1, 330, True)
        steps += [
            send(descriptor((b"alpha",), directory).hex(), "folder"),
            word(3),
            eof("folder"),
            close("folder"),
            close("a"),
        ]
        cases["folder-upload-" + name] = (steps, {"kind": "folder-upload-" + name})
    return cases
