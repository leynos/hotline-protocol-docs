"""Observe folder timer origins with bounded, recorded control activity."""

from native_folder_cases import descriptor, upload_start, word
from native_plan import close, connect, eof, send
from native_queue_cases import pump


def uploads() -> dict[str, tuple[list[dict], dict]]:
    late = upload_start(b"mothra-folder-late", 1, 0)
    # Delay before attaching: omit the final connect/HTXF/initial-ready actions.
    late = late[:-3]
    for identifier, seconds in [(100, 45), (101, 45), (102, 35)]:
        late += pump("a", identifier, seconds)
    late += [
        connect("folder", "data"),
        send("48545846{reference}0000000000010000", "folder"),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    delayed = upload_start(b"mothra-folder-descriptor-delay", 2, 0)
    delayed += pump("a", 100, 45) + pump("a", 101, 45)
    delayed += [send(descriptor((b"wait",), True).hex(), "folder"), word(3)]
    delayed += pump("a", 102, 20) + pump("a", 103, 20)
    delayed += [eof("folder"), close("folder"), close("a")]
    return {
        "folder-upload-late-attachment": (
            late,
            {"kind": "folder-upload-late-attachment", "pause_seconds": 125},
        ),
        "folder-upload-descriptor-delay": (
            delayed,
            {
                "kind": "folder-upload-descriptor-delay",
                "pause_seconds": 130,
                "directory_pause_before": 90,
            },
        ),
    }
