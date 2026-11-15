"""Observe folder timer origins with bounded, recorded control activity."""

from native_folder_steps import (
    FOLDER_CONNECTION_HEX,
    Cases,
    descriptor,
    upload_start,
    word,
)
from native_plan import close, connect, eof, send
from native_queue_cases import pump
from native_wire_names import FOLDER_CONTROL_NEXT

LATE_TRIM_STEPS = 3  # a late attachment omits the connect, HTXF greeting and ready word
LATE_PUMPS = [(100, 45), (101, 45), (102, 35)]
LATE_PAUSE_SECONDS = 125  # the late attachment's recorded pause
DELAY_BEFORE_PUMPS = [(100, 45), (101, 45)]  # before the first descriptor
DELAY_AFTER_PUMPS = [(102, 20), (103, 20)]  # after the first descriptor
DELAY_PAUSE_SECONDS = 130  # the descriptor-delay scenario's recorded pause
DIRECTORY_PAUSE_SECONDS = 90  # the pause before the delayed directory descriptor


def uploads() -> Cases:
    """Plan the late-attachment and descriptor-delay upload observations.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The two timing cases, by name.
    """
    late = upload_start(b"mothra-folder-late", 1, 0)
    # Delay before attaching: omit the final connect/HTXF/initial-ready actions.
    late = late[:-LATE_TRIM_STEPS]
    for identifier, seconds in LATE_PUMPS:
        late += pump("a", identifier, seconds)
    late += [
        connect("folder", "data"),
        send(FOLDER_CONNECTION_HEX, "folder"),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    delayed = upload_start(b"mothra-folder-descriptor-delay", 2, 0)
    for identifier, seconds in DELAY_BEFORE_PUMPS:
        delayed += pump("a", identifier, seconds)
    delayed += [
        send(descriptor((b"wait",), directory=True).hex(), "folder"),
        word(FOLDER_CONTROL_NEXT),
    ]
    for identifier, seconds in DELAY_AFTER_PUMPS:
        delayed += pump("a", identifier, seconds)
    delayed += [eof("folder"), close("folder"), close("a")]
    return {
        "folder-upload-late-attachment": (
            late,
            {
                "kind": "folder-upload-late-attachment",
                "pause_seconds": LATE_PAUSE_SECONDS,
            },
        ),
        "folder-upload-descriptor-delay": (
            delayed,
            {
                "kind": "folder-upload-descriptor-delay",
                "pause_seconds": DELAY_PAUSE_SECONDS,
                "directory_pause_before": DIRECTORY_PAUSE_SECONDS,
            },
        ),
    }
