"""Constants, record builders and socket, bounds and report helpers.

The fakes choose every reply, so the tests check fixture control flow and
receipt conservation. Their responses are not native path observations.
"""

import json
import socket
import typing as typ
from pathlib import Path

import native_path_fields_cases as cases
import native_path_fields_control as control

if typ.TYPE_CHECKING:
    from path_fields_wire import FakeWire


# Kinds of the synthetic model that native_wire_names does not name. They are
# neutral local names, not protocol terms.
TYPE_NEWS_LIST = 370  # the news listing that the model answers
TYPE_NEWS_DELETE = 380  # the removal of a news folder or category
TYPE_NEWS_FOLDER_CREATE = 381  # the creation of a news folder
TYPE_NEWS_CATEGORY_CREATE = 382  # the creation of a news category
FIELD_NEWS_RECORD = 323  # the record field of a news listing reply


def file_record(name: bytes) -> bytes:
    """Encode one file entry of a listing reply.

    Returns
    -------
    bytes
        The sixteen-byte header, the name length and the name.
    """
    return bytes(16) + len(name).to_bytes(4, "big") + name


def news_record(name: bytes, *, folder: bool) -> bytes:
    """Encode one news entry of a listing reply.

    Returns
    -------
    bytes
        The encoded folder or category record.
    """
    if folder:
        return b"\0\2\0\0" + bytes([len(name)]) + name + b"\0"
    return b"\0\3\0\0" + bytes(24) + bytes([len(name)]) + name + bytes(3)


def non_blocking_socket_pair() -> tuple[socket.socket, socket.socket]:
    """Open a connected socket pair whose owned end is non-blocking.

    Returns
    -------
    tuple[socket.socket, socket.socket]
        The owned end, set non-blocking, and the peer end.
    """
    owned, peer = socket.socketpair()
    owned.setblocking(False)  # ruff: ignore[boolean-positional-value-in-call]  # setblocking takes its flag positionally
    return owned, peer


def wire_bounds(plan: dict) -> dict:
    """Give the bounds of the real wire for the plan's endpoint.

    Returns
    -------
    dict
        The endpoint and the schedule limits of the bounded transport.
    """
    return {
        "endpoint": plan["endpoint"],
        "schedule": {
            "max_bytes": 65536,
            "max_frames": 8,
            "max_tail_bytes_per_flow": 4096,
            "max_simultaneous": 1,
        },
    }


def model_report(wire: FakeWire, plan: dict, result: dict) -> dict:
    """Assemble the report of a completed model run, as the runner writes it.

    Returns
    -------
    dict
        The report whose hashes and timings the verifier replays.
    """
    return {
        "status": "completed",
        "error": "",
        "views": result["views"],
        "results": result["results"],
        "progress": result["progress"],
        "events": wire.recorder.events,
        "frames": wire.frames,
        "actions": wire.actions,
        "streams": wire.recorder.streams(),
        "terminals": wire.terminals,
        "unparsed_hex": {"main": ""},
        "request_count": wire.request_count,
        "mutation_count": 20,
        "plan_sha256": cases.sha((json.dumps(plan, indent=2) + "\n").encode()),
        "cases_sha256": control.sha(Path(cases.__file__).read_bytes()),
        "source_sha256": control.sha(Path(control.__file__).read_bytes()),
        "oracle_sha256": control.ORACLE_SHA256,
    }
