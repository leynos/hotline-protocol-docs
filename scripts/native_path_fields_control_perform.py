"""Perform the 212/325 path matrix on the wire.

Part of the path-fields runner (``native_path_fields_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below.
"""

import collections
import dataclasses as dc
import typing as typ

import native_path_fields_cases as cases
from native_path_fields_control_frames import (
    MARKERS,
    PARENTS,
    Report,
    exact_transition,
    file_info,
    file_view,
    location,
    login_gate,
    need,
    news_view,
    one,
    record_view,
    success,
)
from native_plan import login
from native_wire_names import (
    FIELD_FILE_PATH,
    TYPE_LIST_FILES,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    from native_path_fields_control_wire import Wire

REQUEST_CAP = 99
HELLO_REPLY_BYTES = 8
LOGIN_WAIT_SECONDS = 5
REPLY_WAIT_SECONDS = 5
STOP_PROBE_ID = 9000
SETTLED_PHASES = frozenset({"initial", "setup-view", "final"})
CASE_COUNT = 12
NEWS_HIGH = {"field": 323, "kind": 3}
WRAPPER_NAMES = (b"S".hex(), b"H-\x9a".hex())
ONLY_FILES_PHASE = "files-"
FILES_PHASE_PREFIX_LENGTH = len(ONLY_FILES_PHASE)
NEWS_PHASE_PREFIX_LENGTH = len("news-")
MARKER_BASE = 48
NEWS_FIELD = 325
FILES_FIELD = 212
TYPE_GET_USER_ROSTER_LABEL = "initial-roster"


def exchange(
    wire: Wire, spec: Report, connection: str, parent: bytes | None = None
) -> Report:
    """Send one request, count it and wait for its direct reply.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    if connection == "main":
        need(wire.request_count < REQUEST_CAP, "Per-connection request cap reached")
    raw = cases.raw_request(spec, parent)
    before = len(wire.frames)
    wire.send(connection, raw, spec["label"])
    if connection == "main":
        wire.request_count += 1
        wire.partial["request_count"] = wire.request_count
        if spec["mutation"]:
            wire.partial["mutation_count"] += 1
    if parent is not None:
        wire.actions[-1]["dynamic_parent_hex"] = parent.hex()
    wire.wait_for(
        lambda: bool(wire.match(connection, 0, spec["id"], 1)),
        REPLY_WAIT_SECONDS,
        spec["label"],
    )
    reply = one(wire.frames[before:], connection, spec["id"])
    need(reply["flags"] == 0, "Reply flags differ")
    return reply


def connect_login(wire: Wire, name: str, guard: cabc.Callable[[], None]) -> None:
    """Connect a flow, log it in as the admin and check the replies."""
    guard()
    need(len(wire.recorder.sockets) == 0, "Previous connection still open")
    wire.execute({"op": "connect", "connection": name, "endpoint": "control"})
    wire.execute({"op": "send", "connection": name, "hex": cases.HELLO})
    wire.execute({
        "op": "read",
        "connection": name,
        "size": HELLO_REPLY_BYTES,
        "expect_hex": cases.HELLO_REPLY,
    })
    wire.buffers[name] = bytearray()
    wire.send(name, login()[3]["hex"], f"{name}-login")
    if name == "main":
        wire.request_count += 1
    wire.wait_for(
        lambda: (
            bool(wire.match(name, 0, 1, 1))
            and bool(wire.match(name, 354, None, 0))
            and bool(wire.match(name, 109, None, 0))
        ),
        LOGIN_WAIT_SECONDS,
        f"{name} login",
    )
    login_gate(wire.frames, name)


@dc.dataclass(slots=True)
class Matrix:
    """What the matrix has seen so far, kept so that a failure still reports it."""

    wire: Wire
    plan: Report
    views: list[Report] = dc.field(default_factory=list)
    results: list[Report] = dc.field(default_factory=list)
    progress: list[str] = dc.field(default_factory=list)
    after_views: dict[str, list[str]] = dc.field(default_factory=dict)
    first_views: dict[str, list[str]] = dc.field(default_factory=dict)
    before_case_views: dict[str, list[str]] = dc.field(default_factory=dict)
    first_types: dict[str, dict[str, str]] = dc.field(default_factory=dict)
    before_case_types: dict[str, dict[str, str]] = dc.field(default_factory=dict)
    after_types: dict[str, dict[str, str]] = dc.field(default_factory=dict)
    selected: dict[str, str] = dc.field(
        default_factory=lambda: {m.hex(): "S" for m in MARKERS}
    )
    initial_news: list[Report] = dc.field(default_factory=list)


def _settled(matrix: Matrix, label: str, reply: Report) -> None:
    """Record a settled view and check what its label promises."""
    success(reply)
    value = record_view(matrix.views, label, reply)
    if label == "initial-roster":
        matrix.wire.partial["own_uid"] = value["uid"]
    if label == "initial-files-root":
        need(cases.FILES.hex() not in value["names"], "Owned Files name exists")
    if label == "initial-news-root":
        matrix.initial_news = value["names"]
        need(
            cases.NEWS.hex() not in {v["name_hex"] for v in matrix.initial_news},
            "Owned News name exists",
        )
    if label.startswith("setup-view-"):
        _setup_view(matrix, label.removeprefix("setup-view-"), value)
    if label == "setup-news-high":
        need(
            value["names"] == [{**NEWS_HIGH, "name_hex": cases.CATEGORY.hex()}],
            "News high setup differs",
        )


def _setup_view(matrix: Matrix, key: str, value: Report) -> None:
    """Keep a setup parent's view and, after the last, check all three."""
    matrix.first_views[key] = value["names"]
    matrix.first_types[key] = value["types"]
    if key == "H":
        need(
            collections.Counter(matrix.first_views.get("S", []))
            == collections.Counter(m.hex() for m in MARKERS)
            and collections.Counter(matrix.first_views.get("wrapper", []))
            == collections.Counter(WRAPPER_NAMES)
            and matrix.first_views.get("H") == [],
            "Foreign or duplicate setup entry",
        )


def _before_info(matrix: Matrix, spec: Report, reply: Report, i: int) -> None:
    """Start a files case: check the marker and take the views it begins from."""
    marker = b"p" + bytes([MARKER_BASE + i])
    file_info(reply, marker)
    matrix.before_case_views = dict(
        matrix.first_views if i == 0 else matrix.after_views
    )
    matrix.before_case_types = dict(
        matrix.first_types if i == 0 else matrix.after_types
    )
    matrix.after_views = {}
    matrix.after_types = {}
    before = matrix.before_case_views["S"]
    need(marker.hex() in before, "Marker missing before 208")
    matrix.results.append({
        "index": i,
        "field": FILES_FIELD,
        "value_hex": matrix.plan["cells"][i]["value_hex"],
        "before_parent": "S",
        "before_views": before,
        "same_parent_noop": False,
    })
    del spec


def _stop_probe(matrix: Matrix, i: int) -> None:
    """Take one counted read-only Files-root view, then stop the run.

    Raises
    ------
    ValueError
        Always: the marker is outside the selected owned parents.
    """
    wire = matrix.wire
    need(wire.request_count < REQUEST_CAP, "No stop-probe request reserve")
    extra = cases.request(
        f"stop-files-root-{i}",
        TYPE_LIST_FILES,
        STOP_PROBE_ID + i,
        [(FIELD_FILE_PATH, cases.FILES_ROOT)],
        "stop-probe",
    )
    extra_reply = exchange(wire, extra, "main")
    record_view(matrix.views, extra["label"], extra_reply)
    message = "Marker outside selected owned parents"
    raise ValueError(message)


def _after_views(matrix: Matrix, spec: Report, reply: Report) -> None:
    """Keep a parent's view after a move and, after the last, classify the move."""
    label = spec["label"]
    i = int(spec["phase"][FILES_PHASE_PREFIX_LENGTH:])
    marker = b"p" + bytes([MARKER_BASE + i])
    success(reply)
    parent_name = label.rsplit("-", 1)[-1]
    matrix.after_views[parent_name] = file_view(reply)
    matrix.after_types[parent_name] = record_view(matrix.views, label, reply)["types"]
    if parent_name != "H":
        return
    found = location(matrix.after_views, marker)
    if found is None:
        _stop_probe(matrix, i)
        return
    exact_transition(
        matrix.before_case_views,
        matrix.after_views,
        (marker, found),
        (matrix.before_case_types, matrix.after_types),
    )
    for other, old in matrix.selected.items():
        if other != marker.hex():
            need(
                location(matrix.after_views, bytes.fromhex(other)) == old,
                "Other marker location changed",
            )
    status = matrix.results[-1]["status"]
    need(
        (found != "S" and status == 0) or (found == "S" and status != 0),
        "Move status/location ambiguous",
    )
    matrix.results[-1]["selected_parent"] = found
    matrix.results[-1]["after_views"] = dict(matrix.after_views)
    matrix.selected[marker.hex()] = found


def _files(matrix: Matrix, spec: Report, reply: Report) -> None:
    """Handle one request of a files case, by its label."""
    label, phase = spec["label"], spec["phase"]
    i = int(phase[FILES_PHASE_PREFIX_LENGTH:])
    marker = b"p" + bytes([MARKER_BASE + i])
    if label.startswith("before-info-"):
        _before_info(matrix, spec, reply, i)
    elif label.startswith("move-"):
        matrix.results[-1].update(
            request_id=spec["id"], status=reply["error"], error_fields=reply["fields"]
        )
    elif label.startswith("after-view-"):
        _after_views(matrix, spec, reply)
    elif label.startswith("after-info-"):
        found = matrix.selected[marker.hex()]
        file_info(reply, marker)
        matrix.results[-1]["after_info_parent_hex"] = PARENTS[found].hex()
    elif label.startswith("barrier-"):
        success(reply)


def _news_parent(reply: Report, actual: list[Report], initial: list[Report]) -> str:
    """Name the parent that a news reply selects.

    Returns
    -------
    str
        ``news-root``, ``news-high``, ``empty``, ``foreign`` or ``error``.
    """
    if reply["error"] != 0:
        return "error"
    names = collections.Counter(v["name_hex"] for v in actual)
    root = collections.Counter(v["name_hex"] for v in initial)
    root[cases.NEWS.hex()] += 1
    if names == root:
        return "news-root"
    if names == collections.Counter([cases.CATEGORY.hex()]):
        return "news-high"
    return "empty" if not names else "foreign"


def _news(matrix: Matrix, spec: Report, reply: Report) -> None:
    """Handle one request of a news case, by its label."""
    if not spec["label"].startswith("news-"):
        success(reply)
        return
    i = int(spec["phase"][NEWS_PHASE_PREFIX_LENGTH:])
    actual = news_view(reply) if reply["error"] == 0 else []
    selected_parent = _news_parent(reply, actual, matrix.initial_news)
    need(selected_parent != "foreign", "Foreign News selection")
    matrix.results.append({
        "index": i,
        "field": NEWS_FIELD,
        "value_hex": matrix.plan["cells"][i]["value_hex"],
        "request_id": spec["id"],
        "status": reply["error"],
        "error_fields": reply["fields"] if reply["error"] else [],
        "names": actual,
        "selected_parent": selected_parent,
    })


def _request(matrix: Matrix, spec: Report) -> Report:
    """Send one planned request, with its dynamic parent if it has one.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    if spec["fields"] is None:
        marker = bytes.fromhex(spec["marker_hex"])
        parent_name = matrix.selected.get(marker.hex())
        need(parent_name in PARENTS, "Dynamic selected parent absent")
        return exchange(matrix.wire, spec, "main", PARENTS[str(parent_name)])
    return exchange(matrix.wire, spec, "main")


def perform(wire: Wire, plan: Report, guard: cabc.Callable[[], None]) -> Report:
    """Run every request of the plan and keep the progress on the wire.

    Parameters
    ----------
    wire : Wire
        The transport; its ``partial`` keeps the progress if the run fails.
    plan : dict[str, typing.Any]
        The prepared plan.
    guard : collections.abc.Callable[[], None]
        The runtime gate to run before the connection.

    Returns
    -------
    dict[str, typing.Any]
        The views, the results and the progress.
    """
    matrix = Matrix(wire, plan)
    wire.partial = {
        "views": matrix.views,
        "results": matrix.results,
        "progress": matrix.progress,
        "own_uid": None,
        "current_case_index": None,
        "request_count": 0,
        "mutation_count": 0,
    }
    connect_login(wire, "main", guard)
    wire.partial["request_count"] = wire.request_count
    for spec in plan["requests"]:
        label, phase = spec["label"], spec["phase"]
        if phase.startswith(("files-", "news-")):
            wire.partial["current_case_index"] = int(phase.split("-")[1])
        reply = _request(matrix, spec)
        if phase in SETTLED_PHASES:
            _settled(matrix, label, reply)
        elif phase in {"setup", "cleanup"}:
            success(reply)
        elif phase.startswith("files-"):
            _files(matrix, spec, reply)
        elif phase.startswith("news-"):
            _news(matrix, spec, reply)
        matrix.progress.append(label)
        if label.startswith(("barrier-files-", "barrier-news-")):
            wire.partial["current_case_index"] = None
    need(len(matrix.results) == CASE_COUNT, "Incomplete matrix")
    return {
        "views": matrix.views,
        "results": matrix.results,
        "progress": matrix.progress,
    }
