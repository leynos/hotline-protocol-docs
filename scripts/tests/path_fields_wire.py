"""Synthetic wire model and recorder for the path-field control tests.

The fakes choose every reply, so the tests check fixture control flow and
receipt conservation. Their responses are not native path observations.
"""

import datetime as dt
import time
import typing as typ

import native_path_fields_cases as cases
from native_plan import packet, payload
from native_wire_names import (
    TYPE_CREATE_FOLDER,
    TYPE_DELETE_FILE,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MOVE_FILE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from path_fields_support import (
    FIELD_NEWS_RECORD,
    TYPE_NEWS_CATEGORY_CREATE,
    TYPE_NEWS_DELETE,
    TYPE_NEWS_FOLDER_CREATE,
    TYPE_NEWS_LIST,
    file_record,
    news_record,
)
from protocol_capture import decode_frame
from verify_classic_native_baseline import AGREEMENT
from verify_native_auth import ADMIN

if typ.TYPE_CHECKING:
    import collections.abc as cabc


def model_frame(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the callers name the reply and error flags
    name: str,
    kind: int,
    identifier: int,
    values: list,
    *,
    reply: int = 0,
    error: int = 0,
) -> dict:
    """Build the decoded frame of one synthetic reply or notification.

    Returns
    -------
    dict
        The raw bytes, arrival time and decoded fields of the frame.
    """
    raw = bytes.fromhex(
        packet(kind, identifier, payload(values), reply=reply, error=error)
    )
    return {
        "connection": name,
        "raw_hex": raw.hex(),
        "arrival_elapsed_ns": time.monotonic_ns(),
        **decode_frame(raw),
    }


class FakeRecorder:
    """Record the synthetic actions and the bytes that cross each connection."""

    def __init__(self) -> None:
        """Start the clock and empty the event and socket records."""
        self.started = time.monotonic_ns()
        self.started_at_utc = dt.datetime.now(dt.UTC).isoformat()
        self.events: list = []
        self.sockets: dict = {}

    def event(self, action: int, name: str, event: str, raw: bytes = b"") -> None:
        """Append one timed event of an action, a connection and its bytes."""
        self.events.append({
            "action": action,
            "connection": name,
            "event": event,
            "elapsed_ns": time.monotonic_ns() - self.started,
            "hex": raw.hex(),
        })

    def streams(self) -> dict:
        """Concatenate the sent and received bytes of each connection.

        Returns
        -------
        dict
            The sent and received hexadecimal text per connection.
        """
        result: dict = {}
        for event in self.events:
            stream = result.setdefault(
                event["connection"], {"sent_hex": "", "received_hex": ""}
            )
            if event["event"] == "send":
                stream["sent_hex"] += event["hex"]
            if event["event"] == "receive":
                stream["received_hex"] += event["hex"]
        return result


class FakeWire:
    """Answer the planned requests of a synthetic native server."""

    def __init__(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the tests select each fault by keyword
        self,
        plan: dict,
        *,
        missing_readback: bool = False,
        move_error: str | None = None,
        foreign_after_move: bool = False,
        type_flip_after_move: bool = False,
    ) -> None:
        """Start an empty server that answers from the given plan."""
        self.plan = plan
        self.recorder = FakeRecorder()
        self.frames: list = []
        self.actions: list = []
        self.terminals: dict = {}
        self.buffers: dict = {}
        self.request_count = 0
        self.partial: dict = {}
        self.missing_readback = missing_readback
        self.move_error = move_error
        self.foreign_after_move = foreign_after_move
        self.type_flip_after_move = type_flip_after_move
        self.folders: dict = {
            "S": set(),
            "H": set(),
            "wrapper": {b"S", b"H-\x9a"},
        }
        self.wrapper = False
        self.news_folder = False
        self.news_category = False
        self.next_action = 0

    def execute(self, step: dict) -> None:
        """Apply one scripted connect, send or read step to the recorder."""
        name = step["connection"]
        match step["op"]:
            case "connect":
                self.recorder.sockets[name] = object()
                self.recorder.event(self.next_action, name, "connect")
            case "send":
                self.recorder.event(
                    self.next_action, name, "send", bytes.fromhex(step["hex"])
                )
            case "read":
                self.recorder.event(
                    self.next_action,
                    name,
                    "receive",
                    bytes.fromhex(cases.HELLO_REPLY),
                )
        self.next_action += 1

    def send(self, name: str, raw: str, label: str) -> None:
        """Record one request and queue the synthetic replies to it.

        Raises
        ------
        AssertionError
            If the label is neither planned nor a stop probe.
        """
        start = len(self.recorder.events)
        self.recorder.event(self.next_action, name, "send", bytes.fromhex(raw))
        self.next_action += 1
        action = {
            "label": label,
            "connection": name,
            "hex": raw,
            "elapsed_ns": time.monotonic_ns() - self.recorder.started,
            "event_range": [start, len(self.recorder.events)],
        }
        self.actions.append(action)
        if label.endswith("-login"):
            for frame in (
                model_frame(name, 0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1),
                model_frame(name, TYPE_PRIVILEGES_NOTIFICATION, 0, [(110, ADMIN)]),
                model_frame(name, TYPE_LOGIN_AGREEMENT, 0, [(101, AGREEMENT)]),
            ):
                self.add(frame)
            return
        spec = next((s for s in self.plan["requests"] if s["label"] == label), None)
        if spec is None:
            if label.startswith("stop-files-root-"):
                spec = cases.request(
                    label,
                    200,
                    9000 + int(label.rsplit("-", 1)[1]),
                    [(202, cases.FILES_ROOT)],
                    "stop-probe",
                )
            else:
                raise AssertionError(label)
        reply = self.reply(spec, action)
        self.add(reply)

    def add(self, frame: dict) -> None:
        """Record one received frame and stamp its arrival time."""
        self.recorder.event(
            -1, frame["connection"], "receive", bytes.fromhex(frame["raw_hex"])
        )
        frame["arrival_elapsed_ns"] = time.monotonic_ns() - self.recorder.started
        self.frames.append(frame)

    def reply(self, spec: dict, action: dict) -> dict:
        """Answer one planned request.

        Returns
        -------
        dict
            The decoded reply frame.
        """
        name = action["connection"]
        label = spec["label"]
        kind = spec["kind"]
        if kind == TYPE_MOVE_FILE:
            return self.move(name, spec, label)
        values = self.read(kind, label, spec)
        self.change(kind, label, spec)
        return model_frame(name, 0, spec["id"], values, reply=1)

    def read(self, kind: int, label: str, spec: dict) -> list:
        """Build the field values of a reply that only reads state.

        Returns
        -------
        list
            The (field, bytes) pairs; empty for a request that changes state.
        """
        if kind == TYPE_ENUMERATE_ACCOUNTS:
            return [(101, b"account-one"), (101, b"account-two")]
        if kind == TYPE_GET_USER_ROSTER:
            return [(300, b"\0\7\0\1\0\0\0\x0f" + b"framing-fixture")]
        if kind == TYPE_LIST_FILES:
            return self.listing(label)
        if kind == TYPE_GET_FILE_INFO:
            marker = (
                bytes.fromhex(spec["marker_hex"])
                if spec["marker_hex"]
                else bytes.fromhex(spec["fields"][0][1])
            )
            return [(201, marker), (213, b"fldr")]
        if kind == TYPE_NEWS_LIST:
            return self.news(label)
        return []

    def listing(self, label: str) -> list:
        """Build the file entries of a listing reply.

        Returns
        -------
        list
            The (200, record) pairs, altered for the injected faults.
        """
        values = [(200, file_record(v)) for v in self.folder_names(label)]
        if self.type_flip_after_move and label == "after-view-0-H":
            values = [(field, b"TEXT" + raw[4:]) for field, raw in values]
        if self.missing_readback and label == "after-view-0-H":
            values = []
        return values

    def folder_names(self, label: str) -> list:
        """Choose the names that a listing of the labelled view contains.

        Returns
        -------
        list
            The names in the order the listing reports them.
        """
        if "files-root" in label:
            return [b"original"] + ([cases.FILES] if self.wrapper else [])
        if "wrapper" in label:
            return list(self.folders["wrapper"])
        if label.endswith("-S"):
            return sorted(self.folders["S"])
        if label.endswith("-H"):
            return sorted(self.folders["H"])
        return []

    def news(self, label: str) -> list:
        """Build the news entries of a news listing reply.

        Returns
        -------
        list
            The (news record field, record) pairs, or an empty list.
        """
        if "high" in label or label.startswith("news-"):
            return (
                [(FIELD_NEWS_RECORD, news_record(cases.CATEGORY, folder=False))]
                if self.news_category
                else []
            )
        return (
            [(FIELD_NEWS_RECORD, news_record(cases.NEWS, folder=True))]
            if self.news_folder
            else []
        )

    def change(self, kind: int, label: str, spec: dict) -> None:
        """Apply the state change that a request of the given kind makes."""
        match kind:
            case _ if kind == TYPE_CREATE_FOLDER:
                self.create(spec)
            case _ if kind == TYPE_NEWS_FOLDER_CREATE:
                self.news_folder = True
            case _ if kind == TYPE_NEWS_CATEGORY_CREATE:
                self.news_category = True
            case _ if kind == TYPE_NEWS_DELETE:
                if label.endswith("category"):
                    self.news_category = False
                else:
                    self.news_folder = False
            case _ if kind == TYPE_DELETE_FILE:
                self.wrapper = False

    def create(self, spec: dict) -> None:
        """Record a created folder under the wrapper or the source parent."""
        leaf = bytes.fromhex(spec["fields"][0][1])
        parent = bytes.fromhex(spec["fields"][1][1])
        if leaf == cases.FILES:
            self.wrapper = True
        elif parent == cases.SOURCE:
            self.folders["S"].add(leaf)

    def move(self, name: str, spec: dict, label: str) -> dict:
        """Answer a move, moving the marker from the source to the target.

        Returns
        -------
        dict
            The decoded reply frame, with an error for the injected failure.
        """
        marker = bytes.fromhex(spec["marker_hex"])
        if self.move_error == label:
            return model_frame(name, 0, spec["id"], [], reply=1, error=999)
        self.folders["S"].remove(marker)
        self.folders["H"].add(marker)
        if self.foreign_after_move and label == "move-0":
            self.folders["H"].add(b"foreign")
        return model_frame(name, 0, spec["id"], [], reply=1)

    def match(
        self,
        name: str,
        kind: int,
        identifier: int | None,
        reply: int,
    ) -> list:
        """Select the received frames that match the given keys.

        Returns
        -------
        list
            The matching frames in arrival order.
        """
        return [
            f
            for f in self.frames
            if f["connection"] == name
            and f["type"] == kind
            and f["is_reply"] == reply
            and (identifier is None or f["id"] == identifier)
        ]

    def wait_for(  # ruff: ignore[no-self-use]  # the control code calls the fake with the real wait signature
        self,
        predicate: cabc.Callable[[], bool],
        seconds: float,
        label: str,
    ) -> None:
        """Raise unless the predicate already holds.

        Raises
        ------
        ValueError
            If the predicate does not hold.
        """
        if not predicate():
            raise ValueError("Synthetic missing " + label)

    def shutdown_and_close(self, name: str) -> None:
        """Close one connection and record the bounded no-EOF terminal."""
        self.recorder.sockets.pop(name)
        self.recorder.event(-1, name, "close")
        self.terminals[name] = "bounded_no_eof"

    def close_all(self) -> None:
        """Close every open connection."""
        for name in list(self.recorder.sockets):
            self.shutdown_and_close(name)
