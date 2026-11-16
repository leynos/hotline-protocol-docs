"""Check a capture plan for ``protocol_capture`` before any socket is opened.

Part of the capture driver's module set (``protocol_capture.CAPTURE_MODULES``).
``protocol_capture`` re-exports :func:`field_saves` and ``VARIABLE``, and its own
``validate_plan`` calls :func:`validate` with the oracle hash and the capture
limit it holds, so that a test which patches either on ``protocol_capture`` is
still obeyed. The rules run in a fixed order; the first plan fault found is the
one reported.
"""

import dataclasses as dc
import re
import typing as typ
from itertools import starmap

VARIABLE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
NAME = re.compile(r"[a-z][a-z0-9_]*")
PROFILES = {"synthetic-tool-test", "native-mac-oracle"}
STREAM_OPS = {
    "send",
    "read",
    "read_frame",
    "read_eof",
    "close",
    "shutdown_write",
    "expect_quiet",
}
RECEIVE_OPS = {"read", "read_frame", "read_eof"}
MAX_SECONDS = 3600
MAX_PORT = 65535
MAX_FIELD_ID = 65535
# The largest value of each frame header field that a plan may match on.
MATCH_BOUNDS = {"is_reply": 255, "type": 65535, "id": 0xFFFFFFFF}

type Plan = dict[str, typ.Any]
type Step = dict[str, typ.Any]


@dc.dataclass(slots=True)
class PlanState:
    """What the steps seen so far have established.

    Attributes
    ----------
    connections : set[str]
        Connections that are open.
    declared : set[str]
        Every connection ever declared; a name cannot be declared twice.
    writes_closed : set[str]
        Connections whose write side has been shut down.
    variables : set[str]
        Names of saved bytes or fields that later steps may use.
    """

    connections: set[str] = dc.field(default_factory=set)
    declared: set[str] = dc.field(default_factory=set)
    writes_closed: set[str] = dc.field(default_factory=set)
    variables: set[str] = dc.field(default_factory=set)


def field_saves(step: Step) -> dict[str, int]:
    """Normalize field selectors without changing the received value bytes.

    Parameters
    ----------
    step : dict[str, typ.Any]
        A plan step.

    Returns
    -------
    dict[str, int]
        The ``save_fields`` of the step, with ``save_field`` merged in.

    Raises
    ------
    ValueError
        If ``save_field`` repeats a name in ``save_fields``.
    """
    result = dict(step.get("save_fields", {}))
    if "save_field" in step:
        saved = step["save_field"]
        if saved["name"] in result:
            message = "Repeated saved-field variable"
            raise ValueError(message)
        result[saved["name"]] = saved["id"]
    return result


def _check_header(plan: Plan, oracle: str) -> None:
    """Check the plan's schema, profile, operator and oracle.

    Raises
    ------
    ValueError
        For the first of those that is wrong.
    """
    if plan.get("schema_version") != 1:
        message = "Unsupported capture schema"
        raise ValueError(message)
    if plan.get("profile") not in PROFILES:
        message = "Unknown evidence profile"
        raise ValueError(message)
    if not plan.get("operator") or not plan.get("gap_ids"):
        message = "Operator and gap IDs are required"
        raise ValueError(message)
    if plan["profile"] == "native-mac-oracle" and plan["oracle_sha256"] != oracle:
        message = "Native profile requires the recorded Mac oracle hash"
        raise ValueError(message)


def _check_endpoints(plan: Plan) -> None:
    """Check each endpoint's host and port.

    Raises
    ------
    ValueError
        If an endpoint is invalid.
    """
    for endpoint in plan["endpoints"].values():
        if (
            not isinstance(endpoint["host"], str)
            or not 1 <= endpoint["port"] <= MAX_PORT
        ):
            message = "Invalid endpoint"
            raise ValueError(message)


def _check_connect(step: Step, name: str, plan: Plan, state: PlanState) -> None:
    """Check and record a connection declaration.

    Raises
    ------
    ValueError
        If the name is reused or empty, or the endpoint is not in the plan.
    """
    unusable = name in state.declared or not name
    if unusable or step["endpoint"] not in plan["endpoints"]:
        message = "Invalid connection declaration"
        raise ValueError(message)
    state.connections.add(name)
    state.declared.add(name)


def _check_stream_op(op: str, name: str, state: PlanState) -> None:
    """Check an action on an open connection and record its effect.

    Raises
    ------
    ValueError
        If the connection is unknown, or the write side is already closed.
    """
    if name not in state.connections:
        message = f"Unknown connection: {name}"
        raise ValueError(message)
    if op == "close":
        state.connections.remove(name)
    if op in {"send", "shutdown_write"} and name in state.writes_closed:
        message = "Connection write side is already closed"
        raise ValueError(message)
    if op == "shutdown_write":
        state.writes_closed.add(name)


def _check_operation(step: Step, plan: Plan, state: PlanState) -> None:
    """Check the step's operation and what it does to the connections.

    Raises
    ------
    ValueError
        If the operation is unknown or its own rule is broken.
    """
    op = step["op"]
    name = step.get("connection", "")
    if op == "connect":
        _check_connect(step, name, plan, state)
    elif op == "pause":
        if not 0 <= step["seconds"] <= MAX_SECONDS:
            message = "Invalid pause"
            raise ValueError(message)
    elif op in STREAM_OPS:
        _check_stream_op(op, name, state)
    else:
        message = f"Unknown action: {op}"
        raise ValueError(message)


def _bad_match_item(key: str, value: object) -> bool:
    """Say whether one frame-match entry is unknown or out of range.

    Returns
    -------
    bool
        ``True`` for a key that is not a frame header field, a value that is not
        an integer, or one outside the field's range.
    """
    if key not in MATCH_BOUNDS:
        return True
    return not isinstance(value, int) or not 0 <= value <= MATCH_BOUNDS[key]


def _check_match(op: str, match: dict[str, typ.Any]) -> None:
    """Check a frame match.

    Raises
    ------
    ValueError
        If the operation is not a frame read, or the match is empty or out of
        range.
    """
    unusable = op != "read_frame" or not match
    if unusable or any(starmap(_bad_match_item, match.items())):
        message = "Invalid frame match"
        raise ValueError(message)


def _check_limits(step: Step) -> None:
    """Check the timeout, the size reference and the frame match of a step.

    Raises
    ------
    ValueError
        For the first of those that is wrong.
    """
    op = step["op"]
    if not 0 < step.get("timeout", 2) <= MAX_SECONDS:
        message = "Invalid action timeout"
        raise ValueError(message)
    if "size_from" in step and op != "read":
        message = "Only fixed-length reads can use size_from"
        raise ValueError(message)
    if "match_frame" in step:
        _check_match(op, step["match_frame"])


def _check_read(step: Step, state: PlanState, limit: int) -> None:
    """Check how a read says how much to read.

    Raises
    ------
    ValueError
        If the size is unknown, ambiguous or over the limit.
    """
    if "size_from" in step:
        if "size" in step or step["size_from"] not in state.variables:
            message = "Unknown or ambiguous read size"
            raise ValueError(message)
    elif not 0 < step["size"] <= limit:
        message = "Read size exceeds capture limit"
        raise ValueError(message)


def _check_send(step: Step, state: PlanState, limit: int) -> None:
    """Check the bytes a send names and their size.

    Raises
    ------
    ValueError
        If a saved name is unknown or the bytes exceed the limit.
    """
    for variable in VARIABLE.findall(step["hex"]):
        if variable not in state.variables:
            message = f"Unknown saved bytes: {variable}"
            raise ValueError(message)
    literal = VARIABLE.sub("00", step["hex"])
    if len(bytes.fromhex(literal)) > limit:
        message = "Send size exceeds capture limit"
        raise ValueError(message)


def _check_payload(step: Step, state: PlanState, limit: int) -> None:
    """Check the read size, the send bytes and the expected bytes of a step."""
    op = step["op"]
    if op == "read":
        _check_read(step, state, limit)
    if op == "send":
        _check_send(step, state, limit)
    if "expect_hex" in step:
        bytes.fromhex(step["expect_hex"])


def _check_save(
    op: str, saved: dict[str, typ.Any], state: PlanState, limit: int
) -> None:
    """Check a saved slice of received bytes and record its name.

    Raises
    ------
    ValueError
        If the operation receives nothing, or the name or bounds are invalid.
    """
    if op not in RECEIVE_OPS:
        message = "Only received bytes can be saved"
        raise ValueError(message)
    if not NAME.fullmatch(saved["name"]):
        message = "Invalid saved-byte name"
        raise ValueError(message)
    if saved["offset"] < 0 or not 0 < saved["size"] <= limit:
        message = "Invalid saved-byte bounds"
        raise ValueError(message)
    state.variables.add(saved["name"])


def _check_field(op: str, variable: str, field_id: int, state: PlanState) -> None:
    """Check a field saved by identifier and record its name.

    Raises
    ------
    ValueError
        If the operation is not a frame read, the identifier does not fit two
        bytes, or the name is invalid.
    """
    if op != "read_frame" or not 0 <= field_id <= MAX_FIELD_ID:
        message = "Only a frame field can be saved by ID"
        raise ValueError(message)
    if not NAME.fullmatch(variable):
        message = "Invalid saved-field name"
        raise ValueError(message)
    state.variables.add(variable)


def _check_saves(step: Step, state: PlanState, limit: int) -> None:
    """Check the byte save and the field saves of a step, in that order."""
    op = step["op"]
    if "save" in step:
        _check_save(op, step["save"], state, limit)
    for variable, field_id in field_saves(step).items():
        _check_field(op, variable, field_id, state)


def validate(plan: Plan, *, oracle: str, limit: int) -> None:
    """Reject invalid actions and unresolved connections before opening sockets.

    Parameters
    ----------
    plan : dict[str, typ.Any]
        The plan.
    oracle : str
        The recorded Mac oracle hash that a native plan must carry.
    limit : int
        The most bytes a session, a read, a send or a save may cover.
    """
    _check_header(plan, oracle)
    _check_endpoints(plan)
    state = PlanState()
    for step in plan["steps"]:
        _check_operation(step, plan, state)
        _check_limits(step)
        _check_payload(step, state, limit)
        _check_saves(step, state, limit)
