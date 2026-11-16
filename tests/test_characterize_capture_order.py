"""Pin the order in which ``validate_plan`` of ``protocol_capture`` refuses a plan.

The earlier characterization tests break one rule at a time and a few pairs.
Here every pair of faults that one step can carry together, and every pair of
plan-level faults, is checked: the plan is refused for the fault that the
function reaches first. Every expectation was observed on the module at its
pinned commit (``scripts/pinned-sources.json``), so that splitting the function
into one check per rule cannot reorder them.
"""

import itertools
import typing as typ

import protocol_capture as pc
import pytest

CHARACTERIZES = "protocol_capture.py"
LIMIT = 8 * 1024 * 1024

type Plan = dict[str, typ.Any]
type Fault = tuple[str, dict[str, typ.Any], str]


def refusal(plan: Plan) -> str:
    """Run ``validate_plan`` and describe its error.

    Returns
    -------
    str
        The type name and message of the error, or ``"accepted"``.
    """
    try:
        pc.validate_plan(plan)
    except Exception as error:  # ruff: ignore[blind-except]  # the type is the observation
        return f"{type(error).__name__}: {error}"
    return "accepted"


def plan_with(step: dict[str, typ.Any], **changes: object) -> Plan:
    """Build a valid plan that connects ``main`` and then runs one step.

    Returns
    -------
    dict[str, typing.Any]
        The plan, with ``changes`` applied at the top level.
    """
    plan: Plan = {
        "schema_version": 1,
        "profile": "synthetic-tool-test",
        "operator": "operator",
        "gap_ids": ["GAP-001"],
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": [
            {"op": "connect", "connection": "main", "endpoint": "control"},
            step,
        ],
    }
    plan.update(changes)
    return plan


def field_faults(*, op: str) -> list[Fault]:
    """List faults a step of one operation can carry, in the order checked.

    Returns
    -------
    list[tuple[str, dict, str]]
        A name, the fields that cause it and the error it ends with.
    """
    shared: list[Fault] = [
        (
            "connection",
            {"connection": "ghost"},
            "ValueError: Unknown connection: ghost",
        ),
        ("timeout", {"timeout": 0}, "ValueError: Invalid action timeout"),
    ]
    saves: list[Fault] = [
        (
            "expect",
            {"expect_hex": "zz"},
            "ValueError: non-hexadecimal number found in fromhex() arg at position 0",
        ),
        (
            "save-name",
            {"save": {"name": "Bad", "offset": 0, "size": 1}},
            "ValueError: Invalid saved-byte name",
        ),
    ]
    if op == "read_frame":
        return [
            *shared,
            (
                "size-from",
                {"size_from": "n"},
                "ValueError: Only fixed-length reads can use size_from",
            ),
            ("match", {"match_frame": {"bogus": 1}}, "ValueError: Invalid frame match"),
            *saves,
            (
                "field-id",
                {"save_fields": {"x": 70000}},
                "ValueError: Only a frame field can be saved by ID",
            ),
        ]
    if op == "read":
        return [
            *shared,
            (
                "size-from-unknown",
                {"size_from": "n"},
                "ValueError: Unknown or ambiguous read size",
            ),
            *saves,
        ]
    return [
        *shared,
        ("unknown-bytes", {"hex": "{nope}"}, "ValueError: Unknown saved bytes: nope"),
        saves[0],
    ]


def base_step(op: str) -> dict[str, typ.Any]:
    """Build a valid step of one operation on ``main``.

    Returns
    -------
    dict[str, typing.Any]
        The step.
    """
    fields: dict[str, dict[str, typ.Any]] = {
        "read_frame": {},
        "read": {"size": 4},
        "send": {"hex": "00"},
    }
    return {"op": op, "connection": "main", **fields[op]}


def pairs() -> list[tuple[str, str, str, dict, dict, str]]:
    """List every compatible pair of faults of each operation.

    Returns
    -------
    list[tuple]
        The operation, the two names, the fields of each and the error of the
        earlier one. Pairs whose fields share a key are left out.
    """
    found = []
    for op in ("read_frame", "read", "send"):
        for (n1, f1, e1), (n2, f2, _) in itertools.combinations(field_faults(op=op), 2):
            if not set(f1) & set(f2):
                found.append((op, n1, n2, f1, f2, e1))
    return found


@pytest.mark.parametrize(
    "case", pairs(), ids=lambda case: f"{case[0]}-{case[1]}-{case[2]}"
)
def test_a_step_with_two_faults_is_refused_for_the_one_checked_first(
    case: tuple[str, str, str, dict[str, typ.Any], dict[str, typ.Any], str],
) -> None:
    """The earlier rule wins: the first named fault before the second in ``op``."""
    op, first, second, fields_first, fields_second, ending = case
    step = base_step(op) | fields_second | fields_first
    plan = plan_with(step)
    assert refusal(plan) == ending, (first, second)


@pytest.mark.parametrize(
    ("op", "step", "ending"),
    [
        (
            "connect",
            {
                "op": "connect",
                "connection": "main",
                "endpoint": "control",
                "timeout": 0,
            },
            "ValueError: Invalid connection declaration",
        ),
        (
            "pause",
            {"op": "pause", "seconds": -1, "timeout": 0},
            "ValueError: Invalid pause",
        ),
        ("unknown", {"op": "zzz", "timeout": 0}, "ValueError: Unknown action: zzz"),
        (
            "ghost-close",
            {"op": "close", "connection": "ghost", "timeout": 0},
            "ValueError: Unknown connection: ghost",
        ),
    ],
)
def test_the_operation_check_comes_before_the_timeout_check(
    op: str, step: dict[str, typ.Any], ending: str
) -> None:
    """A fault in the operation itself hides an invalid timeout."""
    assert refusal(plan_with(step)) == ending, op


def test_a_send_after_a_write_shutdown_comes_before_the_timeout_check() -> None:
    """The half-close rule is part of the operation check."""
    plan = plan_with({"op": "shutdown_write", "connection": "main"})
    plan["steps"].append({
        "op": "send",
        "connection": "main",
        "hex": "00",
        "timeout": 0,
    })
    assert refusal(plan) == "ValueError: Connection write side is already closed", (
        "expected refusal(plan) == 'ValueError: Connection write sid"
    )


def test_a_repeated_field_variable_comes_before_the_field_rules() -> None:
    """The merge of the two selector forms is the first thing the loop does."""
    step = base_step("read_frame") | {
        "save_fields": {"Bad": 70000},
        "save_field": {"name": "Bad", "id": 1},
    }
    assert refusal(plan_with(step)) == "ValueError: Repeated saved-field variable", (
        "expected refusal(plan_with(step)) == 'ValueError: Repeated "
    )


def test_a_field_identifier_is_checked_before_the_field_name() -> None:
    """The range of the identifier comes first within one saved field."""
    step = base_step("read_frame") | {"save_fields": {"Bad": 70000}}
    assert refusal(plan_with(step)) == (
        "ValueError: Only a frame field can be saved by ID"
    ), "expected refusal(plan_with(step)) == 'ValueError: Only a fr"


def test_a_saved_byte_name_is_checked_before_its_bounds() -> None:
    """The name of a saved value comes before its offset and size."""
    step = base_step("read") | {"save": {"name": "Bad", "offset": -1, "size": 1}}
    assert refusal(plan_with(step)) == "ValueError: Invalid saved-byte name", (
        "expected refusal(plan_with(step)) == 'ValueError: Invalid s"
    )


def test_a_save_on_a_send_comes_before_a_bad_name() -> None:
    """Only a received value can be saved, whatever its name."""
    step = base_step("send") | {"save": {"name": "Bad", "offset": 0, "size": 1}}
    assert refusal(plan_with(step)) == "ValueError: Only received bytes can be saved", (
        "expected refusal(plan_with(step)) == 'ValueError: Only rece"
    )


def test_a_field_save_on_a_read_comes_before_a_bad_id_or_name() -> None:
    """Only a frame read can save a field."""
    step = base_step("read") | {"save_fields": {"Bad": 70000}}
    assert refusal(plan_with(step)) == (
        "ValueError: Only a frame field can be saved by ID"
    ), "expected refusal(plan_with(step)) == 'ValueError: Only a fr"


def test_a_match_on_a_read_comes_before_its_own_content() -> None:
    """A match on another operation is refused before its keys are read."""
    step = base_step("read") | {"match_frame": {"bogus": "x"}}
    assert refusal(plan_with(step)) == "ValueError: Invalid frame match", (
        "expected refusal(plan_with(step)) == 'ValueError: Invalid f"
    )


PLAN_FAULTS: list[tuple[str, dict[str, typ.Any], str]] = [
    ("schema", {"schema_version": 2}, "ValueError: Unsupported capture schema"),
    ("profile", {"profile": "other"}, "ValueError: Unknown evidence profile"),
    (
        "operator",
        {"operator": ""},
        "ValueError: Operator and gap IDs are required",
    ),
    (
        "oracle",
        {"profile": "native-mac-oracle", "oracle_sha256": "0" * 64},
        "ValueError: Native profile requires the recorded Mac oracle hash",
    ),
    (
        "endpoint",
        {"endpoints": {"control": {"host": 1, "port": 15500}}},
        "ValueError: Invalid endpoint",
    ),
    (
        "step",
        {"steps": [{"op": "zzz"}]},
        "ValueError: Unknown action: zzz",
    ),
]


@pytest.mark.parametrize(
    "case",
    [
        (n1, n2, f1, f2, e1)
        for (n1, f1, e1), (n2, f2, _) in itertools.combinations(PLAN_FAULTS, 2)
        if not (n1 == "profile" and n2 == "oracle")
    ],
    ids=lambda case: f"{case[0]}-{case[1]}",
)
def test_a_plan_with_two_faults_is_refused_for_the_one_checked_first(
    case: tuple[str, str, dict[str, typ.Any], dict[str, typ.Any], str],
) -> None:
    """The plan-level rules run in the order of the list above."""
    first, second, fields_first, fields_second, ending = case
    plan = plan_with(base_step("send"), **fields_second)
    plan.update(fields_first)
    assert refusal(plan) == ending, (first, second)


def test_a_native_plan_without_operator_is_refused_before_its_oracle_is_read() -> None:
    """The operator rule precedes the lookup of ``oracle_sha256``."""
    plan = plan_with(base_step("send"), profile="native-mac-oracle", operator="")
    assert refusal(plan) == "ValueError: Operator and gap IDs are required", (
        "expected refusal(plan) == 'ValueError: Operator and gap IDs"
    )
