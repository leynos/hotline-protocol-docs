#!/usr/bin/env python3
"""Prepare two control-only phases for a stopped-image 304 persistence test.

``main`` writes the plans, the digest of each and the identity of the scripts that
will run them (decision D31): ``source-code-identity.json`` holds the path and the
hash of each module of ``native_settings_persistence.CAPTURE_MODULES``, and the
runner checks that the live files are those. A directory of plans made before that
decision holds ``source-code-sha256.json``, the hashes of four files, instead. The
record holds no commit and no digest of the set, which the runner computes from the
files, so that the plans stay the same for the same scripts.

Command line::

    native_settings_persistence_cases.py --runtime F --port N --output D
"""

import hashlib
import json
import sys
import typing as typ
from pathlib import Path

import capture_identity
import native_ban_control_cases as control
from native_auth_cases import authentication
from native_ban_control_cases import A7_SHA
from native_plan import login, packet, payload, read, send
from native_pm_cases import variable_message
from native_wire_names import (
    FIELD_AUTO_RESPONSE,
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_SEND_PRIVATE_MESSAGE,
    TYPE_SET_CLIENT_INFO,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run as run_command

type Step = dict[str, typ.Any]
type Plan = dict[str, typ.Any]
type Expectation = dict[str, typ.Any]


class StageSpec(typ.NamedTuple):
    """One change of the subject's settings and the message that follows it."""

    label: str
    name: bytes
    icon: bytes
    option: bytes | None
    auto: bytes | None
    text: bytes
    active: bool
    identifier: int


BASELINE_NAME = b"A41-Baseline"
MARKER_NAME = b"A41-Persist-On"
MARKER_TEXT = b"a41-explicit-auto"
OFF_NAME = b"A41-Persist-Off"
LOGIN_STEPS = 3  # the handshake steps that precede the login request
ROSTER_ID = 10
BASELINE_ID = 60
SETTINGS_ID_BASE = 30  # the 304 of stage ``n`` takes this plus ``n``
BARRIER_ID_STEP = 100  # a message's barrier takes its ID plus this
QUIET_SECONDS = 2
QUIT_TIMEOUT = 720  # seconds that a held session waits for the app to quit
LOWEST_PORT = 1024
HIGHEST_PORT = 65532
PRIMARY_PORTS = {15500, 15501}
SUBJECT_ICON = b"\0\3"
ENABLED_ICON = b"\0\x11"
DISABLED_ICON = b"\0\x12"
AUTO_OPTION = b"\0\4"
PM_OPTION = b"\0\1"
SAVE_UID = {"peer_uid": FIELD_USER_ID}
FIRST_PHASE = 1
BEFORE_TEXT = b"a41-before"
AFTER_TEXT = b"a41-after-restart"
OPERATOR = "A42 preparation; separate root START required"
GAP_IDS = ["GAP-029"]
IDENTITY_FILE = "source-code-identity.json"
ENABLED = (
    MARKER_NAME,
    ENABLED_ICON,
    AUTO_OPTION,
    MARKER_TEXT,
)  # name to automatic text
DISABLED = (OFF_NAME, DISABLED_ICON, None, None)
STAGES = [
    StageSpec("enable", *ENABLED, b"a41-enabled", active=True, identifier=61),
    StageSpec("disable", *DISABLED, b"a41-disabled", active=False, identifier=62),
    StageSpec("reenable", *ENABLED, b"a41-final", active=True, identifier=63),
]


def barrier(identifier: int) -> list[Step]:
    """Make both sessions answer an empty request and then stay quiet.

    Parameters
    ----------
    identifier : int
        The request ID of the barrier.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send, read and quiet steps of each connection.
    """
    steps: list[Step] = []
    for name in ("main", "subject"):
        steps += [
            send(packet(TYPE_EMPTY_ACK, identifier), name),
            read(name, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": name, "timeout": QUIET_SECONDS},
        ]
    return steps


def message(identifier: int, text: bytes, *, automatic: bool) -> list[Step]:
    """Make the observer message the subject, then bar both sessions.

    Parameters
    ----------
    identifier : int
        The request ID of the message.
    text : bytes
        The message text.
    automatic : bool
        Whether the subject's automatic response comes back to the observer.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the message and of its barrier.
    """
    steps = [
        variable_message(
            TYPE_SEND_PRIVATE_MESSAGE,
            identifier,
            "peer_uid",
            [(FIELD_OPTIONS, PM_OPTION), (FIELD_DATA, text)],
        ),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]
    if automatic:
        steps.append(read(match_frame={"type": TYPE_MESSAGE_NOTIFICATION}))
    steps.append(read("subject", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}))
    return steps + barrier(identifier + BARRIER_ID_STEP)


def _stage_steps(steps: list[Step], spec: StageSpec, number: int) -> Expectation:
    """Append one stage's steps and describe where its actions fall.

    Parameters
    ----------
    steps : list[dict[str, typing.Any]]
        The steps so far, extended in place.
    spec : StageSpec
        The stage.
    number : int
        The stage's position, which numbers its 304.

    Returns
    -------
    dict[str, typing.Any]
        The stage's entry in the expectation.
    """
    mutation = len(steps)
    values = [(FIELD_NAME, spec.name), (FIELD_ICON, spec.icon)]
    if spec.option is not None:
        values.append((FIELD_OPTIONS, spec.option))
    if spec.auto is not None:
        values.append((FIELD_AUTO_RESPONSE, spec.auto))
    steps += [
        send(
            packet(TYPE_SET_CLIENT_INFO, SETTINGS_ID_BASE + number, payload(values)),
            "subject",
        ),
        read(match_frame={"type": TYPE_PRESENCE_UPDATE}),
        read("subject", match_frame={"type": TYPE_PRESENCE_UPDATE}),
    ]
    pm = len(steps)
    steps += message(spec.identifier, spec.text, automatic=spec.active)
    return {
        "label": spec.label,
        "mutation_action": mutation,
        "update_action": mutation + 1,
        "pm_action": pm,
        "pm_id": spec.identifier,
        "pm_text_hex": spec.text.hex(),
        "name_hex": spec.name.hex(),
        "icon_hex": spec.icon.hex(),
        "auto": spec.active,
    }


def _sessions() -> tuple[list[Step], Step]:
    """Log in the observer, read its roster and log in the subject.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps up to the subject's three login frames, and the subject's
        fixed login request.
    """
    steps = [
        *login(),
        send(packet(TYPE_GET_USER_ROSTER, ROSTER_ID)),
        read(match_frame={"is_reply": 1, "id": ROSTER_ID}),
    ]
    steps += [{**step, "connection": "subject"} for step in login()[:LOGIN_STEPS]]
    fixed_login = authentication(
        b"admin",
        b"mothra19",
        name=BASELINE_NAME,
        icon=SUBJECT_ICON,
        connection="subject",
    )
    steps += [fixed_login, read("subject"), read("subject"), read("subject")]
    return steps, fixed_login


def observation(phase: int) -> tuple[list[Step], Expectation]:
    """Make one phase's steps and its expectation.

    Parameters
    ----------
    phase : int
        The phase, 1 before the restart and 2 after it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps, fixed_login = _sessions()
    identity = len(steps)
    steps.append(read(match_frame={"type": TYPE_PRESENCE_UPDATE}, save_fields=SAVE_UID))
    baseline = len(steps)
    text = BEFORE_TEXT if phase == FIRST_PHASE else AFTER_TEXT
    steps += message(BASELINE_ID, text, automatic=False)
    expectation: Expectation = {
        "case": f"settings-persistence-phase{phase}",
        "identity_action": identity,
        "baseline_pm_action": baseline,
        "fixed_login_hex": fixed_login["hex"],
        "baseline_name_hex": BASELINE_NAME.hex(),
        "marker_name_hex": MARKER_NAME.hex(),
        "marker_text_hex": MARKER_TEXT.hex(),
        "sockets_held_for_app_quit": True,
    }
    if phase == FIRST_PHASE:
        expectation["stages"] = [
            _stage_steps(steps, spec, number) for number, spec in enumerate(STAGES)
        ]
    expectation["observation_actions"] = len(steps)
    steps += [
        {"op": "read_eof", "connection": name, "timeout": QUIT_TIMEOUT}
        for name in ("subject", "main")
    ]
    return steps, expectation


def plans(runtime: Plan, port: int) -> dict[str, Plan]:
    """Make the two phase plans and the readiness plan.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record of the emulator.
    port : int
        The control port.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The plans, ``phase1``, ``phase2`` and ``readiness``.

    Raises
    ------
    ValueError
        If the A7 provenance differs or the port is unsafe.
    """
    if runtime.get("source_a7_sha256") != A7_SHA:
        msg = "A7 provenance differs"
        raise ValueError(msg)
    if not LOWEST_PORT <= port <= HIGHEST_PORT or port in PRIMARY_PORTS:
        msg = "Unsafe control endpoint"
        raise ValueError(msg)
    result: dict[str, Plan] = {}
    for phase in (1, 2):
        steps, expectation = observation(phase)
        result[f"phase{phase}"] = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": OPERATOR,
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": GAP_IDS,
            "environment": {
                **runtime,
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            },
            "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
            "steps": steps,
            "expectation": expectation,
        }
    result["readiness"] = {
        **result["phase1"],
        "steps": control.plans()["readiness"],
        "expectation": {"case": "control-readiness"},
    }
    for plan in result.values():
        validate_plan(plan)
    return result


def prepare(runtime: Path, port: int, output: Path) -> None:
    """Write the plans, their digests and the identity of the scripts.

    Parameters
    ----------
    runtime : pathlib.Path
        The runtime record of the emulator, a JSON file.
    port : int
        The control port.
    output : pathlib.Path
        A directory that must not exist yet.
    """
    from native_settings_persistence import (
        CAPTURE_MODULES,
    )  # the runner imports this module

    result = plans(json.loads(runtime.read_text()), port)
    output.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, plan in result.items():
        raw = (json.dumps(plan, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    (output / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
    record = {
        "schema_version": capture_identity.SCHEMA_VERSION,
        "files": capture_identity.identity(CAPTURE_MODULES)["files"],
    }
    (output / IDENTITY_FILE).write_text(json.dumps(record, indent=2) + "\n")


def command(*, runtime: str, port: int, output: str) -> None:
    """Prepare the two phases of a persistence test.

    Parameters
    ----------
    runtime
        The runtime record of the emulator.
    port
        The control port.
    output
        A directory that must not exist yet.
    """
    prepare(Path(runtime), port, Path(output))


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run_command(command, __doc__, sys.argv[1:])
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
