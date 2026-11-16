"""Finite control-only plans for kick, protection and temporary-ban expiry."""

import hashlib
import json
import sys
from pathlib import Path

import native_ban_control_cases as control
from native_auth_cases import authentication, complement
from native_ban_control_cases import A7_SHA
from native_plan import close, eof, login, packet, payload, read, send
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    TYPE_CREATE_ACCOUNT,
    TYPE_EMPTY_ACK,
    TYPE_GET_ACCOUNT,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

CONTROL_PORT = 15800  # the owned B66 control endpoint
TYPE_KICK_USER = (
    110  # the kick or temporary-ban request; not named in native_wire_names
)
ZERO_KEY = b"m-expiry-zero"
PROTECTED_KEY = b"m-expiry-protected"
ZERO_PASSWORD = b"expiry-zero-pass"
PROTECTED_PASSWORD = b"expiry-protected-pass"
ZERO_NAME = b"Expiry Zero"
PROTECTED_NAME = b"Expiry Protected"
ZERO_ACCESS = bytes(8)
PROTECTED_ACCESS = bytes.fromhex("0000010000000000")  # privilege bit 23
TEMPORARY_NOTICE = b"You are temporarily banned on this server."
FIRST = (
    "guard-zero",
    "guard-protected",
    "seed-zero",
    "seed-protected",
    "kick0",
    "kick0-probe",
    "protected",
    "tempban",
    "immediate-probe",
)


def exchange(
    kind: int,
    identifier: int,
    fields: list[tuple[int, bytes]],
    connection: str = "main",
) -> list[dict]:
    """Send one request and read the reply that carries its identifier.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send action followed by the read of its reply.
    """
    return [
        send(packet(kind, identifier, payload(fields)), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def target_login(key: bytes, password: bytes, name: bytes) -> list[dict]:
    """Plan the target's login, agreement and privilege notices.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the target connection.
    """
    return [
        *[{**step, "connection": "target"} for step in login()[:3]],
        authentication(key, password, name=name, connection="target"),
        read("target", match_frame={"is_reply": 1, "id": 1}),
        read("target", match_frame={"type": TYPE_PRIVILEGES_NOTIFICATION}),
        read("target", match_frame={"type": TYPE_LOGIN_AGREEMENT}),
    ]


def account_guard(key: bytes) -> list[dict]:
    """Plan the read that proves the owned account key is absent.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the guard case.
    """
    return login() + exchange(TYPE_GET_ACCOUNT, 30, [(FIELD_LOGIN, key)]) + [close()]


def account_seed(key: bytes, password: bytes, name: bytes, access: bytes) -> list[dict]:
    """Plan the creation and readback of one owned expiry account.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the seed case.
    """
    return (
        login()
        + exchange(
            TYPE_CREATE_ACCOUNT,
            31,
            [
                (FIELD_LOGIN, complement(key)),
                (FIELD_PASSWORD, complement(password)),
                (FIELD_NAME, name),
                (FIELD_ACCESS_BITMAP, access),
            ],
        )
        + exchange(TYPE_GET_ACCOUNT, 32, [(FIELD_LOGIN, key)])
        + [close()]
    )


def kick_case(key: bytes, password: bytes, name: bytes, option: int) -> list[dict]:
    """Plan the target's kick (option 0) or temporary ban (option 1).

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the case.

    Raises
    ------
    ValueError
        If the option is neither a kick nor a temporary ban.
    """
    if option not in {0, 1}:
        message = "Only kick 0 or temporary ban 1 is prepared"
        raise ValueError(message)
    steps = login() + target_login(key, password, name)
    steps += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_field={"name": "target_uid", "id": FIELD_USER_ID},
        )
    ]
    steps += exchange(TYPE_GET_USER_ROSTER, 32, [])
    raw = packet(
        TYPE_KICK_USER,
        33,
        payload([(FIELD_USER_ID, b"\0\0"), (FIELD_OPTIONS, option.to_bytes(2, "big"))]),
    )
    marker = "006700020000"
    if raw.count(marker) != 1:
        message = "110 UID marker is not unique"
        raise ValueError(message)
    steps.append(send(raw.replace(marker, "00670002{target_uid}")))
    if option == 1:
        steps.append(read("target", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}))
    steps += [
        eof("target"),
        read(match_frame={"is_reply": 1, "id": 33}),
        read(match_frame={"type": TYPE_USER_LEFT}),
        close("target"),
        close(),
    ]
    return steps


def protected_case() -> list[dict]:
    """Plan the kick of the protected target, which the server must refuse.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the protected case.

    Raises
    ------
    ValueError
        If the marker that locates the target identifier is not unique.
    """
    steps = login() + target_login(PROTECTED_KEY, PROTECTED_PASSWORD, PROTECTED_NAME)
    steps += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_field={"name": "target_uid", "id": FIELD_USER_ID},
        )
    ]
    steps += exchange(TYPE_GET_USER_ROSTER, 32, [])
    raw = packet(
        TYPE_KICK_USER,
        33,
        payload([(FIELD_USER_ID, b"\0\0"), (FIELD_OPTIONS, b"\0\0")]),
    )
    marker = "006700020000"
    if raw.count(marker) != 1:
        message = "110 UID marker is not unique"
        raise ValueError(message)
    steps += [
        send(raw.replace(marker, "00670002{target_uid}")),
        read(match_frame={"is_reply": 1, "id": 33}),
    ]
    steps += exchange(TYPE_EMPTY_ACK, 80, [], "target")
    steps.append({"op": "expect_quiet", "connection": "target", "timeout": 1})
    steps += [close("target"), close()]
    return steps


def probe(accepted: bool) -> list[dict]:  # ruff: ignore[boolean-type-hint-positional-argument]  # the public signature keeps its positional flag, which the planners pass by keyword
    """Plan a fresh zero-key login, with the roster read only when accepted.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the probe.
    """
    steps = [
        *login()[:3],
        authentication(ZERO_KEY, ZERO_PASSWORD, name=ZERO_NAME),
        read(match_frame={"is_reply": 1, "id": 1}),
    ]
    if accepted:
        steps += [
            read(match_frame={"type": TYPE_PRIVILEGES_NOTIFICATION}),
            read(match_frame={"type": TYPE_LOGIN_AGREEMENT}),
        ]
        steps += exchange(TYPE_GET_USER_ROSTER, 40, [])
    return [*steps, close()]


def plans() -> dict[str, list[dict]]:
    """Plan every case of the three epochs, keyed by case name.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The steps of each case, in the order the epochs run them.
    """
    return {
        "readiness": control.plans()["readiness"],
        "guard-zero": account_guard(ZERO_KEY),
        "guard-protected": account_guard(PROTECTED_KEY),
        "seed-zero": account_seed(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, ZERO_ACCESS),
        "seed-protected": account_seed(
            PROTECTED_KEY, PROTECTED_PASSWORD, PROTECTED_NAME, PROTECTED_ACCESS
        ),
        "kick0": kick_case(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, 0),
        "kick0-probe": probe(accepted=True),
        "protected": protected_case(),
        "tempban": kick_case(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, 1),
        "immediate-probe": probe(accepted=False),
        "pre-probe": probe(accepted=False),
        "post-probe": probe(accepted=True),
    }


def plan(name: str, steps: list[dict], environment: dict, port: int) -> dict:
    """Wrap one case's steps in a validated plan for the control endpoint.

    Returns
    -------
    dict[str, typing.Any]
        The validated plan of the case.

    Raises
    ------
    ValueError
        If the port, the source identity or the fixture profile differs.
    """
    if port != CONTROL_PORT:
        message = "B66 frontend must be owned port 15800"
        raise ValueError(message)
    if environment.get("source_a7_sha256") != A7_SHA:
        message = "Frozen A7 source-plan identity differs"
        raise ValueError(message)
    if (
        environment.get("fixture_profile") != "control-only"
        or environment.get("full_file_baseline") != "not_exercised"
    ):
        message = "Only control-only profile is prepared"
        raise ValueError(message)
    result = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "B66 isolated temporary-ban expiry operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-074"],
        "environment": environment,
        "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
        "steps": steps,
        "expectation": {
            "case": name,
            "epoch": "first"
            if name in FIRST or name == "readiness"
            else "pre"
            if name == "pre-probe"
            else "post",
            "keys_hex": {"zero": ZERO_KEY.hex(), "protected": PROTECTED_KEY.hex()},
            "address": "10.0.2.2",
            "notice_hex": TEMPORARY_NOTICE.hex(),
            "full_file_baseline": "not_exercised",
        },
    }
    validate_plan(result)
    return result


def write_plans(
    output: Path, environment: dict, port: int = CONTROL_PORT
) -> dict[str, str]:
    """Write every case plan and the source-hash table into a new directory.

    Returns
    -------
    dict[str, str]
        The SHA-256 digest of each written plan, keyed by case name.
    """
    generated = {
        name: plan(name, steps, environment, port) for name, steps in plans().items()
    }
    output.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, value in generated.items():
        encoded = (json.dumps(value, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(encoded)
        hashes[name] = hashlib.sha256(encoded).hexdigest()
    (output / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
    return hashes


def write_command(*, runtime: str, output: str, port: int = CONTROL_PORT) -> None:
    """Write the plans for the runtime record and print their digests as JSON."""
    environment = json.loads(Path(runtime).read_text(encoding="utf-8"))
    hashes = write_plans(Path(output), environment, port)
    sys.stdout.write(json.dumps(hashes, indent=2) + "\n")


def main() -> None:
    """Write the plans from the command line."""
    run(write_command, __doc__)


if __name__ == "__main__":
    main()
