"""Prepare configured login-extra and existing-session refresh observations."""

import typing as typ

from native_auth_cases import complement
from native_banner_cases import GIF_B, NATIVE_VERSION
from native_plan import (
    LOGIN_REQUEST_ID,
    Action,
    close,
    connect,
    login,
    packet,
    payload,
    read,
    send,
)
from native_wire_names import (
    BANNER_MIN_VERSION,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_VERSION,
    HTXF_MAGIC_HEX,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_DOWNLOAD_BANNER,
    TYPE_EMPTY_ACK,
    TYPE_LOGIN,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

CONFIGURED_URL = b"https://example.invalid/extras-url"
# The number of N bytes that precede the final byte of the 31-byte names.
NAME_FILL_BYTES = 30
# The handshake requests that login() plans before the login request.
HANDSHAKE_STEP_COUNT = 3
# A client version one below the banner threshold.
BELOW_BANNER_VERSION = 150
DATA_TIMEOUT_SECONDS = 30
QUIET_TIMEOUT_SECONDS = 3
PAUSE_SECONDS = 3
LIFETIME_PAUSE_SECONDS = 20

NAMES = {
    "name-a": b"mothra-name-a",
    "name-b": b"mothra-name-b",
    "name31": b"N" * NAME_FILL_BYTES + b"A",
    "name32": b"N" * NAME_FILL_BYTES + b"B",
    "macroman": b"mothra-\x9a",
    "url": b"mothra-name-b",
    "none": b"mothra-name-b",
    "restored": b"",
}


def authenticate(
    version: int | bytes | None,
    early: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    connection: str = "main",
) -> Action:
    """Plan the login request, with the optional version and early values.

    Returns
    -------
    native_plan.Action
        The send of the login request on ``connection``.
    """
    values = [
        (FIELD_PASSWORD, complement(b"mothra19")),
        (FIELD_LOGIN, complement(b"admin")),
    ]
    if version is not None:
        encoded = version.to_bytes(2, "big") if isinstance(version, int) else version
        values.append((FIELD_VERSION, encoded))
    if early:
        values += [(FIELD_NAME, b"extras-fixture"), (FIELD_ICON, b"\0\1")]
    return send(packet(TYPE_LOGIN, LOGIN_REQUEST_ID, payload(values)), connection)


def start(
    version: int | None,
    early: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    connection: str = "main",
) -> list[Action]:
    """Plan the handshake, the login request and the reads of its replies.

    Returns
    -------
    list[native_plan.Action]
        The handshake, the login request and the reads that follow it.
    """
    steps = [{**s, "connection": connection} for s in login()[:HANDSHAKE_STEP_COUNT]]
    steps += [authenticate(version, early, connection), read(connection)]
    if early:
        steps += [read(connection)]
    return [*steps, read(connection)]


def complete(connection: str = "main") -> list[Action]:
    """Plan the acceptance request and the reads of its replies.

    Returns
    -------
    list[native_plan.Action]
        The send of the acceptance request and the two reads that follow it.
    """
    return [
        send(
            packet(
                TYPE_ACCEPT_AGREEMENT,
                2,
                payload([(FIELD_NAME, b"extras-completed"), (FIELD_ICON, b"\0\2")]),
            ),
            connection,
        ),
        read(connection, match_frame={"is_reply": 1, "id": 2}),
        read(connection),
    ]


def version_presence() -> Cases:
    """Plan four delayed logins with identical credentials and different field 160.

    Returns
    -------
    dict[str, Case]
        Each case ends after the matching login reply, including an error reply.
    """
    cases: Cases = {}
    for name, version in (
        ("version-absent", None),
        ("version-empty", b""),
        ("version-one-zero", b"\x00"),
        ("version-two-zero", b"\x00\x00"),
    ):
        steps = [
            *login()[:HANDSHAKE_STEP_COUNT],
            authenticate(version, early=False),
            read(match_frame={"is_reply": 1, "id": LOGIN_REQUEST_ID}),
            close(),
        ]
        cases[name] = (
            steps,
            {"version_hex": None if version is None else version.hex()},
        )
    return cases


def configured(phase: str) -> Cases:
    """Plan each configured login-extra case for one named server name.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by its label.
    """
    name = NAMES[phase]
    versions = (
        [None, 0, BELOW_BANNER_VERSION, BANNER_MIN_VERSION, NATIVE_VERSION]
        if phase in {"name-a", "restored"}
        else [NATIVE_VERSION]
    )
    cases: Cases = {}
    for version in versions:
        for early in [False, True]:
            steps = start(version, early)
            if not early:
                steps += complete()
            steps += [
                {"op": "pause", "seconds": PAUSE_SECONDS},
                send(packet(TYPE_EMPTY_ACK, 90)),
                read(match_frame={"is_reply": 1, "id": 90}),
                close(),
            ]
            label = (
                phase
                + "-"
                + ("absent" if version is None else str(version))
                + ("-early" if early else "-delayed")
            )
            cases[label] = (
                steps,
                {
                    "kind": "configured-login-extras",
                    "phase": phase,
                    "name_hex": name.hex(),
                    "version": version,
                    "early": early,
                },
            )
    return cases


def downloads() -> Cases:
    """Plan the banner downloads that the login value and the early login reference.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one download case, by its label.
    """
    steps = start(NATIVE_VERSION, early=True)
    for identifier in [10, 11]:
        reference, size, connection = (
            f"ref{identifier}",
            f"size{identifier}",
            f"data{identifier}",
        )
        steps += [
            send(packet(TYPE_DOWNLOAD_BANNER, identifier)),
            read(
                match_frame={"is_reply": 1, "id": identifier},
                save_fields={
                    reference: FIELD_TRANSFER_REFERENCE,
                    size: FIELD_TRANSFER_SIZE,
                },
            ),
            connect(connection, "data"),
            send(
                HTXF_MAGIC_HEX + "{" + reference + "}0000000000020000",
                connection,
            ),
            {
                "op": "read",
                "connection": connection,
                "size_from": size,
                "expect_hex": GIF_B.hex(),
                "timeout": DATA_TIMEOUT_SECONDS,
            },
            {
                "op": "expect_quiet",
                "connection": connection,
                "timeout": QUIET_TIMEOUT_SECONDS,
            },
            close(connection),
        ]
    steps += [close()]
    return {
        "login-value-versus-banner-references": (
            steps,
            {
                "kind": "login-banner-reference",
                "name_hex": NAMES["name-b"].hex(),
                "banner_hex": GIF_B.hex(),
            },
        )
    }


def lifetime() -> Cases:
    """Plan the name change observed by the sessions that already exist.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one lifetime case, by its label.
    """
    steps = start(NATIVE_VERSION, early=True, connection="observer")
    steps += start(NATIVE_VERSION, early=False, connection="waiting")
    # The operator saves name-b during this bounded pause. Before/after reports
    # and positive Prefs snapshots must prove that the change actually occurred.
    steps += [{"op": "pause", "seconds": LIFETIME_PAUSE_SECONDS}]
    steps += start(NATIVE_VERSION, early=True, connection="fresh")
    steps += [close("fresh")]
    steps += complete("waiting")
    for connection in ["waiting", "observer"]:
        steps += [
            send(packet(TYPE_EMPTY_ACK, 90), connection),
            read(connection, match_frame={"is_reply": 1, "id": 90}),
        ]
    steps += [close("waiting"), {"op": "pause", "seconds": PAUSE_SECONDS}]
    steps += [
        send(packet(TYPE_EMPTY_ACK, 91), "observer"),
        read("observer", match_frame={"is_reply": 1, "id": 91}),
        close("observer"),
    ]
    return {
        "name-change-with-existing-sessions": (
            steps,
            {
                "kind": "login-name-lifetime",
                "pause_seconds": LIFETIME_PAUSE_SECONDS,
                "before_hex": NAMES["name-a"].hex(),
                "after_hex": NAMES["name-b"].hex(),
            },
        )
    }
