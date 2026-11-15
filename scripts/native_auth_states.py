"""Plan the native login states and the acceptances around them.

Each case logs in an observer and a subject, varies what the subject sends and
when it completes, and reads the roster the observer sees.
"""

import typing as typ

from native_auth_steps import (
    ADMIN_PASSWORD,
    FIRST_ID,
    HANDSHAKE_STEPS,
    PASSWORD,
    Case,
    Cases,
    answer,
    authentication,
    on,
    pause,
    roster,
    silence,
)
from native_plan import (
    FIXTURE_ICON,
    Action,
    close,
    login,
    packet,
    payload,
    read,
    send,
)
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_EMPTY_ACK,
    TYPE_LOGIN,
)

VISIBLE_NAME = b"auth-visible"
COMPLETED_NAME = b"auth-completed"
COMPLETED_ICON = b"\0\x02"
HIGH_BIT_ICON = b"\x80\0"
HIGH_BIT_ICON_VALUE = 32768
EARLY_ICON_VALUE = 1
DELAYED_ICON_VALUE = 2
DELAYED_ACCEPT_ID = 2
DELAYED_PAUSE_ID = 90
CLOSING_PAUSE_ID = 91
REPLAY_LOGIN_ID = 4
REPLAY_AGREEMENT_ID = 3


class Variant(typ.NamedTuple):
    """One login whose identity fields and timing are varied.

    Attributes
    ----------
    label : str
        The case name.
    key : bytes
        The login key.
    password : bytes
        The password that is sent.
    name : bytes | None
        The visible name, or ``None`` to omit it.
    icon : bytes | None
        The icon, or ``None`` to omit it.
    early : bool
        Whether the login completes without a separate acceptance.
    """

    label: str
    key: bytes
    password: bytes
    name: bytes | None
    icon: bytes | None
    early: bool


VARIANTS = [
    Variant(
        "early-admin", b"admin", ADMIN_PASSWORD, VISIBLE_NAME, FIXTURE_ICON, early=True
    ),
    Variant("delayed-admin", b"admin", ADMIN_PASSWORD, None, None, early=False),
    Variant(
        "early-bypass",
        b"m-auth-bypass",
        PASSWORD,
        VISIBLE_NAME,
        FIXTURE_ICON,
        early=True,
    ),
    Variant("delayed-bypass", b"m-auth-bypass", PASSWORD, None, None, early=False),
    Variant(
        "name-without-icon", b"admin", ADMIN_PASSWORD, VISIBLE_NAME, None, early=False
    ),
    Variant(
        "icon-without-name", b"admin", ADMIN_PASSWORD, None, FIXTURE_ICON, early=False
    ),
    Variant(
        "icon-narrows-zero",
        b"admin",
        ADMIN_PASSWORD,
        VISIBLE_NAME,
        b"\0\1\0\0",
        early=False,
    ),
    Variant(
        "high-bit-icon-is-nonzero",
        b"admin",
        ADMIN_PASSWORD,
        VISIBLE_NAME,
        HIGH_BIT_ICON,
        early=True,
    ),
]


def settle(first_roster: int) -> list[Action]:
    """Plan the close of the subject, a pause and two roster views.

    Returns
    -------
    list[dict[str, typing.Any]]
        The close, the pause, the roster, then the close of the observer.
    """
    return [
        *roster(first_roster),
        close("subject"),
        pause(),
        *roster(first_roster + 1),
        close("observer"),
    ]


def observed_login() -> list[Action]:
    """Plan the observer's login, its first roster and the subject's handshake.

    Returns
    -------
    list[dict[str, typing.Any]]
        The observer login, the roster with ID 10, then the subject handshake.
    """
    return (
        on("observer", login())
        + roster(FIRST_ID)
        + on("subject", login()[:HANDSHAKE_STEPS])
    )


def completion(connection: str) -> list[Action]:
    """Plan the explicit acceptance that completes a delayed login.

    Returns
    -------
    list[dict[str, typing.Any]]
        The pause, the acceptance and the empty ACK that follows it.
    """
    accept = payload([(FIELD_NAME, COMPLETED_NAME), (FIELD_ICON, COMPLETED_ICON)])
    return [
        pause(),
        send(packet(TYPE_ACCEPT_AGREEMENT, DELAYED_ACCEPT_ID, accept), connection),
        answer(DELAYED_ACCEPT_ID, connection),
        read(connection),
        send(packet(TYPE_EMPTY_ACK, DELAYED_PAUSE_ID), connection),
        answer(DELAYED_PAUSE_ID, connection),
    ]


def replays() -> list[Action]:
    """Plan the replay of an acceptance and a login on the subject.

    Returns
    -------
    list[dict[str, typing.Any]]
        The requests, an empty ACK, the replies and the close of the subject.
    """
    return [
        send(packet(TYPE_ACCEPT_AGREEMENT, REPLAY_AGREEMENT_ID), "subject"),
        answer(REPLAY_AGREEMENT_ID, "subject"),
        send(packet(TYPE_LOGIN, REPLAY_LOGIN_ID), "subject"),
        answer(REPLAY_LOGIN_ID, "subject"),
        send(packet(TYPE_EMPTY_ACK, CLOSING_PAUSE_ID), "subject"),
        answer(CLOSING_PAUSE_ID, "subject"),
        close("subject"),
        pause(),
    ]


def state_case(variant: Variant) -> Case:
    """Plan one login whose visible identity and timing are varied.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the case.
    """
    label, key, password, name, icon, early = variant
    steps = observed_login() + roster(FIRST_ID + 1)
    steps += [
        authentication(key, password, name=name, icon=icon, connection="subject"),
        read("subject"),
        read("subject"),
    ]
    if early:
        steps += [read("subject")]
    steps += roster(FIRST_ID + 2)
    if not early:
        steps += completion("subject")
    steps += roster(FIRST_ID + 3)
    steps += replays() + roster(FIRST_ID + 4) + [close("observer")]
    icon_value = (
        HIGH_BIT_ICON_VALUE
        if label == "high-bit-icon-is-nonzero"
        else EARLY_ICON_VALUE
        if early
        else DELAYED_ICON_VALUE
    )
    return (
        steps,
        {
            "kind": "login-state",
            "early": early,
            "bypass": "bypass" in label,
            "icon": icon_value,
        },
    )


def preauth_acceptance() -> Case:
    """Plan an acceptance sent before any login.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the case.
    """
    steps = on("observer", login()) + roster(FIRST_ID)
    steps += on("subject", login()[:HANDSHAKE_STEPS])
    steps += [
        send(packet(TYPE_ACCEPT_AGREEMENT, 1), "subject"),
        answer(1, "subject"),
    ]
    steps += settle(FIRST_ID + 1)
    return steps, {"kind": "preauth-acceptance"}


def failed_password_acceptance() -> Case:
    """Plan an acceptance sent after a login with a wrong password.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the case.
    """
    steps = on("observer", login()) + roster(FIRST_ID)
    steps += on("subject", login()[:HANDSHAKE_STEPS])
    steps += [
        authentication(b"admin", b"wrong-auth-password", connection="subject"),
        read("subject"),
        send(packet(TYPE_ACCEPT_AGREEMENT, 2), "subject"),
        silence("subject"),
    ]
    steps += settle(FIRST_ID + 1)
    return steps, {"kind": "failed-password-acceptance"}


def states() -> Cases:
    """Plan the login states, then the acceptances without a good login.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The login-state and acceptance cases.
    """
    cases = {variant.label: state_case(variant) for variant in VARIANTS}
    cases["acceptance-before-login"] = preauth_acceptance()
    cases["acceptance-after-failed-password"] = failed_password_acceptance()
    return cases


def reauthentication_case(*, before: bool) -> Case:
    """Plan a second login, with or without an earlier acceptance.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the case.
    """
    steps = on("observer", login()) + roster(FIRST_ID)
    steps += on("subject", login()[:HANDSHAKE_STEPS])
    if before:
        steps += [
            send(packet(TYPE_ACCEPT_AGREEMENT, 1), "subject"),
            answer(1, "subject"),
        ]
    else:
        steps += [
            authentication(
                b"admin", ADMIN_PASSWORD, name=None, icon=None, connection="subject"
            ),
            read("subject"),
            read("subject"),
        ]
    steps += roster(FIRST_ID + 1)
    steps += [
        authentication(b"admin", ADMIN_PASSWORD, connection="subject", identifier=2)
    ]
    if before:
        steps += [silence("subject")]
    else:
        steps += [answer(2, "subject"), read("subject"), read("subject")]
    steps += settle(FIRST_ID + 2)
    return steps, {"kind": "reauthentication", "preauth_acceptance": before}


def reauthentication() -> Cases:
    """Plan the repeated login before and after a premature acceptance.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The two reauthentication cases.
    """
    cases = {}
    for before in [False, True]:
        label = (
            "login-after-premature-acceptance"
            if before
            else "repeated-login-before-acceptance"
        )
        cases[label] = reauthentication_case(before=before)
    return cases
