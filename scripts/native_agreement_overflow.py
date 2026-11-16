"""Plan the partial logins that follow an agreement field over its TLV cap.

The planner in ``native_agreement_cases`` re-exports ``field_overflow``, which
prepare_native_cases and verify_native_agreements reach through that module.
"""

import typing as typ

from native_auth_cases import PASSWORD, authentication, roster
from native_plan import Action, close, eof, login, packet, read, send
from native_wire_names import TYPE_ACCEPT_AGREEMENT, TYPE_EMPTY_ACK, TYPE_LOGIN

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

QUIET_TIMEOUT_SECONDS = 3
PAUSE_SECONDS = 3
# The handshake requests that login() plans before the login request.
HANDSHAKE_STEP_COUNT = 3


def field_overflow(name: str) -> Cases:
    """Plan the partial login after a loaded buffer exceeds the TLV field cap.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The early and delayed overflow cases of the phase, by label.
    """
    cases: Cases = {}
    for early in [False, True]:
        steps = [
            {**s, "connection": "observer"} for s in login()[:HANDSHAKE_STEP_COUNT]
        ]
        steps += [
            authentication(b"m-auth-bypass", PASSWORD, connection="observer"),
            read("observer"),
            read("observer"),
            read("observer"),
            *roster(10),
        ]
        steps += [
            {**s, "connection": "subject"} for s in login()[:HANDSHAKE_STEP_COUNT]
        ]
        steps += [
            authentication(
                b"admin",
                b"mothra19",
                name=b"auth-visible" if early else None,
                icon=b"\0\1" if early else None,
                connection="subject",
            ),
            read("subject"),
        ]
        if early:
            steps += [read("subject")]
        steps += [
            {
                "op": "expect_quiet",
                "connection": "subject",
                "timeout": QUIET_TIMEOUT_SECONDS,
            },
            send(packet(TYPE_EMPTY_ACK, 91), "subject"),
        ]
        if early:
            steps += [
                read("subject", match_frame={"is_reply": 1, "id": 91}),
                *roster(12),
            ]
            for kind, identifier in [(TYPE_ACCEPT_AGREEMENT, 2), (TYPE_LOGIN, 3)]:
                steps += [
                    send(packet(kind, identifier), "subject"),
                    read("subject", match_frame={"is_reply": 1, "id": identifier}),
                ]
            steps += roster(13)
        else:
            steps += [eof("subject"), *roster(12)]
        steps += [close("subject"), {"op": "pause", "seconds": PAUSE_SECONDS}]
        steps += roster(14 if early else 13)
        steps += [close("observer")]
        label = "early" if early else "delayed"
        cases[name + "-" + label] = (
            steps,
            {"kind": "agreement-field-overflow", "phase": name, "early": early},
        )
    return cases
