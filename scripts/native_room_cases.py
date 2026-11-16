"""Prepare isolated private-room access, topic and lifecycle observations.

The fixtures live in native_room_data, the shared steps in native_room_steps
and the scenarios in native_room_scenarios. The names below stay importable
from this module: prepare_native_cases.py uses suites, the executed evidence
file run-rooms.py uses inspect, seed and cleanup, and the verifier and its
test use ROLES, key, format_values, message and the scenario names. The
project helpers imported here are re-exported because the original module
imported them at module level.
"""

from native_auth_cases import complement
from native_live_account_cases import account_values, request, subject
from native_mkdir_cases import exchange
from native_plan import close, login, packet, quiet, read, send
from native_room_data import PASSWORD, ROLES, format_values, key
from native_room_scenarios import (
    basics,
    concurrent,
    create_invites,
    formatting,
    invites,
    lifecycle,
    refusals,
    topics,
)
from native_room_steps import barrier, create, finish, message, setup

__all__ = [
    "PASSWORD",
    "ROLES",
    "account_values",
    "barrier",
    "basics",
    "cleanup",
    "close",
    "complement",
    "concurrent",
    "create",
    "create_invites",
    "exchange",
    "finish",
    "format_values",
    "formatting",
    "inspect",
    "invites",
    "key",
    "lifecycle",
    "login",
    "message",
    "packet",
    "quiet",
    "read",
    "refusals",
    "request",
    "seed",
    "send",
    "setup",
    "subject",
    "suites",
    "topics",
]


def inspect() -> tuple[list[dict], dict]:
    """Read the owned accounts and the room-related state before a scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the inspection.
    """
    steps = login() + exchange(348, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    for identifier, label in enumerate(ROLES, 20):
        steps += exchange(352, identifier, [(105, key(label))])
    return [*steps, close()], {"kind": "room-inspect"}


def seed() -> tuple[list[dict], dict]:
    """Create the owned accounts, one for each role.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the seeding.
    """
    steps = login()
    for identifier, (label, access) in enumerate(ROLES.items(), 10):
        steps += exchange(
            350,
            identifier,
            account_values(
                key(label), PASSWORD, b"Room30-" + label.encode(), access, b"room30"
            ),
        )
    return [*steps, close()], {"kind": "room-seed"}


def cleanup() -> tuple[list[dict], dict]:
    """Delete the owned accounts and check the baseline afterwards.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the cleanup.
    """
    steps = login()
    for identifier, label in enumerate(ROLES, 10):
        steps += exchange(351, identifier, [(105, complement(key(label)))])
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return [*steps, close()], {"kind": "room-cleanup"}


def suites() -> dict[str, tuple[list[dict], dict]]:
    """Return every suite of the room corpus, keyed by its name.

    Returns
    -------
    dict[str, tuple[list[dict], dict]]
        Each suite maps to its steps and expectation, in chronological order.
    """
    return {
        "preflight": inspect(),
        "seed": seed(),
        "recovery-inspect": inspect(),
        "basics": basics(),
        "topics": topics(),
        "lifecycle": lifecycle(),
        "concurrent": concurrent(),
        "create_invites": create_invites(),
        "invites": invites(),
        "refusals": refusals(),
        "formatting": formatting(),
        "cleanup": cleanup(),
        "final": inspect(),
    }
