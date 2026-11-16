"""Perform the positive alias rehearsal on the wire.

Part of the missing-alias runner (``native_missing_alias_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. The rehearsal never removes the target.
"""

import json
import time
import typing as typ

import native_missing_alias_cases as cases
from native_missing_alias_control_frames import (
    AGREEMENT_SHA,
    Report,
    Wire,
    digest,
    direct,
    exact_fields,
    need,
    positive_alias,
)
from native_missing_alias_control_host import host_state, same_target
from native_missing_alias_control_operator import check_screens, operator_gate
from native_plan import login
from native_wire_names import (
    FIELD_DATA,
    TYPE_CREATE_FOLDER,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import ADMIN
from verify_native_mkdir import listing

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

HELLO_REPLY_BYTES = 8
REPLY_WAIT_SECONDS = 5
RECEIPT_WAIT_SECONDS = 120
POLL_SECONDS = 0.1
ROOT_COUNT = 42
LOGIN_REPLY_FIELDS = {160: b"\0\xbe", 161: b"\0\0"}


def exchange(wire: Wire, spec: Report, alias: bytes | None = None) -> Report:
    """Send one planned request and return its direct reply.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    raw = cases.request_hex(spec, alias)
    wire.send("main", raw, spec["label"])
    wire.request_count += 1
    wire.partial["request_count"] = wire.request_count
    if spec["kind"] == TYPE_CREATE_FOLDER:
        wire.partial["mutation_count"] = 1
    wire.wait_for(
        lambda: bool(wire.match("main", 0, spec["id"], 1)),
        REPLY_WAIT_SECONDS,
        spec["label"],
    )
    return direct(wire.frames, spec["id"])


def _login(wire: Wire, guard: cabc.Callable[[], None]) -> None:
    """Connect the admin and check its login, its privileges and its agreement."""
    guard()
    wire.execute({"op": "connect", "connection": "main", "endpoint": "control"})
    wire.execute({"op": "send", "connection": "main", "hex": cases.HELLO})
    wire.execute({
        "op": "read",
        "connection": "main",
        "size": HELLO_REPLY_BYTES,
        "expect_hex": cases.HELLO_REPLY,
    })
    wire.buffers["main"] = bytearray()
    wire.send("main", login()[3]["hex"], "login")
    wire.request_count = 1
    wire.partial["request_count"] = 1
    wire.wait_for(
        lambda: (
            bool(wire.match("main", 0, 1, 1))
            and bool(wire.match("main", TYPE_PRIVILEGES_NOTIFICATION, None, 0))
            and bool(wire.match("main", TYPE_LOGIN_AGREEMENT, None, 0))
        ),
        REPLY_WAIT_SECONDS,
        "admin login",
    )
    ack = direct(wire.frames, 1)
    need(exact_fields(ack) == LOGIN_REPLY_FIELDS, "Login version/extras differ")
    grants = wire.match("main", TYPE_PRIVILEGES_NOTIFICATION, None, 0)
    agreements = wire.match("main", TYPE_LOGIN_AGREEMENT, None, 0)
    need(
        len(grants) == len(agreements) == 1
        and exact_fields(grants[0]) == {110: ADMIN}
        and digest(exact_fields(agreements[0]).get(FIELD_DATA, b"")) == AGREEMENT_SHA,
        "Admin grant/agreement differs",
    )


def _announce(wire: Wire, plan: Report) -> None:
    """Print the READY record that tells the operator to make the alias."""
    print(
        json.dumps(
            {
                "event": "READY",
                "stage": wire.partial["stage"],
                "plan_sha256": digest((json.dumps(plan, indent=2) + "\n").encode()),
                "emulator_pid": plan["environment"]["emulator_pid"],
                "emulator_netns_inode": plan["environment"]["emulator_netns_inode"],
                "numbered_requests": wire.request_count,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def _await_receipt(
    wire: Wire, receipt_path: Path, guard: cabc.Callable[[], None]
) -> None:
    """Wait for the operator's reviewed Finder receipt, keeping the guard."""
    until = min(time.monotonic() + RECEIPT_WAIT_SECONDS, wire.deadline)
    while not receipt_path.is_file():
        need(time.monotonic() < until, "Reviewed Finder receipt absent")
        guard()
        wire.poll(POLL_SECONDS)
    need(not receipt_path.is_symlink(), "Finder receipt is a symlink")


def perform(
    wire: Wire, plan: Report, receipt_path: Path, guard: cabc.Callable[[], None]
) -> None:
    """Run the rehearsal: create the folder, wait for the operator, read the alias.

    Parameters
    ----------
    wire : Wire
        The transport; its ``partial`` keeps the progress if the run fails.
    plan : dict[str, typing.Any]
        The prepared plan.
    receipt_path : pathlib.Path
        The operator's reviewed Finder receipt, which appears during the run.
    guard : collections.abc.Callable[[], None]
        The runtime gate to run before each wait.
    """
    wire.partial = {
        "request_count": 0,
        "mutation_count": 0,
        "operator": None,
        "host_before": None,
        "host_after": None,
        "positive206": None,
        "stage": "start",
    }
    before = host_state(plan)
    need(
        before["finder"]["sha256"] == plan["environment"]["initial_finf_sha256"],
        "Pre-staged Finder sidecar differs from runtime pin",
    )
    wire.partial["host_before"] = before
    _login(wire, guard)
    create, root = plan["requests"][:2]
    exchange(wire, create)
    wire.partial["stage"] = "created"
    roots = listing(exchange(wire, root))
    need(
        len(roots) == ROOT_COUNT and cases.ROOT in roots,
        "Owned Files folder/root count differs",
    )
    wire.partial["stage"] = "awaiting-reviewed-Finder-receipt"
    _announce(wire, plan)
    _await_receipt(wire, receipt_path, guard)
    operator_raw = receipt_path.read_bytes()
    receipt = json.loads(operator_raw)
    name = operator_gate(receipt, plan)
    check_screens(receipt, receipt_path.parent)
    after = host_state(plan)
    same_target(before, after)
    wire.partial["host_after"] = after
    wire.partial["operator"] = {
        "sha256": digest(operator_raw),
        "alias_name_hex": name.hex(),
        "screenshots": receipt["screenshots"],
    }
    wire.partial["stage"] = "reviewed-Finder-receipt"
    listed = listing(exchange(wire, plan["requests"][2]))
    need(set(listed) == {name}, "Copied alias directory ambiguous/foreign")
    wire.partial["stage"] = "copied-alias-listed"
    frame = exchange(wire, plan["requests"][3], name)
    wire.partial["positive206"] = positive_alias(frame, name)
    wire.partial["stage"] = "positive206-live-wire-only"
