"""Prepare controlled queues with global limit2 and per-session limit1."""

from native_plan import close, connect, eof, login, packet, payload, read, send


def session(name: str) -> list[dict]:
    """Return the login steps on a named connection."""
    return [{**s, "connection": name} for s in login()]


def request(
    owner: str,
    identifier: int,
    variable: str,
    *,
    mode: int | None = None,
    empty: bool = False,
    empty_preview: bool = False,
) -> list[dict]:
    """Return the steps that request a fixture download in a mode and, unless the preview is empty, save its reference and size."""
    filename = b"mothra-empty-fixture" if empty else b"mothra-fork-fixture"
    values = [(201, filename)]
    if mode is not None:
        values.append((204, mode.to_bytes(2, "big")))
    options = {"match_frame": {"is_reply": 1, "id": identifier}}
    if not empty_preview:
        options["save_fields"] = {variable: 107, variable + "_size": 108}
    return [
        send(packet(202, identifier, payload(values)), owner),
        read(owner, **options),
    ]


def cancel(owner: str, identifier: int, variable: str | None) -> list[dict]:
    """Return the steps that cancel a download by its saved reference and read the reply."""
    value = payload([(107, b"REF!")]) if variable else b"\0\0"
    encoded = packet(214, identifier, value)
    if variable:
        encoded = encoded.replace(b"REF!".hex(), "{" + variable + "}")
    return [
        send(encoded, owner),
        read(owner, match_frame={"is_reply": 1, "id": identifier}),
    ]


def pump(owner: str, identifier: int, seconds: int = 3) -> list[dict]:
    """Return the steps that pause and then exchange a request so that the queue advances."""
    return [
        {"op": "pause", "seconds": seconds},
        send(packet(500, identifier), owner),
        read(owner, match_frame={"is_reply": 1, "id": identifier}),
    ]


def attach(variable: str) -> list[dict]:
    """Return the steps that open the data connection of a saved reference."""
    return [
        connect(variable, "data"),
        send("48545846{" + variable + "}0000000000000000", variable),
    ]


def take(owner: str, variable: str, identifier: int) -> list[dict]:
    """Return the steps that read a whole download, cancel it and close its connection."""
    return (
        attach(variable)
        + [
            {
                "op": "read",
                "connection": variable,
                "size_from": variable + "_size",
                "timeout": 30,
            }
        ]
        + cancel(owner, identifier, variable)
        + [eof(variable), close(variable)]
    )


def queues() -> dict[str, tuple[list[dict], dict]]:
    """Build the plan that queues downloads in every mode and then takes them in order."""
    modes = session("a") + request("a", 10, "blocker")
    specs = [
        (0, False),
        (1, False),
        (3, False),
        (65535, False),
        (2, False),
        (None, True),
    ]
    for index, (mode, empty) in enumerate(specs, 11):
        modes += request("a", index, f"m{index}", mode=mode, empty=empty)
    modes += request("a", 17, "zero", mode=2, empty=True, empty_preview=True)
    modes += cancel("a", 20, "blocker") + pump("a", 21)
    for index in range(11, 17):
        modes += take("a", f"m{index}", index + 20) + pump("a", index + 40)
    modes += [close("a")]

    middle = session("a")
    for index in range(1, 5):
        middle += request("a", 9 + index, f"a{index}")
    middle += attach("a3") + [{"op": "expect_quiet", "connection": "a3", "timeout": 3}]
    middle += cancel("a", 20, "a3") + [eof("a3"), close("a3")] + pump("a", 21)
    middle += cancel("a", 22, "a2") + pump("a", 23)
    middle += cancel("a", 24, "a1") + pump("a", 25)
    middle += take("a", "a4", 26) + cancel("a", 27, "a4") + [close("a")]

    fairness = session("a")
    for index in range(1, 4):
        fairness += request("a", 9 + index, f"a{index}")
    fairness += session("b") + request("b", 10, "b1") + request("b", 11, "b2")
    fairness += cancel("b", 20, "b1") + pump("b", 21) + pump("a", 22)
    fairness += take("b", "b2", 23)
    fairness += cancel("a", 24, "a1") + pump("a", 25)
    fairness += attach("a3") + [
        {"op": "expect_quiet", "connection": "a3", "timeout": 3}
    ]
    fairness += cancel("b", 26, "a2") + [
        {"op": "expect_quiet", "connection": "a3", "timeout": 3}
    ]
    fairness += cancel("a", 27, "a2") + pump("a", 28)
    fairness += [
        {"op": "read", "connection": "a3", "size_from": "a3_size", "timeout": 30}
    ]
    fairness += cancel("a", 29, "a3") + [eof("a3"), close("a3")]
    fairness += cancel("a", 30, "a1") + cancel("a", 31, None)
    for identifier, encoded in [(32, bytes(4)), (33, bytes.fromhex("ffffffff"))]:
        fairness += [
            send(packet(214, identifier, payload([(107, encoded)])), "a"),
            read("a", match_frame={"is_reply": 1, "id": identifier}),
        ]
    fairness += [close("b"), close("a")]
    return {
        "queue-mode-matrix": (modes, {"kind": "queue-modes"}),
        "queue-cancel-position": (middle, {"kind": "queue-cancel-position"}),
        "queue-two-owner-order": (fairness, {"kind": "queue-two-owner-order"}),
    }


def timer() -> dict[str, tuple[list[dict], dict]]:
    """Build the plan that lets a queued download wait until its pending timeout expires."""
    steps = session("a") + request("a", 10, "expired") + request("a", 11, "waiting")
    for index in range(12):
        steps += pump("a", 100 + index, 45)
    steps += attach("expired") + [eof("expired"), close("expired")]
    steps += take("a", "waiting", 120) + [close("a")]
    return {
        "queue-pending-timeout": (
            steps,
            {"kind": "queue-pending-timeout", "wait_seconds": 540},
        )
    }
