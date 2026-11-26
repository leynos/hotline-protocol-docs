"""Prepare native account lookup and login/agreement transition observations."""

from native_plan import close, login, packet, payload, quiet, read, send

PASSWORD = b"auth-pass"
KEY31 = b"m-auth-" + b"a" * 24
KEY32 = b"m-auth-" + b"b" * 25
ACCOUNTS = [
    (b"m-auth-cr", b"Auth CR", bytes(8)),
    (b"m-auth-\x8a", b"Auth high byte", bytes(8)),
    (KEY31, b"Auth length31", bytes(8)),
    (KEY32, b"Auth length32", bytes(8)),
    (b"m-auth-bypass", b"Auth bypass", bytes.fromhex("0000003000000000")),
]


def complement(value: bytes) -> bytes:
    """Return each byte XORed with 0xFF, as the protocol obscures keys and passwords."""
    return bytes(b ^ 255 for b in value)


def seed() -> dict:
    """Build the plan that creates the authentication fixture accounts."""
    steps = login()
    steps += [send(packet(352, 9, payload([(105, b"guest")]))), read()]
    for identifier, (key, name, privileges) in enumerate(ACCOUNTS, 10):
        steps += [
            send(
                packet(
                    350,
                    identifier,
                    payload(
                        [
                            (105, complement(key)),
                            (106, complement(PASSWORD)),
                            (102, name),
                            (110, privileges),
                        ]
                    ),
                )
            ),
            read(match_frame={"is_reply": 1, "id": identifier}),
            send(packet(352, identifier + 10, payload([(105, key)]))),
            read(match_frame={"is_reply": 1, "id": identifier + 10}),
        ]
    steps += [{"op": "pause", "seconds": 3}, close()]
    return {"seed-owned-auth-accounts": (steps, {"kind": "account-seed"})}


def authentication(
    key: bytes | None,
    password: bytes,
    *,
    name: bytes | None = b"auth-fixture",
    icon: bytes | None = b"\0\1",
    connection: str = "main",
    identifier: int = 1,
) -> dict:
    """Build the plan step that sends an authentication request with optional name and icon."""
    values = [(106, complement(password)), (160, b"\0\xbe")]
    if key is not None:
        values.append((105, complement(key)))
    if name is not None:
        values.append((102, name))
    if icon is not None:
        values.append((104, icon))
    return send(packet(107, identifier, payload(values)), connection)


def lookup(*, missing_guest: bool = False) -> dict:
    """Build the plans that probe how account keys are looked up."""
    cases = {}
    for name, key, password in [
        ("admin-mixed-case", b"AdMiN", b"mothra19"),
        ("admin-upper-case", b"ADMIN", b"mothra19"),
        ("guest-absent", None, b""),
        ("guest-empty", b"", b""),
        ("guest-explicit", b"guest", b""),
        ("unknown-nonempty", b"m-auth-no-such-account", b""),
        ("carriage-return-maps-to-hyphen", b"m-auth\rcr", PASSWORD),
        ("high-byte-80-maps-to-8a", b"m-auth-\x80", PASSWORD),
        ("nul-leading", b"\0admin", b"mothra19"),
        ("nul-trailing", b"admin\0", b"mothra19"),
        ("nul-interior", b"ad\0min", b"mothra19"),
        ("nul-only", b"\0", b""),
        ("name-length31", KEY31, PASSWORD),
        ("name-length32", KEY32, PASSWORD),
        ("name-over32-clipped", KEY32 + b"-ignored", PASSWORD),
    ]:
        if missing_guest and not name.startswith("guest-"):
            continue
        success = name in {
            "admin-mixed-case",
            "admin-upper-case",
            "carriage-return-maps-to-hyphen",
            "high-byte-80-maps-to-8a",
            "name-length31",
        } or (name.startswith("guest-") and not missing_guest)
        steps = login()[:3] + [authentication(key, password), read()]
        if success:
            steps += [read(), read()]
        steps += [quiet(), close()]
        label = (
            ("missing-" if missing_guest else "configured-") + name
            if name.startswith("guest-")
            else name
        )
        cases[label] = (
            steps,
            {
                "kind": "lookup",
                "key_hex": None if key is None else key.hex(),
                "success": success,
            },
        )
    return cases


def guest_create() -> dict:
    """Build the plan that creates a guest account with an empty password."""
    steps = login() + [
        send(
            packet(
                350,
                10,
                payload(
                    [
                        (105, complement(b"guest")),
                        (106, b""),
                        (102, b"Auth guest"),
                        (110, bytes(8)),
                    ]
                ),
            )
        ),
        read(match_frame={"is_reply": 1, "id": 10}),
        send(packet(352, 11, payload([(105, b"guest")]))),
        read(match_frame={"is_reply": 1, "id": 11}),
        {"op": "pause", "seconds": 3},
        close(),
    ]
    return {"create-temporary-guest": (steps, {"kind": "guest-create"})}


def roster(identifier: int) -> list[dict]:
    """Build the steps that fetch the user list as the observer connection."""
    return [
        send(packet(300, identifier), "observer"),
        read("observer", match_frame={"is_reply": 1, "id": identifier}),
    ]


def states() -> dict:
    """Build the plans that authenticate in each session state, with and without early name and icon."""
    cases = {}
    variants = [
        ("early-admin", b"admin", b"mothra19", b"auth-visible", b"\0\1", True),
        ("delayed-admin", b"admin", b"mothra19", None, None, False),
        ("early-bypass", b"m-auth-bypass", PASSWORD, b"auth-visible", b"\0\1", True),
        ("delayed-bypass", b"m-auth-bypass", PASSWORD, None, None, False),
        ("name-without-icon", b"admin", b"mothra19", b"auth-visible", None, False),
        ("icon-without-name", b"admin", b"mothra19", None, b"\0\1", False),
        (
            "icon-narrows-zero",
            b"admin",
            b"mothra19",
            b"auth-visible",
            b"\0\1\0\0",
            False,
        ),
        (
            "high-bit-icon-is-nonzero",
            b"admin",
            b"mothra19",
            b"auth-visible",
            b"\x80\0",
            True,
        ),
    ]
    for label, key, password, name, icon, early in variants:
        steps = [{**s, "connection": "observer"} for s in login()] + roster(10)
        steps += [{**s, "connection": "subject"} for s in login()[:3]] + roster(11)
        steps += [
            authentication(key, password, name=name, icon=icon, connection="subject"),
            read("subject"),
            read("subject"),
        ]
        if early:
            steps += [read("subject")]
        steps += roster(12)
        if not early:
            steps += [
                {"op": "pause", "seconds": 3},
                send(
                    packet(
                        121, 2, payload([(102, b"auth-completed"), (104, b"\0\x02")])
                    ),
                    "subject",
                ),
                read("subject", match_frame={"is_reply": 1, "id": 2}),
                read("subject"),
                send(packet(500, 90), "subject"),
                read("subject", match_frame={"is_reply": 1, "id": 90}),
            ]
        steps += roster(13)
        steps += (
            [
                send(packet(121, 3), "subject"),
                read("subject", match_frame={"is_reply": 1, "id": 3}),
                send(packet(107, 4), "subject"),
                read("subject", match_frame={"is_reply": 1, "id": 4}),
                send(packet(500, 91), "subject"),
                read("subject", match_frame={"is_reply": 1, "id": 91}),
                close("subject"),
                {"op": "pause", "seconds": 3},
            ]
            + roster(14)
            + [close("observer")]
        )
        cases[label] = (
            steps,
            {
                "kind": "login-state",
                "early": early,
                "bypass": "bypass" in label,
                "icon": 32768
                if label == "high-bit-icon-is-nonzero"
                else 1
                if early
                else 2,
            },
        )
    steps = [{**s, "connection": "observer"} for s in login()] + roster(10)
    steps += [{**s, "connection": "subject"} for s in login()[:3]]
    steps += [
        send(packet(121, 1), "subject"),
        read("subject", match_frame={"is_reply": 1, "id": 1}),
    ]
    steps += (
        roster(11)
        + [close("subject"), {"op": "pause", "seconds": 3}]
        + roster(12)
        + [close("observer")]
    )
    cases["acceptance-before-login"] = (steps, {"kind": "preauth-acceptance"})
    steps = [{**s, "connection": "observer"} for s in login()] + roster(10)
    steps += [{**s, "connection": "subject"} for s in login()[:3]]
    steps += [
        authentication(b"admin", b"wrong-auth-password", connection="subject"),
        read("subject"),
        send(packet(121, 2), "subject"),
        {"op": "expect_quiet", "connection": "subject", "timeout": 3},
    ]
    steps += (
        roster(11)
        + [close("subject"), {"op": "pause", "seconds": 3}]
        + roster(12)
        + [close("observer")]
    )
    cases["acceptance-after-failed-password"] = (
        steps,
        {"kind": "failed-password-acceptance"},
    )
    return cases


def reauthentication() -> dict:
    """Build the plans that authenticate a second time, before and after the first request."""
    cases = {}
    for before in [False, True]:
        steps = [{**s, "connection": "observer"} for s in login()] + roster(10)
        steps += [{**s, "connection": "subject"} for s in login()[:3]]
        if before:
            steps += [
                send(packet(121, 1), "subject"),
                read("subject", match_frame={"is_reply": 1, "id": 1}),
            ]
        else:
            steps += [
                authentication(
                    b"admin", b"mothra19", name=None, icon=None, connection="subject"
                ),
                read("subject"),
                read("subject"),
            ]
        steps += roster(11)
        steps += [
            authentication(b"admin", b"mothra19", connection="subject", identifier=2)
        ]
        if before:
            steps += [{"op": "expect_quiet", "connection": "subject", "timeout": 3}]
        else:
            steps += [
                read("subject", match_frame={"is_reply": 1, "id": 2}),
                read("subject"),
                read("subject"),
            ]

        steps += (
            roster(12)
            + [close("subject"), {"op": "pause", "seconds": 3}]
            + roster(13)
            + [close("observer")]
        )
        label = (
            "login-after-premature-acceptance"
            if before
            else "repeated-login-before-acceptance"
        )
        cases[label] = (
            steps,
            {"kind": "reauthentication", "preauth_acceptance": before},
        )
    return cases


def cleanup() -> dict:
    """Build the plan that deletes the owned authentication accounts."""
    steps = login()
    for identifier, key in enumerate(
        [b"guest"] + [key for key, _, _ in ACCOUNTS if key != KEY32], 10
    ):
        steps += [
            send(packet(351, identifier, payload([(105, complement(key))]))),
            read(match_frame={"is_reply": 1, "id": identifier}),
        ]
        steps += [
            send(packet(352, identifier + 10, payload([(105, key)]))),
            read(match_frame={"is_reply": 1, "id": identifier + 10}),
        ]
    steps += [{"op": "pause", "seconds": 3}, close()]
    return {"remove-owned-auth-accounts": (steps, {"kind": "account-cleanup"})}
