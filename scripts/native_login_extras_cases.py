"""Prepare configured login-extra and existing-session refresh observations."""

from native_auth_cases import complement
from native_banner_cases import GIF_B
from native_plan import close, connect, login, packet, payload, read, send

CONFIGURED_URL = b"https://example.invalid/extras-url"

NAMES = {
    "name-a": b"mothra-name-a",
    "name-b": b"mothra-name-b",
    "name31": b"N" * 30 + b"A",
    "name32": b"N" * 30 + b"B",
    "macroman": b"mothra-\x9a",
    "url": b"mothra-name-b",
    "none": b"mothra-name-b",
    "restored": b"",
}


def authenticate(version: int | None, early: bool, connection: str = "main") -> dict:
    values = [(106, complement(b"mothra19")), (105, complement(b"admin"))]
    if version is not None:
        values.append((160, version.to_bytes(2, "big")))
    if early:
        values += [(102, b"extras-fixture"), (104, b"\0\1")]
    return send(packet(107, 1, payload(values)), connection)


def start(version: int | None, early: bool, connection: str = "main") -> list[dict]:
    steps = [{**s, "connection": connection} for s in login()[:3]]
    steps += [authenticate(version, early, connection), read(connection)]
    if early:
        steps += [read(connection)]
    return steps + [read(connection)]


def complete(connection: str = "main") -> list[dict]:
    return [
        send(
            packet(121, 2, payload([(102, b"extras-completed"), (104, b"\0\2")])),
            connection,
        ),
        read(connection, match_frame={"is_reply": 1, "id": 2}),
        read(connection),
    ]


def configured(phase: str) -> dict:
    name = NAMES[phase]
    versions = [None, 0, 150, 151, 190] if phase in {"name-a", "restored"} else [190]
    cases = {}
    for version in versions:
        for early in [False, True]:
            steps = start(version, early)
            if not early:
                steps += complete()
            steps += [
                {"op": "pause", "seconds": 3},
                send(packet(500, 90)),
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


def downloads() -> dict:
    steps = start(190, True)
    for identifier in [10, 11]:
        reference, size, connection = (
            f"ref{identifier}",
            f"size{identifier}",
            f"data{identifier}",
        )
        steps += [
            send(packet(212, identifier)),
            read(
                match_frame={"is_reply": 1, "id": identifier},
                save_fields={reference: 107, size: 108},
            ),
            connect(connection, "data"),
            send("48545846{" + reference + "}0000000000020000", connection),
            {
                "op": "read",
                "connection": connection,
                "size_from": size,
                "expect_hex": GIF_B.hex(),
                "timeout": 30,
            },
            {"op": "expect_quiet", "connection": connection, "timeout": 3},
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


def lifetime() -> dict:
    steps = start(190, True, "observer") + start(190, False, "waiting")
    # The operator saves name-b during this bounded pause. Before/after reports
    # and positive Prefs snapshots must prove that the change actually occurred.
    steps += [{"op": "pause", "seconds": 20}]
    steps += start(190, True, "fresh") + [close("fresh")]
    steps += complete("waiting")
    for connection in ["waiting", "observer"]:
        steps += [
            send(packet(500, 90), connection),
            read(connection, match_frame={"is_reply": 1, "id": 90}),
        ]
    steps += [close("waiting"), {"op": "pause", "seconds": 3}]
    steps += [
        send(packet(500, 91), "observer"),
        read("observer", match_frame={"is_reply": 1, "id": 91}),
        close("observer"),
    ]
    return {
        "name-change-with-existing-sessions": (
            steps,
            {
                "kind": "login-name-lifetime",
                "pause_seconds": 20,
                "before_hex": NAMES["name-a"].hex(),
                "after_hex": NAMES["name-b"].hex(),
            },
        )
    }
