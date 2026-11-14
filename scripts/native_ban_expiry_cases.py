"""Finite control-only plans for kick, protection and temporary-ban expiry."""

import argparse
import hashlib
import json
from pathlib import Path

import native_ban_control_cases as control
from native_auth_cases import authentication, complement
from native_plan import close, eof, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

ZERO_KEY = b"m-expiry-zero"
PROTECTED_KEY = b"m-expiry-protected"
ZERO_PASSWORD = b"expiry-zero-pass"
PROTECTED_PASSWORD = b"expiry-protected-pass"
ZERO_NAME = b"Expiry Zero"
PROTECTED_NAME = b"Expiry Protected"
ZERO_ACCESS = bytes(8)
PROTECTED_ACCESS = bytes.fromhex("0000010000000000")  # privilege bit 23
TEMPORARY_NOTICE = b"You are temporarily banned on this server."
A7_SHA = control.A7_SHA
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
    return [
        send(packet(kind, identifier, payload(fields)), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def target_login(key: bytes, password: bytes, name: bytes) -> list[dict]:
    return [{**step, "connection": "target"} for step in login()[:3]] + [
        authentication(key, password, name=name, connection="target"),
        read("target", match_frame={"is_reply": 1, "id": 1}),
        read("target", match_frame={"type": 354}),
        read("target", match_frame={"type": 109}),
    ]


def account_guard(key: bytes) -> list[dict]:
    return login() + exchange(352, 30, [(105, key)]) + [close()]


def account_seed(key: bytes, password: bytes, name: bytes, access: bytes) -> list[dict]:
    return (
        login()
        + exchange(
            350,
            31,
            [
                (105, complement(key)),
                (106, complement(password)),
                (102, name),
                (110, access),
            ],
        )
        + exchange(352, 32, [(105, key)])
        + [close()]
    )


def kick_case(key: bytes, password: bytes, name: bytes, option: int) -> list[dict]:
    if option not in (0, 1):
        raise ValueError("Only kick 0 or temporary ban 1 is prepared")
    steps = login() + target_login(key, password, name)
    steps += [
        read(match_frame={"type": 301}, save_field={"name": "target_uid", "id": 103})
    ]
    steps += exchange(300, 32, [])
    raw = packet(110, 33, payload([(103, b"\0\0"), (113, option.to_bytes(2, "big"))]))
    marker = "006700020000"
    if raw.count(marker) != 1:
        raise ValueError("110 UID marker is not unique")
    steps.append(send(raw.replace(marker, "00670002{target_uid}")))
    if option == 1:
        steps.append(read("target", match_frame={"type": 104}))
    steps += [
        eof("target"),
        read(match_frame={"is_reply": 1, "id": 33}),
        read(match_frame={"type": 302}),
        close("target"),
        close(),
    ]
    return steps


def protected_case() -> list[dict]:
    steps = login() + target_login(PROTECTED_KEY, PROTECTED_PASSWORD, PROTECTED_NAME)
    steps += [
        read(match_frame={"type": 301}, save_field={"name": "target_uid", "id": 103})
    ]
    steps += exchange(300, 32, [])
    raw = packet(110, 33, payload([(103, b"\0\0"), (113, b"\0\0")]))
    marker = "006700020000"
    if raw.count(marker) != 1:
        raise ValueError("110 UID marker is not unique")
    steps += [
        send(raw.replace(marker, "00670002{target_uid}")),
        read(match_frame={"is_reply": 1, "id": 33}),
    ]
    steps += exchange(500, 80, [], "target")
    steps.append({"op": "expect_quiet", "connection": "target", "timeout": 1})
    steps += [close("target"), close()]
    return steps


def probe(accepted: bool) -> list[dict]:
    steps = login()[:3] + [
        authentication(ZERO_KEY, ZERO_PASSWORD, name=ZERO_NAME),
        read(match_frame={"is_reply": 1, "id": 1}),
    ]
    if accepted:
        steps += [read(match_frame={"type": 354}), read(match_frame={"type": 109})]
        steps += exchange(300, 40, [])
    return steps + [close()]


def plans() -> dict[str, list[dict]]:
    return {
        "readiness": control.plans()["readiness"],
        "guard-zero": account_guard(ZERO_KEY),
        "guard-protected": account_guard(PROTECTED_KEY),
        "seed-zero": account_seed(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, ZERO_ACCESS),
        "seed-protected": account_seed(
            PROTECTED_KEY, PROTECTED_PASSWORD, PROTECTED_NAME, PROTECTED_ACCESS
        ),
        "kick0": kick_case(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, 0),
        "kick0-probe": probe(True),
        "protected": protected_case(),
        "tempban": kick_case(ZERO_KEY, ZERO_PASSWORD, ZERO_NAME, 1),
        "immediate-probe": probe(False),
        "pre-probe": probe(False),
        "post-probe": probe(True),
    }


def plan(name: str, steps: list[dict], environment: dict, port: int) -> dict:
    if port != 15800:
        raise ValueError("B66 frontend must be owned port 15800")
    if environment.get("source_a7_sha256") != A7_SHA:
        raise ValueError("Frozen A7 source-plan identity differs")
    if (
        environment.get("fixture_profile") != "control-only"
        or environment.get("full_file_baseline") != "not_exercised"
    ):
        raise ValueError("Only control-only profile is prepared")
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


def write_plans(output: Path, environment: dict, port: int = 15800) -> dict[str, str]:
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=15800)
    args = parser.parse_args()
    print(
        json.dumps(
            write_plans(args.output, json.loads(args.runtime.read_text()), args.port),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
