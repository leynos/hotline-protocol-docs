#!/usr/bin/env python3
"""Prepare two control-only phases for a stopped-image 304 persistence test."""

import argparse
import hashlib
import json
from pathlib import Path

import native_ban_control_cases as control
from native_auth_cases import authentication
from native_plan import login, packet, payload, read, send
from native_pm_cases import variable_message
from protocol_capture import ORACLE_SHA256, validate_plan

A7_SHA = control.A7_SHA
BASELINE_NAME = b"A41-Baseline"
MARKER_NAME = b"A41-Persist-On"
MARKER_TEXT = b"a41-explicit-auto"


def barrier(identifier: int) -> list[dict]:
    steps = []
    for name in ("main", "subject"):
        steps += [
            send(packet(500, identifier), name),
            read(name, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": name, "timeout": 2},
        ]
    return steps


def message(identifier: int, text: bytes, *, automatic: bool) -> list[dict]:
    steps = [
        variable_message(
            108,
            identifier,
            "peer_uid",
            [(113, b"\0\1"), (101, text)],
        ),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]
    if automatic:
        steps.append(read(match_frame={"type": 104}))
    steps.append(read("subject", match_frame={"type": 104}))
    return steps + barrier(identifier + 100)


def observation(phase: int) -> tuple[list[dict], dict]:
    steps = login() + [
        send(packet(300, 10)),
        read(match_frame={"is_reply": 1, "id": 10}),
    ]
    steps += [{**step, "connection": "subject"} for step in login()[:3]]
    fixed_login = authentication(
        b"admin", b"mothra19", name=BASELINE_NAME, icon=b"\0\3", connection="subject"
    )
    steps += [fixed_login, read("subject"), read("subject"), read("subject")]
    identity = len(steps)
    steps.append(read(match_frame={"type": 301}, save_fields={"peer_uid": 103}))
    baseline = len(steps)
    steps += message(
        60, b"a41-before" if phase == 1 else b"a41-after-restart", automatic=False
    )
    expectation = {
        "case": f"settings-persistence-phase{phase}",
        "identity_action": identity,
        "baseline_pm_action": baseline,
        "fixed_login_hex": fixed_login["hex"],
        "baseline_name_hex": BASELINE_NAME.hex(),
        "marker_name_hex": MARKER_NAME.hex(),
        "marker_text_hex": MARKER_TEXT.hex(),
        "sockets_held_for_app_quit": True,
    }
    if phase == 1:
        stages = [
            (
                "enable",
                MARKER_NAME,
                b"\0\x11",
                b"\0\4",
                MARKER_TEXT,
                b"a41-enabled",
                True,
                61,
            ),
            (
                "disable",
                b"A41-Persist-Off",
                b"\0\x12",
                None,
                None,
                b"a41-disabled",
                False,
                62,
            ),
            (
                "reenable",
                MARKER_NAME,
                b"\0\x11",
                b"\0\4",
                MARKER_TEXT,
                b"a41-final",
                True,
                63,
            ),
        ]
        expectation["stages"] = []
        for label, name, icon, option, auto, text, active, identifier in stages:
            mutation = len(steps)
            values = [(102, name), (104, icon)]
            if option is not None:
                values.append((113, option))
            if auto is not None:
                values.append((215, auto))
            steps += [
                send(
                    packet(304, 30 + len(expectation["stages"]), payload(values)),
                    "subject",
                ),
                read(match_frame={"type": 301}),
                read("subject", match_frame={"type": 301}),
            ]
            pm = len(steps)
            steps += message(identifier, text, automatic=active)
            expectation["stages"].append(
                {
                    "label": label,
                    "mutation_action": mutation,
                    "update_action": mutation + 1,
                    "pm_action": pm,
                    "pm_id": identifier,
                    "pm_text_hex": text.hex(),
                    "name_hex": name.hex(),
                    "icon_hex": icon.hex(),
                    "auto": active,
                }
            )
    expectation["observation_actions"] = len(steps)
    steps += [
        {"op": "read_eof", "connection": name, "timeout": 720}
        for name in ("subject", "main")
    ]
    return steps, expectation


def plans(runtime: dict, port: int) -> dict[str, dict]:
    if runtime.get("source_a7_sha256") != A7_SHA:
        raise ValueError("A7 provenance differs")
    if not 1024 <= port <= 65532 or port in {15500, 15501}:
        raise ValueError("Unsafe control endpoint")
    result = {}
    for phase in (1, 2):
        steps, expectation = observation(phase)
        result[f"phase{phase}"] = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "A42 preparation; separate root START required",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-029"],
            "environment": {
                **runtime,
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            },
            "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
            "steps": steps,
            "expectation": expectation,
        }
    result["readiness"] = {
        **result["phase1"],
        "steps": control.plans()["readiness"],
        "expectation": {"case": "control-readiness"},
    }
    for plan in result.values():
        validate_plan(plan)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = plans(json.loads(args.runtime.read_text()), args.port)
    args.output.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, plan in result.items():
        raw = (json.dumps(plan, indent=2) + "\n").encode()
        (args.output / f"{name}.json").write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    (args.output / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
    sources = {
        name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
        for name in (
            "native_settings_persistence_cases.py",
            "native_settings_persistence.py",
            "native_control_readiness.py",
            "native_ban_control_cases.py",
        )
    }
    (args.output / "source-code-sha256.json").write_text(
        json.dumps(sources, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
