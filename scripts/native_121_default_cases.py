#!/usr/bin/env python3
"""Prepare two client-only delayed-121 default-auto observations."""

import argparse
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import close, login, packet, payload, read, send
from native_pm_cases import BASELINE_SHA256, load_baseline, variable_message
from protocol_capture import ORACLE_SHA256, validate_plan

DEFAULT = b"I'm not able to respond right now. Please try later!"


def roster(identifier: int) -> list[dict]:
    return [
        send(packet(300, identifier)),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def barrier(identifier: int, subject: str) -> list[dict]:
    result = []
    for connection in ("main", subject):
        result += [
            send(packet(500, identifier, payload([])), connection),
            read(connection, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": connection, "timeout": 2},
        ]
    return result


def delayed_case(label: str, index: int) -> tuple[list[dict], dict]:
    subject = f"subject_{label}"
    name = f"A35-{label}-215".encode()
    icon = (7 + index).to_bytes(2, "big")
    login_id = 2 + index
    agreement_id = 20 + index * 20
    pm_id = 30 + index * 20
    text = f"a35-{label}-pm".encode()
    steps = [{**step, "connection": subject} for step in login()[:3]]
    steps += [
        authentication(
            b"admin",
            b"mothra19",
            name=None,
            icon=None,
            connection=subject,
            identifier=login_id,
        ),
        read(subject, match_frame={"is_reply": 1, "id": login_id}),
        read(subject, match_frame={"type": 109}),
    ]
    steps += roster(11 + index)
    values = [(102, name), (104, icon), (113, b"\0\4")]
    if label == "empty":
        values.append((215, b""))
    steps += [send(packet(121, agreement_id, payload(values)), subject)]
    steps += [read(subject, match_frame={"is_reply": 1, "id": agreement_id})]
    steps += [read(match_frame={"type": 301}, save_fields={"peer_uid": 103})]
    steps += [read(subject, match_frame={"type": 354})]
    # 122 depends on saved client version and banner configuration; the 500
    # barrier records it if present without making it a prerequisite.
    steps += [send(packet(500, agreement_id + 1), subject)]
    steps += [read(subject, match_frame={"is_reply": 1, "id": agreement_id + 1})]
    steps += roster(agreement_id + 2)
    steps += [variable_message(108, pm_id, "peer_uid", [(113, b"\0\1"), (101, text)])]
    steps += [
        read(match_frame={"is_reply": 1, "id": pm_id}),
        read(match_frame={"type": 104}),
        read(subject, match_frame={"type": 104}),
    ]
    steps += barrier(pm_id + 1, subject)
    steps += [close(subject), read(match_frame={"type": 302})]
    steps += roster(pm_id + 2)
    return steps, {
        "label": label,
        "subject_connection": subject,
        "name_hex": name.hex(),
        "icon_hex": icon.hex(),
        "login_id": login_id,
        "agreement_id": agreement_id,
        "pm_id": pm_id,
        "pm_text_hex": text.hex(),
        "default_text_hex": DEFAULT.hex(),
    }


def observe() -> tuple[list[dict], list[dict]]:
    steps = login() + roster(10)
    expected = []
    for index, label in enumerate(("absent", "empty")):
        case_steps, detail = delayed_case(label, index)
        steps += case_steps
        expected.append(detail)
    return steps + [close()], expected


def plans(runtime: dict, baseline_raw: bytes) -> dict[str, dict]:
    baseline = load_baseline(baseline_raw)
    for key in ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap"):
        if runtime.get(key) != baseline["environment"].get(key):
            raise ValueError("Runtime identity differs from pinned A7 baseline")
    steps, cases = observe()
    observed = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "A35 offline 121 preparation; separate live START required",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-029", "GAP-030"],
        "environment": runtime,
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": steps,
        "expectation": {
            "case": "delayed-121-default-215",
            "cases": cases,
            "baseline_plan_sha256": BASELINE_SHA256,
            "pm_request_count": len(cases),
        },
    }
    validate_plan(observed)
    return {"preflight": baseline, "observe": observed, "postflight": baseline}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--baseline-plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing existing output")
    raw = args.baseline_plan.read_bytes()
    prepared = plans(json.loads(args.runtime_record.read_text()), raw)
    args.output.mkdir(parents=True)
    for label, plan in prepared.items():
        (args.output / f"{label}.json").write_bytes(
            raw if label != "observe" else (json.dumps(plan, indent=2) + "\n").encode()
        )


if __name__ == "__main__":
    main()
