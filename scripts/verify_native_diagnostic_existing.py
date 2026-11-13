#!/usr/bin/env python3
"""Check bounded A8 303 load reports without imposing exact prose parity."""

import argparse
import json
from pathlib import Path

from native_diagnostic_existing_cases import CASES, NAME
from protocol_capture import verify_capture

STREAM_BYTES = 1_049_073
FORK_BYTES = 1_048_893


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def reply(report: dict, identifier: int, *, success: bool = True) -> dict:
    found = [
        frame
        for frame in report["frames"]
        if frame["is_reply"] == 1 and frame["id"] == identifier
    ]
    require(len(found) == 1, f"Expected one reply {identifier}")
    if success:
        require(found[0]["error"] == 0, f"Reply {identifier} failed")
    return found[0]


def values(frame: dict) -> dict[int, bytes]:
    result = {}
    for field in frame["fields"]:
        require(field["id"] not in result, "Duplicate scalar field")
        result[field["id"]] = bytes.fromhex(field["hex"])
    return result


def current_uid(report: dict) -> bytes:
    fields = reply(report, 10)["fields"]
    require(len(fields) == 1 and fields[0]["id"] == 300, "Ambiguous current roster")
    encoded = bytes.fromhex(fields[0]["hex"])
    require(len(encoded) >= 2, "Short current roster")
    return encoded[:2]


def check_references(report: dict, admitted: list[int], queued: list[int]) -> dict:
    refs = []
    positions = []
    for identifier in admitted + queued:
        item = values(reply(report, identifier))
        require(set(item) >= {107, 108, 207}, f"Missing 202 fields {identifier}")
        require(len(item[107]) == 4, "Reference width differs")
        require(item[108] == STREAM_BYTES.to_bytes(4, "big"), "Stream size differs")
        require(item[207] == FORK_BYTES.to_bytes(4, "big"), "Fork size differs")
        if identifier in admitted:
            require(116 not in item, f"Admitted {identifier} was queued")
        else:
            require(
                116 in item and int.from_bytes(item[116], "big") > 0,
                f"Missing positive queue position {identifier}",
            )
            positions.append(int.from_bytes(item[116], "big"))
        refs.append(item[107].hex())
    require(len(refs) == len(set(refs)), "Duplicate transfer reference")
    return {"references": refs, "waiting_positions": positions}


def check_diagnostic(report: dict, identifier: int, uid: bytes) -> dict:
    item = values(reply(report, identifier))
    require(set(item) == {101, 102}, f"303 fields differ at {identifier}")
    require(item[102] == b"framing-fixture", "303 name differs")
    require(item[101].startswith(b"Nickname:"), "303 text prefix differs")
    requests = [
        bytes.fromhex(event["hex"])
        for event in report["events"]
        if event["event"] == "send"
        and event["connection"] == "a"
        and int.from_bytes(bytes.fromhex(event["hex"])[2:4], "big") == 303
        and int.from_bytes(bytes.fromhex(event["hex"])[4:8], "big") == identifier
    ]
    require(
        len(requests) == 1 and requests[0].endswith(b"\x00g\x00\x02" + uid),
        "303 target differs from current roster",
    )
    return {
        "field101_bytes": len(item[101]),
        "field101_hex": item[101].hex(),
        "field102_hex": item[102].hex(),
    }


def semantic(case: str, report: dict, baseline: dict | None = None) -> dict:
    require(report["status"] == "completed", "Capture incomplete")
    plan = json.loads(report["_plan_path"].read_text())
    require(plan["expectation"]["case"] == case, "Case differs")
    require(plan["expectation"]["fixture_name_hex"] == NAME.hex(), "Fixture differs")
    if case == "postflight":
        if baseline is None:
            raise ValueError("Missing A7 baseline")
        require(
            reply(report, 10)["fields"] == reply(baseline, 10)["fields"],
            "Account baseline changed",
        )
        require(
            reply(report, 11)["fields"] == reply(baseline, 11)["fields"],
            "Files baseline changed",
        )
        require(
            reply(report, 12)["fields"] == reply(baseline, 12)["fields"],
            "Fixture metadata changed",
        )
        roster = reply(report, 13)["fields"]
        require(
            len(roster) == 1 and roster[0]["id"] == 300, "Ambiguous postflight roster"
        )
        uid = bytes.fromhex(roster[0]["hex"])[:2]
        return {"case": case, "diagnostics": {"14": check_diagnostic(report, 14, uid)}}
    uid = current_uid(report)
    if case == "one-active-one-queued":
        references = check_references(report, [11], [12])
        diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [13, 17]}
        denied = values(reply(report, 14, success=False))
        require(
            reply(report, 14, success=False)["error"] == 1 and set(denied) == {100},
            "Missing-target control differs",
        )
        require(
            NAME in bytes.fromhex(diagnostics["13"]["field101_hex"]),
            "No active fixture in 303",
        )
        active_text = bytes.fromhex(diagnostics["13"]["field101_hex"])
        require(b"Waiting Downloads" in active_text, "No waiting section in 303")
        require(
            NAME in active_text.split(b"Waiting Downloads", 1)[1],
            "No queued fixture in 303",
        )
        return {"case": case, **references, "diagnostics": diagnostics}
    require(case == "density", "Unknown case")
    references = check_references(report, list(range(20, 28)), list(range(40, 48)))
    diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [35, 60, 61, 90]}
    for identifier in [35, 60, 61]:
        require(
            NAME in bytes.fromhex(diagnostics[str(identifier)]["field101_hex"]),
            "No active fixture in density 303",
        )
    return {"case": case, **references, "diagnostics": diagnostics}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--a7-baseline", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = verify_capture(args.capture)
    report["_plan_path"] = args.capture / "plan.json"
    baseline = verify_capture(args.a7_baseline) if args.a7_baseline else None
    result = semantic(args.case, report, baseline)
    if args.output.exists():
        raise SystemExit(f"Refusing existing output: {args.output}")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{args.case}: structural diagnostic checks passed")


if __name__ == "__main__":
    main()
