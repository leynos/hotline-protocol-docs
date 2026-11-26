#!/usr/bin/env python3
"""Check bounded A8 303 load reports without imposing exact prose parity."""

import argparse
import json
import re
from pathlib import Path

from native_diagnostic_existing_cases import CASES, NAME
from protocol_capture import decode_frame, verify_capture

STREAM_BYTES = 1_049_073
FORK_BYTES = 1_048_893
HEADINGS = (
    b"-------- File Downloads ---------",
    b"------- Folder Downloads --------",
    b"--------- File Uploads ----------",
    b"-------- Folder Uploads ---------",
    b"------- Waiting Downloads -------",
)


def require(condition: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not condition:
        raise ValueError(message)


def reply(report: dict, identifier: int, *, success: bool = True) -> dict:
    """Return the one reply frame with the given identifier, optionally requiring success."""
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
    """Return a frame's fields as a map from identifier to bytes, refusing duplicates."""
    result = {}
    for field in frame["fields"]:
        require(field["id"] not in result, "Duplicate scalar field")
        result[field["id"]] = bytes.fromhex(field["hex"])
    return result


def current_uid(report: dict) -> bytes:
    """Return the two-byte user identifier from the current roster reply."""
    fields = reply(report, 10)["fields"]
    require(len(fields) == 1 and fields[0]["id"] == 300, "Ambiguous current roster")
    encoded = bytes.fromhex(fields[0]["hex"])
    require(len(encoded) >= 2, "Short current roster")
    return encoded[:2]


def check_references(report: dict, admitted: list[int], queued: list[int]) -> dict:
    """Check the download replies: reference and size fields, and queue positions for the queued ones."""
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
    """Check one diagnostic reply and the request that produced it."""
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


def section_witness(text: bytes, active: int, waiting: int) -> dict:
    """Count complete native rows; never equate an incomplete section with proof."""
    result = {
        "expected_active": active,
        "expected_waiting": waiting,
        "field101_bytes": len(text),
        "status": "incomplete",
    }
    sections = {}
    terminated = {}
    rest = text
    for index, heading in enumerate(HEADINGS):
        marker = b"\r\r" + heading + b"\r\r"
        if marker not in rest:
            return {**result, "reason": f"Missing complete section {index}"}
        _, _, rest = rest.partition(marker)
        if index + 1 < len(HEADINGS):
            next_marker = b"\r\r" + HEADINGS[index + 1] + b"\r\r"
            if next_marker not in rest:
                return {**result, "reason": f"Section {index} has no terminator"}
            body, _, rest = rest.partition(next_marker)
            # Keep the next heading for the following iteration.
            rest = next_marker + rest
        else:
            body = rest
        terminated[index] = body.endswith(b"\r")
        lines = body.rstrip(b"\r").split(b"\r")
        sections[index] = lines
    if any(sections[index] != [b"None."] for index in (1, 2, 3)):
        return {**result, "reason": "Unrelated transfer section is nonempty"}
    counts = {}
    for index, label in ((0, "active"), (4, "waiting")):
        lines = sections[index]
        if lines == [b"None."]:
            counts[label] = 0
        elif (index < 4 or terminated[index]) and all(
            re.fullmatch(
                re.escape(NAME)
                + (rb" +[0-9]{1,3}% +\S.*" if index == 0 else rb" +\(File\)"),
                line,
            )
            for line in lines
        ):
            counts[label] = len(lines)
        else:
            return {
                **result,
                "reason": f"Incomplete or foreign {label} row",
                "observed_counts": counts,
            }
    result["observed_counts"] = counts
    if counts == {"active": active, "waiting": waiting}:
        result["status"] = "complete"
    else:
        result["reason"] = "Row counts differ from the planned density point"
    return result


def check_cancellations(report: dict, targets: dict[int, bytes]) -> None:
    """Check that each cancellation was sent once and targeted the expected transfer reference."""
    for identifier, expected_ref in targets.items():
        reply(report, identifier)
        sent = [
            bytes.fromhex(event["hex"])
            for event in report["events"]
            if event["event"] == "send"
            and event["connection"] == "a"
            and int.from_bytes(bytes.fromhex(event["hex"])[2:4], "big") == 214
            and int.from_bytes(bytes.fromhex(event["hex"])[4:8], "big") == identifier
        ]
        require(len(sent) == 1, f"Missing unique 214 send {identifier}")
        request = decode_frame(sent[0])
        require(
            values(request) == {107: expected_ref},
            f"Cancellation {identifier} targeted another reference",
        )


def semantic(case: str, report: dict, baseline: dict | None = None) -> dict:
    """Check a diagnostic capture's plan and replies and return the semantic result."""
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
        diagnostic = check_diagnostic(report, 14, uid)
        witness = section_witness(bytes.fromhex(diagnostic["field101_hex"]), 0, 0)
        return {
            "case": case,
            "status": "verified"
            if witness["status"] == "complete"
            else "incomplete-witness",
            "diagnostics": {"14": diagnostic},
            "witnesses": {"14": witness},
        }
    uid = current_uid(report)
    if case == "one-active-one-queued":
        references = check_references(report, [11], [12])
        diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [13, 17]}
        denied = values(reply(report, 14, success=False))
        require(
            reply(report, 14, success=False)["error"] == 1 and set(denied) == {100},
            "Missing-target control differs",
        )
        saved = [bytes.fromhex(value) for value in references["references"]]
        check_cancellations(report, {15: saved[1], 16: saved[0]})
        witnesses = {
            "13": section_witness(
                bytes.fromhex(diagnostics["13"]["field101_hex"]), 1, 1
            ),
            "17": section_witness(
                bytes.fromhex(diagnostics["17"]["field101_hex"]), 0, 0
            ),
        }
        complete = all(value["status"] == "complete" for value in witnesses.values())
        return {
            "case": case,
            "status": "verified" if complete else "incomplete-witness",
            **references,
            "diagnostics": diagnostics,
            "witnesses": witnesses,
        }
    require(case == "density", "Unknown case")
    references = check_references(report, list(range(20, 28)), list(range(40, 48)))
    diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [35, 60, 61, 90]}
    saved = [bytes.fromhex(value) for value in references["references"]]
    check_cancellations(
        report,
        {
            **{70 + index: saved[8 + index] for index in range(8)},
            **{80 + index: saved[index] for index in range(8)},
        },
    )
    points = {35: (4, 0), 60: (8, 4), 61: (8, 8), 90: (0, 0)}
    witnesses = {
        str(identifier): section_witness(
            bytes.fromhex(diagnostics[str(identifier)]["field101_hex"]), *counts
        )
        for identifier, counts in points.items()
    }
    complete = all(value["status"] == "complete" for value in witnesses.values())
    return {
        "case": case,
        "status": "verified" if complete else "incomplete-witness",
        **references,
        "diagnostics": diagnostics,
        "witnesses": witnesses,
    }


def main() -> None:
    """Verify a capture and write its semantic result to the output file."""
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
    print(f"{args.case}: {result['status']}")
    if result["status"] != "verified":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
