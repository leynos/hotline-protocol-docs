#!/usr/bin/env python3
"""Verify bounded native framing observations without generalizing duplicates."""

import argparse
import hashlib
import json
from pathlib import Path

from native_framing_cases import framing
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from verify_native_core import require


def check_quiet(report: dict, plan: dict) -> None:
    """Require measured silence before later input, not just an action label."""
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(step["timeout"] >= 3, "Quiet observation too short")
        quiet = [
            e
            for e in report["events"]
            if e["action"] == action and e["event"] == "quiet"
        ]
        require(len(quiet) == 1, "Missing quiet event")
        previous = [e for e in report["events"] if e["action"] < action]
        require(
            quiet[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
            >= step["timeout"] * 1e9,
            "Quiet observation was shorter than its plan",
        )


def check_outcome(report: dict, expected: dict, packets: dict) -> dict:
    """Check handler-visible outcomes after the three-frame login bootstrap."""
    frames = report["frames"]
    require(len(frames) >= 3, "Missing login bootstrap")
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in frames[:3]]
        == [(0, 1, 0), (354, 0, 0), (109, 0, 0)],
        "Login bootstrap changed",
    )
    remaining = frames[3:]
    kind = expected["kind"]
    observed = {}
    if kind in {"ack", "ack-sequence"}:
        ids = expected["ids"] if kind == "ack-sequence" else [expected["id"]]
        require(len(remaining) == len(ids), "ACK count changed")
        for frame, identifier in zip(remaining, ids, strict=True):
            require(
                (
                    frame["type"],
                    frame["is_reply"],
                    frame["id"],
                    frame["error"],
                    frame["payload_hex"],
                )
                == (0, 1, identifier, 0, "0000"),
                "ACK bytes changed",
            )
    elif kind == "close":
        require(not remaining, "Unexpected numbered reply before close")
        require(
            any(e["event"] == "eof" for e in report["events"]),
            "Missing socket EOF",
        )
        require(packets["guest_server_initiated_close"], "Guest did not initiate close")
    elif kind in {"settings", "duplicate-settings"}:
        require(len(remaining) == 1, "Settings notification count changed")
        frame = remaining[0]
        require(
            (frame["type"], frame["is_reply"], frame["error"]) == (301, 0, 0),
            "Settings notification envelope changed",
        )
        fields = {f["id"]: f["hex"] for f in frame["fields"]}
        require(fields[102] == expected["name_hex"], "Effective name differs")
        icon = int.from_bytes(bytes.fromhex(fields[104]), "big")
        if kind == "duplicate-settings":
            require(icon in expected["allowed_icons"], "Unexpected duplicate selection")
        else:
            require(icon == expected["icon"], "Effective icon differs")
        require(
            len(bytes.fromhex(fields[104])) == (4 if icon > 65535 else 2),
            "Icon wire width differs",
        )
        observed = {"effective_name_hex": fields[102], "emitted_icon_hex": fields[104]}
    else:
        raise ValueError("Unknown semantic expectation")
    return observed


def verify(directory: Path) -> dict:
    """Check the complete declared matrix against both packet capture views."""
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected_cases = framing()
    names = {p.name for p in (directory / "transcripts").iterdir() if p.is_dir()}
    require(names == set(expected_cases), "Framing corpus inventory differs")
    sources = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    observations = []
    for name, (steps, expected) in sorted(expected_cases.items()):
        case = directory / "transcripts" / name
        plan = json.loads((case / "plan.json").read_text())
        report = verify_capture(case)
        require(report["status"] == "completed", name + ": capture failed")
        require(report["driver_sha256"] in sources, "Missing capture-driver source")
        require(
            plan["steps"] == steps and plan["expectation"] == expected, "Plan differs"
        )
        packets = reconcile(report, host, guest)["main"]
        check_quiet(report, plan)
        outcome = check_outcome(report, expected, packets)
        observations.append({"case": name, **packets, **outcome})
    initial = verify_capture(directory / "initial-hypotheses/tlv-icon-ffffffff")
    require(initial["status"] == "completed", "Initial icon capture status differs")
    require(
        next(f for f in initial["frames"][-1]["fields"] if f["id"] == 104)["hex"]
        == "ffffffff",
        "Initial disproven icon hypothesis changed",
    )
    reconcile(initial, host, guest)
    return {
        "cases": observations,
        "initial_hypotheses": 1,
        "scope": "62 native cases; duplicate choices are observations, not a universal last-wins rule; silence is bounded to plan windows",
    }


def main() -> None:
    """Verify the corpus named on the command line and print the summary as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
