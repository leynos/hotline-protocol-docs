#!/usr/bin/env python3
"""Verify native field-110 walking bits, width controls and account cleanup."""

import argparse
import json
from pathlib import Path

import native_bitmap_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import reply, selected
from verify_native_core import require
from verify_native_shx import fields, sha

NAMES = tuple(cases.suites())
EXE_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"


def sent(report: dict, kind: int, identifier: int, connection: str = "main") -> dict:
    frames = []
    for event in report["events"]:
        if event["event"] != "send" or event["connection"] != connection:
            continue
        raw = bytes.fromhex(event["hex"])
        if len(raw) < 20:
            continue
        frame = decode_frame(raw)
        if frame["type"] == kind and frame["id"] == identifier:
            frames.append(frame)
    require(len(frames) == 1, "Missing/duplicate bitmap request")
    return frames[0]


def account(frame: dict, access: bytes) -> None:
    require(
        frame["type"] == 0
        and frame["is_reply"] == 1
        and frame["error"] == 0
        and fields(frame)
        == {
            102: cases.NAME,
            105: complement(cases.KEY),
            106: b"x",
            110: access,
        },
        "Owned account identity/bitmap/password readback differs",
    )


def replacement(
    report: dict, update_id: int, read_id: int, submitted: bytes | None, observed: bytes
) -> None:
    request = fields(sent(report, 353, update_id))
    expected = {
        105: complement(cases.KEY),
        102: cases.NAME,
        106: b"\0",
        111: cases.ATTRIBUTE,
    }
    if submitted is not None:
        expected[110] = submitted
    require(request == expected, "Wrong submitted bitmap/owned replacement fields")
    require(reply(report, update_id)["error"] == 0, "Bitmap replacement failed")
    require(
        fields(sent(report, 352, read_id)) == {105: cases.KEY},
        "Account readback requested another identity",
    )
    account(reply(report, read_id), observed)


def ordered_replies(report: dict, identifiers: list[int]) -> None:
    actual = [
        frame["id"]
        for frame in report["frames"]
        if frame["connection"] == "main"
        and frame["type"] == 0
        and frame["is_reply"]
        and frame["id"] in identifiers
    ]
    require(actual == identifiers, "Bitmap replacement/readback order differs")


def semantic(reports: dict[str, dict]) -> dict:
    """Check every measured bit, input width, identity and observed ordering."""
    require(set(reports) == set(NAMES), "Bitmap case inventory differs")
    preflight, seed, widths, all_ones, cleanup = (
        reports[name] for name in ("preflight", "seed", "widths", "all-ones", "cleanup")
    )
    baseline = enumeration(reply(preflight, 10))
    require(len(baseline) == 2, "Preflight account inventory differs")
    missing = reply(preflight, 11)
    require(
        missing["error"] == 1
        and list(fields(missing)) == [100]
        and fields(sent(preflight, 352, 11)) == {105: cases.KEY},
        "Owned account was not proven absent",
    )
    require(
        fields(sent(seed, 350, 10))
        == {
            105: complement(cases.KEY),
            106: complement(cases.PASSWORD),
            102: cases.NAME,
            110: cases.ZERO,
            111: cases.ATTRIBUTE,
        }
        and reply(seed, 10)["error"] == 0,
        "Owned account seed differs",
    )
    account(reply(seed, 11), cases.ZERO)
    rows = []
    for group in range(8):
        report = reports[f"walk-{group:02d}"]
        ids = [
            identifier
            for offset in range(8)
            for identifier in (20 + 2 * offset, 21 + 2 * offset)
        ]
        ordered_replies(report, ids)
        for offset in range(8):
            bit = group * 8 + offset
            value = cases.walking_bit(bit)
            replacement(report, 20 + 2 * offset, 21 + 2 * offset, value, value)
            rows.append(
                {
                    "bit": bit,
                    "case": f"walk-{group:02d}",
                    "update_id": 20 + 2 * offset,
                    "read_id": 21 + 2 * offset,
                    "submitted_hex": value.hex(),
                    "readback_hex": fields(reply(report, 21 + 2 * offset))[110].hex(),
                }
            )
    ordered_replies(
        widths,
        [
            identifier
            for offset in range(6)
            for identifier in (40 + 2 * offset, 41 + 2 * offset)
        ],
    )
    width_outcomes = {}
    for offset, (name, value) in enumerate(cases.WIDTHS.items()):
        observed = ((value or b"") + bytes(8))[:8]
        replacement(widths, 40 + 2 * offset, 41 + 2 * offset, value, observed)
        width_outcomes[name] = observed.hex()
    replacement(all_ones, 10, 11, b"\xff" * 8, b"\xff" * 8)
    owned_login = fields(sent(all_ones, 107, 1, "owned"))
    require(
        owned_login.get(105) == complement(cases.KEY)
        and owned_login.get(106) == complement(cases.PASSWORD),
        "All-ones subject used other credentials",
    )
    access = [
        f for f in selected(all_ones, "owned") if f["type"] == 354 and not f["is_reply"]
    ]
    require(
        len(access) == 1 and fields(access[0]) == {110: b"\xff" * 8},
        "All-ones effective session bitmap differs",
    )
    require(
        reply(cleanup, 10)["error"] == 0
        and fields(sent(cleanup, 351, 10)) == {105: complement(cases.KEY)}
        and reply(cleanup, 11)["error"] == 1
        and fields(reply(cleanup, 11)) == fields(missing)
        and enumeration(reply(cleanup, 12)) == baseline,
        "Owned account cleanup/baseline differs",
    )
    return {
        "walking_bits_verified": 64,
        "walking_rows": rows,
        "width_readbacks_hex": width_outcomes,
        "baseline_accounts": len(baseline),
    }


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["reports"] == list(NAMES)
        and {p.parent.name for p in directory.glob("*/report.json")} == set(NAMES),
        "Bitmap evidence inventory differs",
    )
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == 1259319
        and runtime["running_executable_sha256"] == EXE_SHA256,
        "Bitmap runtime identity differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == 582
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Bitmap host capture count/drop differs",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    require(set(tails) == {"all-ones"}, "Bitmap unread tail inventory differs")
    reports = {}
    paired = 0
    for name in NAMES:
        path = directory / name
        report = verify_capture(path)
        plan = json.loads((path / "plan.json").read_text())
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] == manifest["driver_sha256"]
            and plan["environment"] == runtime,
            "Bitmap plan/oracle provenance differs",
        )
        view_tails = tails.get(name, {})
        observations = reconcile(
            report,
            host,
            guest,
            unread_output={
                k: bytes.fromhex(v) for k, v in view_tails.get("host", {}).items()
            },
            guest_unread_output={
                k: bytes.fromhex(v) for k, v in view_tails.get("guest", {}).items()
            },
        )
        paired += len(observations)
        reports[name] = report
    for connection, expected_type in (("main", 301), ("owned", 302)):
        host_tail = tails["all-ones"]["host"][connection]
        guest_tail = tails["all-ones"]["guest"][connection]
        require(
            host_tail == guest_tail
            and decode_frame(bytes.fromhex(host_tail))["type"] == expected_type,
            "Bitmap unread host/guest tail differs",
        )
    require(paired == 14, "Bitmap paired TCP lifetime count differs")
    require(
        sha(directory / "sources/native_bitmap_cases.py")
        == manifest["generator_sha256"],
        "Bitmap plan generator source differs",
    )
    result = semantic(reports)
    require(
        json.loads((directory / "per-bit.json").read_text()) == result["walking_rows"],
        "Published per-bit evidence differs",
    )
    result.pop("walking_rows")
    return {
        "completed_reports": len(reports),
        "paired_connections": paired,
        **result,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
