#!/usr/bin/env python3
"""Verify native banner type selection, TEXT loading and absent-buffer recovery."""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from native_banner_cases import GIF_B, URL
from native_banner_formats import FORMATS, content
from native_banner_oracle import verify as verify_oracle
from native_packet_evidence import reconcile
from native_plan import packet
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_banners import fields
from verify_native_core import require
from verify_native_queues import frame_time


def requests(report: dict, connection: str) -> list[dict]:
    data = bytes.fromhex(report["streams"][connection]["sent_hex"])
    require(
        data[:12] == bytes.fromhex("54525450484f544c00010002"),
        "Wrong format control handshake",
    )
    data = data[12:]
    result = []
    while data:
        require(len(data) >= 20, "Truncated format request")
        size = 20 + int.from_bytes(data[16:20], "big")
        require(len(data) >= size, "Truncated format payload")
        result.append(decode_frame(data[:size]))
        data = data[size:]
    return result


def banners(report: dict, connection: str) -> list[dict]:
    return [
        f
        for f in report["frames"]
        if f["connection"] == connection and f["type"] == 122 and not f["is_reply"]
    ]


def banner_ack(report: dict) -> tuple[bytes, int]:
    acks = [
        f
        for f in report["frames"]
        if f["connection"] == "main" and f["is_reply"] and f["id"] == 10
    ]
    require(len(acks) == 1 and acks[0]["error"] == 0, "Missing banner212 ACK")
    values = fields(acks[0])
    require(set(values) == {107, 108}, "Banner212 field inventory differs")
    ref = values[107]
    require(
        len(ref) == 4 and int.from_bytes(ref, "big") & 1 == 1,
        "Banner reference differs",
    )
    return ref, int.from_bytes(values[108], "big")


def check_format(name: str, report: dict) -> dict:
    require(report["status"] == "completed", name + ": incomplete format capture")
    input_frames = requests(report, "main")
    require(
        input_frames[0]["type"] == 107
        and fields(input_frames[0])[160] == b"\0\xbe"
        and 102 not in fields(input_frames[0])
        and any(f["type"] == 121 for f in input_frames),
        name + ": delayed input differs",
    )
    filename, finder, tag, _ = FORMATS[name]
    notes = banners(report, "main")
    require(len(notes) == int(tag is not None), name + ": metadata eligibility differs")
    if tag is not None:
        require(
            fields(notes[0]) == {152: tag, 153: URL},
            name + ": advertised type/link differs",
        )
    reference, size = banner_ack(report)
    expected = content(name)
    if finder == b"TEXT":
        expected = expected.replace(b"\r\n", b"\r")
    require(size == len(expected), name + ": advertised byte count differs")
    value = report["streams"]["banner"]
    require(
        value["sent_hex"] == "48545846" + reference.hex() + "0000000000020000",
        name + ": HTXF differs",
    )
    require(
        bytes.fromhex(value["received_hex"]) == expected, name + ": payload differs"
    )
    require(
        any(
            e["event"] == ("quiet" if expected else "eof")
            and e["connection"] == "banner"
            for e in report["events"]
        ),
        name + ": missing banner end/window observation",
    )
    return {
        "format": name,
        "filename_hex": filename.hex(),
        "finder_hex": finder.hex(),
        "tag_hex": tag.hex() if tag is not None else None,
        "native_file_bytes": len(content(name)),
        "advertised_bytes": size,
        "received_bytes": len(expected),
    }


def check_recovery(report: dict, plan: dict) -> dict:
    require(report["status"] == "completed", "Incomplete recovery observation")
    reference, size = banner_ack(report)
    require(size == len(GIF_B), "Recovery advertisement differs")
    require(not banners(report, "absent"), "Missing phase still advertises banner")
    restored = banners(report, "restored")
    require(
        len(restored) == 1 and fields(restored[0]) == {152: b"GIFf", 153: URL},
        "Restored phase lacks GIF metadata",
    )
    early = 102 in fields(requests(report, "main")[0])
    initial = banners(report, "main")
    require(
        len(initial) == (0 if early else 1), "Initial delayed banner metadata differs"
    )
    if initial:
        require(
            fields(initial[0]) == {152: b"GIFf", 153: URL},
            "Initial recovery metadata differs",
        )
        ack_frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "main" and f["is_reply"] and f["id"] == 10
        )
        require(
            initial[0]["action"] < ack_frame["action"],
            "Initial banner was not advertised before212",
        )
    if "initial_completion" in plan["expectation"]:
        require(
            plan["expectation"]["initial_completion"]
            == ("early" if early else "delayed"),
            "Recovery input mode differs",
        )
    for connection, identifier in [("absent", 91), ("restored", 92)]:
        require(
            any(
                f["connection"] == connection
                and f["is_reply"]
                and f["id"] == identifier
                and f["error"] == 0
                for f in report["frames"]
            ),
            "Missing protocol phase delimiter",
        )
    for identifier in [*range(20, 26), *range(30, 36), 80, 90]:
        require(
            any(
                f["connection"] == "main"
                and f["is_reply"]
                and f["id"] == identifier
                and f["error"] == 0
                for f in report["frames"]
            ),
            "Missing owner activity ACK",
        )
    stream = report["streams"]["banner"]
    require(
        stream["sent_hex"] == "48545846" + reference.hex() + "0000000000020000",
        "Recovery reference changed",
    )
    require(bytes.fromhex(stream["received_hex"]) == GIF_B, "Restored payload differs")
    quiets = [
        e
        for e in report["events"]
        if e["connection"] == "banner" and e["event"] == "quiet"
    ]
    receives = [
        e
        for e in report["events"]
        if e["connection"] == "banner" and e["event"] == "receive"
    ]
    require(
        len(quiets) == 2
        and quiets[0]["elapsed_ns"]
        < receives[0]["elapsed_ns"]
        < quiets[1]["elapsed_ns"],
        "Recovery silence/data ordering differs",
    )
    pauses = [
        e
        for e in report["events"]
        if e["event"] == "pause" and plan["steps"][e["action"]]["seconds"] == 30
    ]
    require(len(pauses) == 12, "Recovery pause inventory differs")
    for event in pauses:
        prior = max(
            e["elapsed_ns"]
            for e in report["events"]
            if e["action"] == event["action"] - 1
        )
        require(event["elapsed_ns"] - prior >= 30e9, "Shortened recovery phase pause")
    return {
        "advertised_bytes": size,
        "initial_completion": "early" if early else "delayed",
        "received_bytes": len(GIF_B),
        "planned_pause_seconds": 360,
        "first_quiet_elapsed_seconds": quiets[0]["elapsed_ns"] / 1e9,
        "first_receive_elapsed_seconds": receives[0]["elapsed_ns"] / 1e9,
    }


def verify_native_files(directory: Path) -> list[dict]:
    records = []
    for source in ["native-format-files", "native-text-file", "native-empty-file"]:
        snapshot = json.loads((directory / source / "extraction.json").read_text())
        records.extend((directory / source, record) for record in snapshot["records"])
    observed = []
    for name, (filename, finder, _, _) in FORMATS.items():
        matches = [
            (source, record)
            for source, record in records
            if record["path"] == "/Hotline19/" + filename.decode()
        ]
        require(len(matches) == 1, name + ": native path not uniquely observed")
        source, record = matches[0]
        prefix = source / record["key"]
        data = record["attributes"]["data"]
        require(
            data["exit_code"] == 0 and data["bytes"] == len(content(name)),
            name + ": native extraction differs",
        )
        require(
            prefix.with_suffix(".data").read_bytes() == content(name),
            name + ": native data fork differs",
        )
        stat = prefix.with_suffix(".stat.txt").read_text()
        require(
            ("File type:\t" + (finder.hex() if finder != bytes(4) else "0000")) in stat
            and "MOTH" in stat,
            name + ": native Finder type differs",
        )
        observed.append(
            {
                "format": name,
                "path": record["path"],
                "catalog": record["catalog"],
                "data_bytes": data["bytes"],
            }
        )
    return observed


def check_post_reset_write(
    report: dict, host: list[dict], guest: list[dict], difference: dict
) -> None:
    require(
        difference["case"] == "empty-followup-ack"
        and difference["connection"] == "main",
        "Unexpected post-reset boundary case",
    )
    require(
        report["streams"]["main"]["sent_hex"] == difference["host_sent_hex"],
        "Post-reset host write differs",
    )
    require(
        difference["host_sent_hex"] == difference["guest_sent_hex"] + packet(500, 90)
        and difference["unconsumed_suffix_hex"] == packet(500, 90),
        "Post-reset unconsumed suffix differs",
    )
    started = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        client, endpoint = tuple(event["local_address"]), tuple(event["peer_address"])
        when = int(started + event["elapsed_ns"] / 1000)
        name = event["connection"]
        recorded = report["streams"][name]
        for label, packets, source, target in [
            ("host", host, client, endpoint),
            (
                "guest",
                guest,
                ("10.0.2.2", client[1]),
                ("10.0.2.15", 5500 + endpoint[1] - 15500),
            ),
        ]:
            selected = lifetime(packets, source, target, when)
            expected = (
                difference["guest_sent_hex"]
                if label == "guest" and name == "main"
                else recorded["sent_hex"]
            )
            require(
                stream(selected, source, target).hex() == expected,
                "Post-reset boundary input differs",
            )
            require(
                stream(selected, target, source).hex() == recorded["received_hex"],
                "Post-reset boundary output differs",
            )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    reports = {}
    packets = {}
    expected = {"format-" + n for n in FORMATS} | {
        "phase-checked-recovery",
        "phase-checked-early-recovery",
        "before-delayed-recovery",
        "seed-formats",
        "seed-text",
        "seed-empty",
        "post-reset-session",
        "cleanup-no-banner",
        "missing-confirmation",
    }
    require(
        set(manifest["cases"]) == expected and len(manifest["cases"]) == len(expected),
        "Format/recovery corpus inventory differs",
    )
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == expected,
        "Unexpected final format transcript",
    )
    driver_hash = hashlib.sha256(
        (directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    for name in manifest["cases"]:
        report = verify_capture(directory / "transcripts" / name)
        require(
            report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] == driver_hash,
            "Wrong native format oracle/capture source",
        )
        reports[name] = report
        packets[name] = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest.get("unread_output", {}).get(name, {}).items()
            },
        )
    native_files = verify_native_files(directory)
    oracle = verify_oracle(directory)
    observations = [check_format(name, reports["format-" + name]) for name in FORMATS]
    require(
        packets["format-empty"]["banner"]["guest_server_initiated_close"],
        "Empty banner native close not observed",
    )
    recovery = check_recovery(
        reports["phase-checked-recovery"],
        json.loads(
            (directory / "transcripts/phase-checked-recovery/plan.json").read_text()
        ),
    )
    early_recovery = check_recovery(
        reports["phase-checked-early-recovery"],
        json.loads(
            (
                directory / "transcripts/phase-checked-early-recovery/plan.json"
            ).read_text()
        ),
    )
    baseline = reports["before-delayed-recovery"]
    require(
        baseline["status"] == "completed"
        and banner_ack(baseline)[1] == len(GIF_B)
        and len(banners(baseline, "main")) == 1
        and fields(banners(baseline, "main")[0])[152] == b"GIFf",
        "Delayed-recovery baseline differs",
    )
    for name, summary in [
        ("phase-checked-recovery", recovery),
        ("phase-checked-early-recovery", early_recovery),
    ]:
        report = reports[name]
        connect = next(
            e
            for e in report["events"]
            if e["connection"] == "banner" and e["event"] == "connect"
        )
        started = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
        client = ("10.0.2.2", connect["local_address"][1])
        server = ("10.0.2.15", 5501)
        selected = lifetime(
            guest, client, server, int(started + connect["elapsed_ns"] / 1000)
        )
        native_data = [
            p
            for p in direction(selected, server, client)
            if p["payload_hex"] and not p["flags"] & 4
        ]
        require(bool(native_data), "Missing native restored-banner bytes")
        ack = next(
            f
            for f in report["frames"]
            if f["connection"] == "main" and f["is_reply"] and f["id"] == 10
        )
        first = min(p["timestamp_us"] for p in native_data)
        require(
            started + summary["first_quiet_elapsed_seconds"] * 1e6
            < first
            <= started + summary["first_receive_elapsed_seconds"] * 1e6,
            "Native restore/read ordering differs",
        )
        summary["first_native_data_after_ack_seconds"] = (
            first - frame_time(report, ack, guest)
        ) / 1e6
    require(
        reports["missing-confirmation"]["status"] == "completed"
        and not banners(reports["missing-confirmation"], "main"),
        "Initial absence control differs",
    )
    for connection in ["main", "observer"]:
        require(
            packets["format-empty"][connection]["guest_server_initiated_close"],
            "Empty banner observer/control reset not observed",
        )
        require(
            any(
                e["event"] == "eof" and e["connection"] == connection
                for e in reports["format-empty"]["events"]
            ),
            "Missing empty-trigger control EOF",
        )
    post = reports["post-reset-session"]
    require(
        post["status"] == "completed"
        and any(
            f["is_reply"] and f["id"] == 90 and f["error"] == 0 for f in post["frames"]
        ),
        "Post-reset login/liveness failed",
    )
    require(
        reports["cleanup-no-banner"]["status"] == "completed"
        and not banners(reports["cleanup-no-banner"], "main"),
        "Final no-banner configuration differs",
    )
    differences = json.loads((directory / "boundary-differences.json").read_text())
    require(len(differences) == 1, "Post-reset boundary inventory differs")
    expected_initial = {
        "empty-followup-ack",
        "empty-open-window",
        "remote-empty-save",
        "remote-empty-return",
        "remote-empty-held-save",
    }
    require(
        set(manifest["initial_cases"]) == expected_initial
        and {p.name for p in (directory / "initial").iterdir()} == expected_initial,
        "Exploratory format inventory differs",
    )
    initial = []
    for path in sorted((directory / "initial").iterdir()):
        report = verify_capture(path)
        require(
            report["driver_sha256"] == driver_hash, "Missing exploratory capture source"
        )
        expected_status = "failed" if path.name.startswith("empty-") else "completed"
        require(
            report["status"] == expected_status, "Initial hypothesis status differs"
        )
        if expected_status == "completed":
            notes = banners(report, "main")
            require(
                len(notes) == 1 and fields(notes[0])[152] == b"GIFf",
                "Stale GUI configuration evidence differs",
            )
        pinned = {
            k: bytes.fromhex(v)
            for k, v in manifest.get("unread_output", {})
            .get("initial/" + path.name, {})
            .items()
        }
        if path.name == "empty-followup-ack":
            require(not pinned, "Unexpected post-reset unread output")
            check_post_reset_write(report, host, guest, differences[0])
        else:
            reconcile(report, host, guest, pinned)
        initial.append(
            {"case": path.name, "status": report["status"], "error": report["error"]}
        )
    require(len(initial) == 5, "Initial hypothesis inventory differs")
    setup = []
    require(
        set(manifest.get("setup_cases", []))
        == {p.name for p in (directory / "setup").iterdir()},
        "Setup inventory differs",
    )
    for path in sorted((directory / "setup").iterdir()):
        report = verify_capture(path)
        require(
            report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] == driver_hash,
            "Setup capture provenance differs",
        )
        pinned = {
            k: bytes.fromhex(v)
            for k, v in manifest.get("unread_output", {})
            .get("setup/" + path.name, {})
            .items()
        }
        reconcile(report, host, guest, pinned)
        setup.append(
            {
                "case": path.name,
                "status": report["status"],
                "error": report["error"],
                "scope": "Setup observation; completion does not imply its configuration expectation passed",
            }
        )
    return {
        "formats": observations,
        "setup": setup,
        "oracle": oracle,
        "initial": initial,
        "native_files": native_files,
        "recovery": recovery,
        "early_recovery": early_recovery,
        "packet_reconciliation": packets,
        "scope": "Native loader/type and raw-byte fixtures; no client rendering or arbitrary lifetime/ownership proof",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
