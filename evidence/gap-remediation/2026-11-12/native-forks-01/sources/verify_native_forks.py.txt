#!/usr/bin/env python3
"""Verify matched-reference transfers, forks and observed completion boundaries."""

import argparse
import hashlib
import json
from pathlib import Path

from native_filp import decode, metadata
from native_packet_evidence import reconcile
from native_transfer_cases import downloads, resource_fork, transfers
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from verify_native_core import require
from verify_native_framing import check_quiet

HANDOVER = bytes.fromhex("54525450484f544c00010003")
SUCCESS = bytes.fromhex("5452545000000000")


def fields(frame: dict) -> dict[int, bytes]:
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "Transfer control ACK changed",
    )
    result = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(result) == len(frame["fields"]), "Duplicate output field")
    return result


def check_metadata(info: bytes, name: bytes, uploaded: bool) -> dict:
    values = metadata(info)
    require(
        values["type"] == b"TEXT" and values["creator"] == b"MOTH",
        "Type/creator differ",
    )
    require(values["comment"] == b"fixture-comment", "Comment round trip differs")
    require(
        values["name"] == (b"metadata-only-name" if uploaded else name),
        "INFO name differs",
    )
    require(
        int.from_bytes(values["flags"], "big") == (0x8100 if uploaded else 0),
        "Metadata flags differ",
    )
    for field in ["created", "modified"]:
        require(
            (values[field] == bytes(8)) == uploaded,
            "Transmitted zero dates unexpectedly restored",
        )
    return {key: value.hex() for key, value in values.items()}


def check_file_info(frame: dict, name: bytes, logical_size: int) -> dict:
    values = fields(frame)
    require(values[201] == name, "Request name did not survive upload")
    require(
        values[213] == b"TEXT" and values[206] == b"MOTH",
        "File-info type/creator differ",
    )
    require(
        int.from_bytes(values[207], "big") == logical_size, "File-info size differs"
    )
    require(values[210] == b"fixture-comment", "File-info comment differs")
    require(
        values[208] != bytes(8) and values[209] != bytes(8),
        "File-info dates stayed zero",
    )
    return {str(k): v.hex() for k, v in values.items()}


def transfer_bytes(
    report: dict, connection: str, handover: bool
) -> tuple[bytes, bytes]:
    received = bytes.fromhex(report["streams"][connection]["received_hex"])
    sent = bytes.fromhex(report["streams"][connection]["sent_hex"])
    if handover:
        require(
            sent.startswith(HANDOVER) and received.startswith(SUCCESS),
            "Handover failed",
        )
        sent, received = sent[12:], received[8:]
    require(sent[:4] == b"HTXF" and len(sent) >= 16, "Missing HTXF header")
    return sent, received


def verify(directory: Path) -> dict:
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = transfers() | downloads()
    require(
        {p.name for p in (directory / "transcripts").iterdir() if p.is_dir()}
        == set(expected),
        "Transfer corpus inventory differs",
    )
    sources = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    observations = []
    for name, (steps, expectation) in expected.items():
        case = directory / "transcripts" / name
        plan = json.loads((case / "plan.json").read_text())
        report = verify_capture(case)
        require(report["status"] == "completed", name + ": capture failed")
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Plan differs",
        )
        require(report["driver_sha256"] in sources, "Missing exact capture source")
        # The recorder closed this control socket before consuming a queued301.
        # Pin the complete independently observed suffix; do not alter the report.
        unread = (
            {
                "main": bytes.fromhex(
                    "0000012d000000030000000000000027000000270004"
                    "006700020060006800020001007000020012"
                    "0066000f6672616d696e672d66697874757265"
                )
            }
            if name == "download-empty"
            else None
        )
        packets = reconcile(report, host, guest, unread)
        check_quiet(report, plan)
        frames = report["frames"][3:]
        values = fields(frames[0])
        filename = bytes.fromhex(expectation["name_hex"])
        empty = filename == b"mothra-empty-fixture"
        data = b"" if empty else b"data-fork\r\n\x00\xff"
        resource = b"" if empty else resource_fork()
        logical = len(data) + len(resource)
        observed = {"case": name, "connections": packets}
        if expectation["kind"] == "upload":
            sent, received = transfer_bytes(
                report, "upload", expectation.get("handover", False)
            )
            reference = values[107]
            require(
                len(reference) == 4 and not int.from_bytes(reference, "big") & 1,
                "Upload ref parity",
            )
            require(
                sent[4:8] == reference and sent[12:16] == bytes(4),
                "Upload HTXF differs",
            )
            body = sent[16:]
            require(
                int.from_bytes(sent[8:12], "big") == len(body), "Upload size differs"
            )
            require(body.hex() == expectation["stream_hex"], "Upload body differs")
            forks = decode(body)
            require(
                forks["DATA"] == data and forks["MACR"] == resource,
                "Uploaded forks differ",
            )
            check_metadata(forks["INFO"], filename, True)
            require(not received, "Unexpected upload application response")
            require(
                packets["upload"]["guest_server_initiated_close"],
                "Upload completion did not close",
            )
            require(len(frames) == 2, "Unexpected upload completion ACK")
            observed["file_info"] = check_file_info(frames[1], filename, logical)
        elif name == "download-empty-preview":
            require(
                set(values) == {108} and values[108] == b"\0\0",
                "Empty preview metadata differs",
            )
            require(set(packets) == {"main"}, "Empty preview opened data connection")
        else:
            reference = values[107]
            require(
                len(reference) == 4 and int.from_bytes(reference, "big") & 1 != 0,
                "Download ref parity",
            )
            require(
                int.from_bytes(values[207], "big") == logical,
                "Logical download size differs",
            )
            sent, received = transfer_bytes(report, "download", expectation["handover"])
            require(
                sent
                == b"HTXF"
                + reference
                + bytes(4)
                + expectation["selector"].to_bytes(2, "big")
                + bytes(2),
                "Download HTXF differs",
            )
            if expectation["selector"] in {1, 2}:
                require(
                    not received
                    and packets["download"]["guest_server_initiated_close"],
                    "Wrong collection not rejected",
                )
            else:
                require(
                    len(received) == int.from_bytes(values[108], "big"),
                    "Advertised count differs",
                )
                if expectation["preview"]:
                    require(received == data, "Preview not raw data fork")
                else:
                    forks = decode(received)
                    require(
                        forks["DATA"] == data and forks["MACR"] == resource,
                        "Downloaded forks differ",
                    )
                    observed["metadata"] = check_metadata(
                        forks["INFO"], filename, False
                    )
                quiet = next(e for e in report["events"] if e["event"] == "quiet")
                require(
                    not any(
                        e["event"] == "eof" and e["action"] <= quiet["action"]
                        for e in report["events"]
                    ),
                    "EOF before quiet window",
                )
                if name == "download-raw":
                    require(
                        len(frames) == 2 and not fields(frames[1]),
                        "Cleanup ACK differs",
                    )
                    require(
                        any(
                            e["event"] == "eof" and e["action"] > quiet["action"]
                            for e in report["events"]
                        ),
                        "Missing post214 EOF",
                    )
                else:
                    require(
                        not packets["download"]["guest_server_initiated_close"],
                        "Download closed before peer cleanup",
                    )
            observed["advertised_bytes"] = int.from_bytes(values[108], "big")
        observations.append(observed)
    for name, data, resource in [
        ("mothra-fork-fixture", b"data-fork\r\n\x00\xff", resource_fork()),
        ("mothra-empty-fixture", b"", b""),
    ]:
        require(
            (directory / "native-files" / (name + ".data")).read_bytes() == data,
            "Native data fork differs",
        )
        if resource:
            require(
                (directory / "native-files" / (name + ".rsrc")).read_bytes()
                == resource,
                "Native resource fork differs",
            )
        else:
            extraction = json.loads(
                (directory / "native-files/extraction.json").read_text()
            )
            record = next(f for f in extraction["files"] if f["name"] == name)
            require(
                record["resource_exit_code"] != 0,
                "Absent resource extraction misreported",
            )
            require(
                "Attribute 4353-1 not found"
                in (directory / "native-files" / (name + ".rsrc.stderr")).read_text(),
                "Missing absent-resource evidence",
            )
        stat = (directory / "native-files" / (name + ".stat.txt")).read_text()
        require(
            "File Path: /Hotline19/Files/" + name in stat
            and "TEXT" in stat
            and "MOTH" in stat,
            "Native catalogue identity differs",
        )
        require(
            f"Resource fork size:\t{len(resource)}" in stat,
            "Catalogue resource length differs",
        )
    initial = []
    for case in sorted((directory / "initial-eof-hypotheses").iterdir()):
        report = verify_capture(case)
        reconcile(report, host, guest)
        initial.append(
            {"case": case.name, "status": report["status"], "error": report["error"]}
        )
    require(
        len(initial) == 8 and sum(c["status"] == "failed" for c in initial) == 5,
        "Initial EOF hypothesis inventory differs",
    )
    return {
        "cases": observations,
        "initial_eof_hypotheses": initial,
        "scope": "Two successful uploads, eight download modes; completion bytes and observed cleanup, not restart durability or full transfer conformance",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
