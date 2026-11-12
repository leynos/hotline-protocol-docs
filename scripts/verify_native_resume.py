#!/usr/bin/env python3
"""Verify native RFLT boundaries, continuation bytes and inconsistent clients."""

import argparse
import hashlib
import json
from pathlib import Path

from native_filp import decode
from native_packet_evidence import reconcile
from native_resume_cases import downloads, rflt, upload_continuations, upload_probes
from native_transfer_cases import resource_fork
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from verify_native_core import require
from verify_native_forks import check_file_info, check_metadata, fields
from verify_native_framing import check_quiet

DATA = b"data-fork\r\n\x00\xff"
RESOURCE = resource_fork()


def reply(report: dict, identifier: int) -> dict:
    selected = [
        f for f in report["frames"] if f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate control reply")
    require(selected[0]["type"] == 0, "Unexpected direct reply type")
    return selected[0]


def expected_forks(name: str) -> tuple[bytes, bytes]:
    """Pin observed byte ranges, including noncanonical repeated-entry outcomes."""
    return {
        "zero-entries": (DATA, RESOURCE),
        "data-zero": (DATA, RESOURCE),
        "data-inside": (DATA[3:], RESOURCE),
        "resource-inside": (DATA, RESOURCE[4:]),
        "both-inside": (DATA[3:], RESOURCE[4:]),
        "both-eof": (b"", b""),
        "both-beyond": (b"", b""),
        "unknown-tag": (DATA, RESOURCE),
        "duplicate-data-3-4": (DATA[4:10], RESOURCE),
        "duplicate-data-4-3": (DATA[3:9], RESOURCE),
        "duplicate-data-beyond-inside": (b"", RESOURCE),
        "duplicate-resource-3-4": (DATA, RESOURCE[4:314]),
    }[name.removeprefix("resume-download-")]


def check_download(name: str, report: dict, expectation: dict, packets: dict) -> dict:
    if expectation["kind"] == "resume-no-reply":
        require(
            not any(f["is_reply"] and f["id"] == 10 for f in report["frames"]),
            "Unexpected invalid-RFLT reply",
        )
        require(
            reply(report, 11)["payload_hex"] == "0000",
            "Control session did not remain usable",
        )
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        require(
            pause["elapsed_ns"] - prior["elapsed_ns"] >= 3e9,
            "Short invalid-input window",
        )
        return {
            "outcome": "No reply10 observed before three-second pause and subsequent500 ACK"
        }
    values = fields(reply(report, 10))
    reference = values[107]
    require(
        len(reference) == 4 and int.from_bytes(reference, "big") & 1 != 0,
        "Download ref parity",
    )
    require(int.from_bytes(values[207], "big") == 330, "Logical file length changed")
    sent = bytes.fromhex(report["streams"]["download"]["sent_hex"])
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(sent == b"HTXF" + reference + bytes(8), "Download header differs")
    advertised = int.from_bytes(values[108], "big")
    if expectation["kind"] == "resume-data-error":
        require(
            advertised == 180 and not received, "Unsigned-max offset outcome differs"
        )
        require(
            packets["download"]["guest_server_initiated_close"],
            "Missing native offset-error close",
        )
        require(
            any(e["event"] == "eof" for e in report["events"]),
            "Missing offset-error EOF",
        )
        return {
            "advertised_bytes": advertised,
            "delivered_bytes": 0,
            "outcome": "Data connection closed without advertised stream",
        }
    require(len(received) == advertised, "Resume advertised count differs")
    forks = decode(received)
    expected_data, expected_resource = expected_forks(name)
    require(
        forks["DATA"] == expected_data and forks["MACR"] == expected_resource,
        "Resume fork range differs",
    )
    check_metadata(forks["INFO"], b"mothra-fork-fixture", False)
    require(
        not packets["download"]["guest_server_initiated_close"],
        "Resume download closed before client",
    )
    return {
        "advertised_bytes": advertised,
        "data_bytes": len(expected_data),
        "resource_bytes": len(expected_resource),
    }


def check_upload(report: dict, expectation: dict, packets: dict) -> dict:
    kind = expectation["kind"]
    filename = bytes.fromhex(expectation["name_hex"])
    response = reply(report, 10)
    if kind == "resume-upload-probe" and filename != b"mothra-resume-partial":
        require(response["error"] == 1, "Missing/completed file resume accepted")
        values = {f["id"]: bytes.fromhex(f["hex"]) for f in response["fields"]}
        require(set(values) == {100}, "Resume failure unexpectedly allocated reference")
        phrase = (
            b"does not exist"
            if filename == b"mothra-missing-partial"
            else b"already fully transfered"
        )
        require(phrase in values[100], "Resume failure message differs")
        return {"outcome": phrase.decode()}
    values = fields(response)
    reference = values[107]
    require(
        len(reference) == 4 and not int.from_bytes(reference, "big") & 1,
        "Upload ref parity",
    )
    if kind != "upload-prefix":
        require(
            values[203] == rflt([(b"DATA", 13), (b"MACR", 5)]),
            "Negotiated offsets differ",
        )
    if kind == "resume-upload-probe":
        return {"negotiated_data_offset": 13, "negotiated_resource_offset": 5}
    sent = bytes.fromhex(report["streams"]["upload"]["sent_hex"])
    require(
        sent[:8] == b"HTXF" + reference and sent[12:16] == bytes(4),
        "Upload header differs",
    )
    advertised = int.from_bytes(sent[8:12], "big")
    if kind == "upload-prefix":
        require(
            sent[16:].hex() == expectation["prefix_hex"] and advertised == 509,
            "Seed prefix differs",
        )
        require(len(sent) - 16 == 197, "Unexpected partial upload count")
        info = fields(reply(report, 11))
        require(
            info[213] == b"HTft" and int.from_bytes(info[207], "big") == 18,
            "Incomplete file state differs",
        )
        require(
            not packets["upload"]["guest_server_initiated_close"],
            "Seed closed before interruption",
        )
        return {
            "advertised_bytes": advertised,
            "sent_body_bytes": 197,
            "retained_data_bytes": 13,
            "retained_resource_bytes": 5,
        }
    body = sent[16:]
    require(
        body.hex() == expectation["stream_hex"] and len(body) == advertised,
        "Continuation body differs",
    )
    uploaded = decode(body)
    inconsistent = expectation["inconsistent"]
    require(
        uploaded["DATA"] == (DATA if inconsistent else b""), "Continuation DATA differs"
    )
    require(
        uploaded["MACR"] == (RESOURCE if inconsistent else RESOURCE[5:]),
        "Continuation MACR differs",
    )
    check_metadata(uploaded["INFO"], filename, True)
    require(
        packets["upload"]["guest_server_initiated_close"],
        "Continuation did not close upload",
    )
    expected_data = DATA + DATA if inconsistent else DATA
    expected_resource = RESOURCE[:5] + RESOURCE if inconsistent else RESOURCE
    check_file_info(
        reply(report, 11), filename, len(expected_data) + len(expected_resource)
    )
    download = bytes.fromhex(report["streams"]["download"]["received_hex"])
    control = fields(reply(report, 12))
    require(
        len(download) == int.from_bytes(control[108], "big"), "Readback count differs"
    )
    require(
        bytes.fromhex(report["streams"]["download"]["sent_hex"])
        == b"HTXF" + control[107] + bytes(8),
        "Readback reference differs",
    )
    forks = decode(download)
    require(
        forks["DATA"] == expected_data and forks["MACR"] == expected_resource,
        "Resumed native readback differs",
    )
    check_metadata(forks["INFO"], filename, False)
    return {
        "data_bytes": len(expected_data),
        "resource_bytes": len(expected_resource),
        "inconsistent_client": inconsistent,
    }


def verify(directory: Path) -> dict:
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = downloads() | upload_probes() | upload_continuations()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Resume corpus inventory differs",
    )
    sources = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    unread = json.loads((directory / "unread-output.json").read_text())
    observations = []
    for name, (steps, expectation) in expected.items():
        case = directory / "transcripts" / name
        plan = json.loads((case / "plan.json").read_text())
        report = verify_capture(case)
        require(report["status"] == "completed", "Final resume capture failed")
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Resume plan differs",
        )
        require(
            report["driver_sha256"] in sources, "Missing exact resume driver source"
        )
        require(
            [(f["type"], f["is_reply"], f["error"]) for f in report["frames"][:3]]
            == [(0, 1, 0), (354, 0, 0), (109, 0, 0)],
            "Login bootstrap differs",
        )
        require(
            str(case.relative_to(directory)) not in unread,
            "Unexpected final unread output",
        )
        packets = reconcile(report, host, guest)
        check_quiet(report, plan)
        outcome = (
            check_download(name, report, expectation, packets)
            if name.startswith("resume-download-")
            else check_upload(report, expectation, packets)
        )
        observations.append({"case": name, "connections": packets, **outcome})
    for stage, name, data, resource in [
        ("before", "mothra-resume-partial", DATA, RESOURCE[:5]),
        ("after", "mothra-resume-partial", DATA, RESOURCE),
        ("after", "mothra-resume-inconsistent", DATA + DATA, RESOURCE[:5] + RESOURCE),
    ]:
        base = directory / "native-files" / stage
        require(
            (base / (name + ".data")).read_bytes() == data,
            "Native resumed DATA differs",
        )
        require(
            (base / (name + ".rsrc")).read_bytes() == resource,
            "Native resumed MACR differs",
        )
        stat = (base / (name + ".stat.txt")).read_text()
        require(
            ("HTft" if stage == "before" else "TEXT") in stat,
            "Native resume file type differs",
        )
        require(
            f"Resource fork size:\t{len(resource)}" in stat,
            "Native resource catalogue differs",
        )
    initial = []
    for path in sorted((directory / "initial-probes").rglob("report.json")):
        report = verify_capture(path.parent)
        require(report["driver_sha256"] in sources, "Missing initial resume source")
        suffixes = {
            k: bytes.fromhex(v)
            for k, v in unread.get(str(path.parent.relative_to(directory)), {}).items()
        }
        reconcile(report, host, guest, suffixes)
        initial.append(
            {
                "case": str(path.parent.relative_to(directory)),
                "status": report["status"],
                "error": report["error"],
            }
        )
    require(
        len(initial) == 7 and sum(c["status"] == "failed" for c in initial) == 3,
        "Initial resume attempts changed",
    )
    return {
        "cases": observations,
        "initial_probes": initial,
        "scope": "23 final bounded observations plus7 initial attempts; native tolerance, not a safe malformed-input policy or restart-durability proof",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
