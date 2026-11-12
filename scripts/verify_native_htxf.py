#!/usr/bin/env python3
"""Verify native HTXF routing, size replacement and bounded reference use."""

import argparse
import json
from pathlib import Path

from native_banner_cases import GIF_B
from native_filp import decode
from native_htxf_cases import htxf
from native_packet_evidence import reconcile
from native_transfer_cases import file_stream, resource_fork
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_banner_formats import requests
from verify_native_banners import fields
from verify_native_core import require


def ack(report: dict, identifier: int = 10, connection: str = "a") -> dict:
    matches = [
        f
        for f in report["frames"]
        if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
    ]
    require(len(matches) == 1 and matches[0]["error"] == 0, "Missing HTXF success ACK")
    return fields(matches[0])


def observed(report: dict, connection: str, event: str) -> list[dict]:
    return [
        e
        for e in report["events"]
        if e["connection"] == connection and e["event"] == event
    ]


def check_case(name: str, report: dict, packets: dict) -> dict:
    require(report["status"] == "completed", "Incomplete HTXF observation")
    values = ack(report, connection="main" if name == "preflight" else "a")
    ref = values[107]
    require(len(ref) == 4, "HTXF reference width differs")
    if name == "preflight":
        require(
            int.from_bytes(values[108], "big") == len(GIF_B), "Preflight size differs"
        )
        return {"case": name, "reference_hex": ref.hex()}
    source = requests(report, "a")
    operation = next(f for f in source if f["id"] == 10)
    require(operation["type"] in {202, 203, 210, 212}, "Wrong HTXF request")
    require(
        int.from_bytes(ref, "big") & 1 == (operation["type"] != 203),
        "Reference parity differs",
    )
    if "b" in report["streams"]:
        privilege = [
            f for f in report["frames"] if f["connection"] == "b" and f["type"] == 354
        ]
        require(
            len(privilege) == 1 and fields(privilege[0]) == {110: bytes(8)},
            "Observer privileges differ",
        )
        credentials = fields(requests(report, "b")[0])
        require(
            credentials[105] == bytes(v ^ 255 for v in b"fixture-low"),
            "Observer identity differs",
        )
    selector = 2 if operation["type"] == 212 else 0
    size, reserved, magic = 0, 0, b"HTXF"
    if name == "banner-size-ffffffff-reserved-ffff":
        size, reserved = 0xFFFFFFFF, 65535
    elif name in {"banner-size-one-reserved-1234", "banner-split-15-plus-1"}:
        size, reserved = (1 if "size-one" in name else 0), 0x1234
    elif name == "banner-bad-magic":
        magic = b"HTXG"
    elif name == "download-size-reserved-selector-ffff":
        selector, size, reserved = 65535, 0xFFFFFFFF, 0xABCD
    elif name.startswith("folder-download-wrong-selector-"):
        selector = int(name.rsplit("-", 1)[1])
    elif name.startswith("upload-nonfolder-selector-"):
        selector = int(name.rsplit("-", 1)[1])
        size = len(file_stream(b"header-routing-" + str(selector).encode(), b""))
        reserved = 65535
    header = (
        magic
        + ref
        + size.to_bytes(4, "big")
        + selector.to_bytes(2, "big")
        + reserved.to_bytes(2, "big")
    )
    successful = []
    for connection, value in report["streams"].items():
        if connection in {"a", "b"}:
            continue
        sent, received = (
            bytes.fromhex(value["sent_hex"]),
            bytes.fromhex(value["received_hex"]),
        )
        require(sent[:16] == header, name + ": physical HTXF header differs")
        if operation["type"] == 203:
            body = file_stream(b"header-routing-" + str(selector).encode(), b"")
            require(sent[16:] == body and not received, "Upload stream differs")
            advertised = int.from_bytes(fields(operation)[108], "big")
            require(
                advertised == len(body) + (37 if selector == 0 else 0),
                "Upload request size differs",
            )
            require(bool(observed(report, connection, "eof")), "Missing upload close")
            ack(report, 11)
        else:
            require(len(sent) == 16, "Unexpected HTXF input suffix")
            succeeds = connection in {"first", "foreign"} or name in {
                "banner-size-ffffffff-reserved-ffff",
                "banner-size-one-reserved-1234",
                "banner-split-15-plus-1",
                "download-size-reserved-selector-ffff",
                "download-separate-low-privilege-session",
            }
            if succeeds:
                if operation["type"] == 212:
                    require(received == GIF_B, "Banner bytes differ")
                else:
                    forks = decode(received)
                    require(
                        forks["DATA"] == b"data-fork\r\n\x00\xff"
                        and forks["MACR"] == resource_fork(),
                        "Download forks differ",
                    )
                    require(
                        len(received) == int.from_bytes(values[108], "big"),
                        "Download advertised size differs",
                    )
                successful.append(connection)
            else:
                require(not received, "Rejected/duplicate connection delivered bytes")
            event = "quiet" if succeeds and connection != "download" else "eof"
            if name == "banner-reuse-after-close" and connection == "first":
                event = "close"
            require(
                bool(observed(report, connection, event)),
                "Missing HTXF quiet/close observation",
            )
        if observed(report, connection, "eof"):
            require(
                packets[connection]["guest_server_initiated_close"],
                "Missing native close",
            )
    for e in report["events"]:
        if e["event"] == "quiet":
            before = max(
                p["elapsed_ns"] for p in report["events"] if p["action"] < e["action"]
            )
            require(
                e["elapsed_ns"] - before >= 3_000_000_000,
                "Short HTXF quiet observation",
            )
    if name == "banner-split-15-plus-1":
        sends = observed(report, "data", "send")
        require(
            [len(bytes.fromhex(e["hex"])) for e in sends] == [15, 1],
            "Split header differs",
        )
        require(
            any(
                sends[0]["action"] < q["action"] < sends[1]["action"]
                for q in observed(report, "data", "quiet")
            ),
            "Missing incomplete-header quiet interval",
        )
    if name in {"banner-owner-gone", "download-owner-gone"}:
        target = "stale" if name.startswith("banner") else "download"
        require(
            observed(report, "a", "close")[0]["action"]
            < observed(report, target, "connect")[0]["action"],
            "Owner was not closed before attachment",
        )
    if name == "banner-reuse-after-close":
        require(
            observed(report, "first", "close")[0]["action"]
            < observed(report, "stale", "connect")[0]["action"],
            "Reference was not reused after close",
        )
    if name == "banner-duplicate-after-send":
        require(
            not packets["first"]["guest_server_initiated_close"],
            "First duplicate transport closed natively",
        )
        end = observed(report, "second", "eof")[0]["action"]
        require(
            observed(report, "a", "close")[0]["action"]
            < end
            < observed(report, "first", "quiet")[-1]["action"],
            "Duplicate cleanup ordering differs",
        )
    return {
        "case": name,
        "reference_hex": ref.hex(),
        "operation": operation["type"],
        "successful_connections": successful,
    }


def verify_native_uploads(directory: Path) -> None:
    root = directory / "native-uploads"
    extraction = json.loads((root / "extraction.json").read_text())
    expected = {
        f"/Hotline19/Files/m-htxf-u{s}": b"header-routing-" + str(s).encode()
        for s in [0, 2, 65535]
    }
    require(
        {r["path"] for r in extraction["records"]} == set(expected),
        "Native upload inventory differs",
    )
    for record in extraction["records"]:
        stat = (root / (record["key"] + ".stat.txt")).read_text()
        require(
            "File Path: " + record["path"] + "\n" in stat
            and "54455854  TEXT" in stat
            and "4d4f5448  MOTH" in stat,
            "Native upload identity differs",
        )
        require("Resource fork size:\t0\n" in stat, "Native resource fork size differs")
        require(
            record["attributes"]["data"]["exit_code"] == 0
            and (root / (record["key"] + ".data")).read_bytes()
            == expected[record["path"]],
            "Native upload data differs",
        )
        require(
            record["attributes"]["rsrc"]["exit_code"] == 1
            and "Attribute not found" in record["attributes"]["rsrc"]["stderr"],
            "Absent resource attribute was not retained",
        )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        set(manifest["cases"]) == set(htxf()) | {"preflight"}
        and len(manifest["cases"]) == 18,
        "HTXF case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "HTXF oracle identity differs")
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    results, packets = [], {}
    for name in manifest["cases"]:
        report = verify_capture(directory / "transcripts" / name)
        packets[name] = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest["unread_output"].get(name, {}).items()
            },
        )
        results.append(check_case(name, report, packets[name]))
    require(
        packets == json.loads((directory / "packet-reconciliation.json").read_text()),
        "Retained packet reconciliation differs",
    )
    verify_native_uploads(directory)
    return {"cases": results, "packet_reconciliation": packets}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    print(
        f"Verified {len(result['cases'])} native HTXF observations and three native uploads"
    )


if __name__ == "__main__":
    main()
