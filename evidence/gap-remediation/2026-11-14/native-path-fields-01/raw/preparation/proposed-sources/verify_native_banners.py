#!/usr/bin/env python3
"""Verify bounded native banner metadata, payload and reload observations."""

import argparse
import json
from pathlib import Path

from native_banner_cases import GIF_A, GIF_B, URL, image, metadata
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_core import require


def fields(frame: dict) -> dict[int, bytes]:
    """Return a frame's fields by identifier, refusing duplicates."""
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(values) == len(frame["fields"]), "Duplicate banner field")
    return values


def check_case(name: str, report: dict, plan: dict, packets: dict) -> dict:
    """Check actual frames/streams; plan labels alone cannot establish semantics."""
    require(report["status"] == "completed", name + ": incomplete observation")
    incoming = bytes.fromhex(report["streams"]["main"]["sent_hex"])[12:]
    requests = []
    while incoming:
        require(len(incoming) >= 20, name + ": truncated request")
        size = 20 + int.from_bytes(incoming[16:20], "big")
        require(len(incoming) >= size, name + ": truncated request body")
        requests.append(decode_frame(incoming[:size]))
        incoming = incoming[size:]
    expectation = plan["expectation"]
    kind = expectation["kind"]
    banners = [f for f in report["frames"] if f["type"] == 122 and not f["is_reply"]]
    result = {"case": name, "kind": kind, "packet_reconciliation": packets}
    if kind == "metadata":
        login_request = next(r for r in requests if r["type"] == 107)
        require(
            fields(login_request)[160] == expectation["version"].to_bytes(2, "big"),
            name + ": reported version differs",
        )
        require(
            102 not in fields(login_request)
            and 104 not in fields(login_request)
            and any(r["type"] == 121 for r in requests),
            name + ": delayed completion input differs",
        )
        tag = expectation["type_hex"]
        emitted = tag is not None and expectation["version"] >= 151
        require(len(banners) == int(emitted), name + ":122 eligibility differs")
        if emitted:
            expected = {152: bytes.fromhex(tag)}
            if expectation["link_hex"] is not None:
                expected[153] = bytes.fromhex(expectation["link_hex"])
            require(fields(banners[0]) == expected, name + ":122 fields differ")
            earlier = [
                f for f in report["frames"] if f["action"] < banners[0]["action"]
            ]
            require(
                any(f["type"] == 354 for f in earlier), name + ":122 ordering differs"
            )
        result["banner_notifications"] = len(banners)
        return result
    if kind in {"early", "no-reply-212"}:
        require(not banners, name + ": unexpected122")
        if kind == "no-reply-212":
            require(
                not any(f["is_reply"] and f["id"] == 10 for f in report["frames"]),
                name + ": unexpected212 reply",
            )
            require(
                any(e["event"] == "quiet" for e in report["events"]),
                name + ": missing bounded silence",
            )
            require(
                any(
                    f["is_reply"] and f["id"] == 90 and f["error"] == 0
                    for f in report["frames"]
                ),
                name + ": missing subsequent liveness ACK",
            )
        return result
    acks = [f for f in report["frames"] if f["is_reply"] and f["id"] == 10]
    require(len(acks) == 1 and acks[0]["error"] == 0, name + ":212 ACK differs")
    values = fields(acks[0])
    require(set(values) == {107, 108}, name + ":212 fields differ")
    reference = values[107]
    require(
        len(reference) == 4 and int.from_bytes(reference, "big") & 1 == 1,
        name + ": reference differs",
    )
    advertised = int.from_bytes(values[108], "big")
    stream = report["streams"]["banner"]
    sent = bytes.fromhex(stream["sent_hex"])
    raw = bytes.fromhex(stream["received_hex"])
    require(len(sent) == 16 and sent[:4] == b"HTXF", name + ": HTXF header differs")
    if kind == "reject":
        expected_ref = (
            b"\xff" * 4
            if name.endswith("-unknown")
            else bytes(4)
            if name.endswith("-zero")
            else reference
        )
        require(
            sent[4:8] == expected_ref
            and int.from_bytes(sent[12:14], "big") == expectation["selector"],
            name + ": negative HTXF control differs",
        )
    if kind == "expired":
        require(
            sent[4:8] == reference and sent[12:14] == b"\0\2",
            name + ": expiry reference differs",
        )
    if kind in {"reject", "expired"}:
        require(
            not raw and packets["banner"]["guest_server_initiated_close"],
            name + ": rejection outcome differs",
        )
    else:
        require(
            sent[4:8] == reference and sent[12:14] == b"\0\2",
            name + ": attached reference/selector differs",
        )
        expected = GIF_B if kind in {"changed", "absent-restored"} else GIF_A
        require(raw == expected, name + ": raw banner bytes differ")
        require(
            advertised == (len(GIF_B) if kind == "absent-restored" else len(GIF_A)),
            name + ": advertised size differs",
        )
        require(
            any(
                e["event"] == "quiet" and e["connection"] == "banner"
                for e in report["events"]
            ),
            name + ": missing open-stream observation",
        )
        if kind == "changed":
            require(
                len(banners) == 1 and fields(banners[0]) == {152: b"GIFf", 153: URL},
                name + ": reload metadata sequence differs",
            )
        else:
            require(not banners, name + ": early login unexpectedly emitted122")
        if kind == "absent-restored":
            receives = [
                e
                for e in report["events"]
                if e["event"] == "receive" and e["connection"] == "banner"
            ]
            pauses = [e for e in report["events"] if e["event"] == "pause"]
            quiets = [
                e
                for e in report["events"]
                if e["event"] == "quiet" and e["connection"] == "banner"
            ]
            require(
                len(pauses) == 2
                and quiets[0]["elapsed_ns"]
                < pauses[1]["elapsed_ns"]
                < receives[0]["elapsed_ns"],
                name + ": restoration ordering differs",
            )
        if kind == "cancel-does-not-close":
            cancellations = [
                f
                for f in report["frames"]
                if f["is_reply"] and f["id"] in {11, 12} and f["error"] == 0
            ]
            require(len(cancellations) == 2, name + ": cancellation ACKs differ")
    if kind == "expired":
        require(
            {
                f["id"]
                for f in report["frames"]
                if f["is_reply"] and f["error"] == 0 and 20 <= f["id"] <= 31
            }
            == set(range(20, 32)),
            name + ": missing owner liveness ACKs",
        )
        pauses = [e for e in report["events"] if e["event"] == "pause"]
        require(len(pauses) == 12, name + ": expiry windows differ")
        for event in pauses:
            prior = max(
                e["elapsed_ns"]
                for e in report["events"]
                if e["action"] == event["action"] - 1
            )
            require(
                event["elapsed_ns"] - prior >= 45e9, name + ": shortened expiry pause"
            )
    result.update(advertised_bytes=advertised, delivered_bytes=len(raw))
    return result


def verify(directory: Path) -> dict:
    """Verify the banner corpus and return the summary."""
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = (
        set(metadata("none", None, None))
        | set(metadata("url", b"URL ", URL))
        | set(image())
        | {"changed-buffer", "missing-metadata-190", "expired-reference"}
    )
    require(
        set(manifest["final_cases"]) == expected
        and len(manifest["final_cases"]) == len(expected),
        "Banner case inventory differs",
    )
    require(
        manifest["oracle_sha256"] == ORACLE_SHA256, "Banner oracle identity differs"
    )
    for address in ["1002af80", "1002e8b0", "1002f080", "1002f0c0"]:
        prefix = directory / "path-queries" / ("BN-D-" + address)
        record = json.loads(prefix.with_suffix(".json").read_text())
        require(
            record["program"]["sha256"] == ORACLE_SHA256
            and not record["result"]["isError"],
            "Filename helper oracle differs",
        )
        require(
            record["query"]["arguments"]["address"] == address
            and record["result"]["structuredContent"]["code"]
            == prefix.with_suffix(".c").read_text(),
            "Filename helper query differs",
        )
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    observations = []
    for name in manifest["final_cases"]:
        path = directory / "transcripts" / name
        report = verify_capture(path)
        plan = json.loads((path / "plan.json").read_text())
        packets = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest.get("unread_output", {}).get(name, {}).items()
            },
        )
        observations.append(check_case(name, report, plan, packets))
    for catalog, expected in [(11240, GIF_A), (11241, GIF_B)]:
        prefix = directory / "native-files" / f"catalog-{catalog}"
        require(
            prefix.with_suffix(".data").read_bytes() == expected,
            "Native banner fork differs",
        )
        stat = prefix.with_suffix(".stat.txt").read_text()
        require(
            f"File Path: /Hotline19/mothra-banner-{'a' if catalog == 11240 else 'b'}.gif"
            in stat
            and "GIFf" in stat
            and "MOTH" in stat,
            "Native banner identity differs",
        )
    require(
        set(manifest["initial_cases"])
        == {p.name for p in (directory / "initial").iterdir()}
        and len(manifest["initial_cases"]) == 42,
        "Exploratory banner inventory differs",
    )
    initial = []
    for path in sorted((directory / "initial").iterdir()):
        report = verify_capture(path)
        packets = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest.get("unread_output", {})
                .get("initial/" + path.name, {})
                .items()
            },
        )
        initial.append(
            {
                "case": path.name,
                "status": report["status"],
                "error": report["error"],
                "packet_reconciliation": packets,
            }
        )
    return {
        "cases": observations,
        "initial": initial,
        "scope": "Bounded GIF/URL/absent banner observations, not all formats, arbitrary reference lifetimes or historical client acceptance",
    }


def main() -> None:
    """Verify the corpus named on the command line and print the summary as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
