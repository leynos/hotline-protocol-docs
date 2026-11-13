#!/usr/bin/env python3
"""Verify configured login-name bytes, version gates and refresh observations."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from native_banner_cases import GIF_B, URL
from native_login_extras_cases import (
    CONFIGURED_URL,
    NAMES,
    configured,
    downloads,
    lifetime,
)
from native_packet_evidence import reconcile
from pcap_tcp import direction, read_packets, stream
from pcap_tcp import lifetime as tcp_lifetime
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_auth import ADMIN, reply, selected
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet


def preferences(directory: Path) -> dict:
    extraction = json.loads((directory / "extraction.json").read_text())
    records = [r for r in extraction["records"] if r["path"] == "/Hotline19/Prefs"]
    require(
        len(records) == 1 and not records[0]["directory"],
        "Missing positive native Prefs record",
    )
    record = records[0]
    require(record["attributes"]["data"]["exit_code"] == 0, "Native Prefs read failed")
    data = (directory / (record["key"] + ".data")).read_bytes()
    require(
        len(data) >= 86 and data[:2] == b"\0\5", "Native Prefs version/prefix differs"
    )
    require(
        (
            int.from_bytes(data[54:56], "big"),
            int.from_bytes(data[64:66], "big"),
            int.from_bytes(data[66:68], "big"),
            int.from_bytes(data[68:70], "big"),
        )
        == (5, 5500, 100, 10),
        "Native General configuration drifted",
    )
    values = []
    position = 76
    for _ in range(10):
        require(position < len(data), "Missing native Pascal length")
        length = data[position]
        require(position + 1 + length <= len(data), "Truncated native Pascal content")
        values.append(data[position + 1 : position + 1 + length])
        position += 1 + length
    require(len(values[3]) <= 31, "Native server-name destination exceeds31 bytes")
    return {
        "name": values[3],
        "strings": values,
        "flags": int.from_bytes(data[60:64], "big"),
        "bytes": data,
    }


def login_ack(frame: dict, name: bytes) -> None:
    expected = {160: b"\0\xbe", 161: b"\0\0"}
    if name:
        expected[162] = name
    require(
        frame["is_reply"] == 1 and frame["id"] == 1 and frame["error"] == 0,
        "Login extra ACK correlation/status differs",
    )
    require(fields(frame) == expected, "Configured login-extra values differ")


def check_configured(report: dict, expected: dict, agreement: bytes) -> dict:
    frames = report["frames"]
    early, version = expected["early"], expected["version"]
    advertised = (
        not early
        and version is not None
        and version >= 151
        and expected["phase"] != "none"
    )
    shape = (
        [(0, 1, 0), (354, 0, 0), (109, 0, 0)]
        if early
        else [(0, 1, 0), (109, 0, 0), (0, 1, 0), (354, 0, 0)]
    )
    if advertised:
        shape.append((122, 0, 0))
    shape.append((0, 1, 0))
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in frames] == shape,
        "Configured login/banner sequence differs",
    )
    login_ack(frames[0], bytes.fromhex(expected["name_hex"]))
    require(
        [f["id"] for f in frames if f["is_reply"]]
        == ([1, 90] if early else [1, 2, 90]),
        "Configured reply IDs differ",
    )
    require(
        fields(next(f for f in frames if f["type"] == 109)) == {101: agreement},
        "Configured agreement changed",
    )
    require(
        fields(next(f for f in frames if f["type"] == 354)) == {110: ADMIN},
        "Configured privileges changed",
    )
    if advertised:
        tag, link = (
            (b"URL ", CONFIGURED_URL) if expected["phase"] == "url" else (b"GIFf", URL)
        )
        require(
            fields(next(f for f in frames if f["type"] == 122))
            == {152: tag, 153: link},
            "Configured banner metadata differs",
        )
    require(fields(reply(report, 90)) == {}, "Configured liveness ACK differs")
    if not early:
        require(
            fields(reply(report, 2)) == {},
            "Acceptance ACK unexpectedly refreshes login extras",
        )
    return {"early": early, "version": version, "advertised": advertised}


def check_lifetime(report: dict, agreement: bytes) -> dict:
    for connection, name in [
        ("observer", NAMES["name-a"]),
        ("waiting", NAMES["name-a"]),
        ("fresh", NAMES["name-b"]),
    ]:
        frames = selected(report, connection)
        login_ack(frames[0], name)
        require(
            fields(next(f for f in frames if f["type"] == 109)) == {101: agreement},
            "Lifetime agreement changed",
        )
        for frame in frames[1:]:
            require(
                not ({161, 162} & set(fields(frame))),
                "Existing-session login extras were refreshed",
            )
    require(
        fields(reply(report, 2, "waiting")) == {},
        "Waiting acceptance refreshed its login extras",
    )
    require(
        fields(reply(report, 90, "waiting")) == {},
        "Waiting session failed to complete after the change",
    )
    for identifier in [90, 91]:
        require(
            fields(reply(report, identifier, "observer")) == {},
            "Existing online session lost liveness",
        )
    waiting = selected(report, "waiting")
    require(
        [f["type"] for f in waiting] == [0, 109, 0, 354, 122, 0],
        "Waiting name-change completion differs",
    )
    require(
        fields(next(f for f in waiting if f["type"] == 122))
        == {152: b"GIFf", 153: URL},
        "Name-only save changed banner metadata",
    )
    return {
        "old_name_hex": NAMES["name-a"].hex(),
        "fresh_name_hex": NAMES["name-b"].hex(),
    }


def check_downloads(report: dict, agreement: bytes) -> dict:
    frames = selected(report, "main")
    login_ack(frames[0], NAMES["name-b"])
    require(
        fields(frames[1]) == {110: ADMIN} and fields(frames[2]) == {101: agreement},
        "Banner-reference login bootstrap differs",
    )
    require(
        [(f["id"], f["error"]) for f in frames if f["is_reply"]]
        == [(1, 0), (10, 0), (11, 0)],
        "Banner-reference replies differ",
    )
    references = []
    for identifier in [10, 11]:
        response = fields(reply(report, identifier))
        require(
            set(response) == {107, 108} and response[108] == b"\0\x3a",
            "Banner reference/size fields differ",
        )
        require(
            len(response[107]) == 4 and int.from_bytes(response[107], "big") != 0,
            "Banner reference equals zero login value161",
        )
        connection = f"data{identifier}"
        require(
            report["streams"][connection]["received_hex"] == GIF_B.hex(),
            "Configured banner bytes changed",
        )
        require(
            report["streams"][connection]["sent_hex"]
            == "48545846" + response[107].hex() + "0000000000020000",
            "Banner attach reference differs",
        )
        references.append(response[107].hex())
    return {"login_value_hex": "0000", "banner_reference_hex": references}


def cases() -> dict:
    expected = {}
    for name in NAMES:
        expected.update(configured(name))
    return expected | lifetime() | downloads()


def check_failed_lifetime(report: dict, host: list[dict], guest: list[dict]) -> None:
    """Keep host-only late input and guest-only cleanup outside equal streams."""
    start = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
    require(report["status"] == "failed", "Long waiting hypothesis was rewritten")
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        name = event["connection"]
        client, server = tuple(event["local_address"]), tuple(event["peer_address"])
        guest_client, guest_server = ("10.0.2.2", client[1]), ("10.0.2.15", 5500)
        when = int(start + event["elapsed_ns"] / 1000)
        hp = tcp_lifetime(host, client, server, when)
        gp = tcp_lifetime(guest, guest_client, guest_server, when)
        host_input, guest_input = (
            stream(hp, client, server),
            stream(gp, guest_client, guest_server),
        )
        host_output, guest_output = (
            stream(hp, server, client),
            stream(gp, guest_server, guest_client),
        )
        require(
            host_input.hex() == report["streams"][name]["sent_hex"],
            "Failed trial host input differs",
        )
        received = bytes.fromhex(report["streams"][name]["received_hex"])
        require(
            host_output.startswith(received),
            "Failed trial recorded output is not a prefix",
        )
        if name == "waiting":
            require(
                host_input.startswith(guest_input),
                "Failed waiting input boundary is not a prefix",
            )
            late = host_input[len(guest_input) :]
            frame = decode_frame(late)
            require(
                frame["type"] == 121 and frame["id"] == 2,
                "Expected host-only late acceptance",
            )
            sent = next(
                e
                for e in report["events"]
                if e["event"] == "send"
                and e["connection"] == name
                and e["hex"] == late.hex()
            )
            closes = [
                p for p in direction(gp, guest_server, guest_client) if p["flags"] & 5
            ]
            require(
                bool(closes)
                and closes[0]["timestamp_us"] < start + sent["elapsed_ns"] / 1000,
                "Late acceptance preceded native close",
            )
        else:
            require(
                host_input == guest_input,
                "Failed trial input differs outside waiting session",
            )
        if name == "observer":
            require(
                guest_output.startswith(host_output),
                "Failed observer output boundary is not a prefix",
            )
            late = guest_output[len(host_output) :]
            frame = decode_frame(late)
            require(
                len(late) == 28 and frame["type"] == 302 and not frame["is_reply"],
                "Expected guest-only cleanup tail",
            )
        else:
            require(
                host_output == guest_output,
                "Failed trial output differs outside observer cleanup",
            )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Login-extra oracle differs")
    expected_cases = cases()
    require(
        set(manifest["cases"]) == set(expected_cases) and len(expected_cases) == 34,
        "Login-extra case inventory differs",
    )
    require(
        set(manifest["configurations"]) == set(NAMES),
        "Native configuration inventory differs",
    )
    for name, path in manifest["configurations"].items():
        prefs = preferences(directory / path)
        require(prefs["name"] == NAMES[name], "Native stored server name differs")
        if name in {"url", "none"}:
            require(
                not prefs["flags"] & 128
                and prefs["strings"][9] == (CONFIGURED_URL if name == "url" else b""),
                "Native remote banner configuration differs",
            )
        else:
            require(
                prefs["flags"] & 128
                and prefs["strings"][7:10] == [b"mothra-banner-b.gif", URL, b""],
                "Native Local banner configuration differs",
            )
    original = preferences(directory / manifest["original_preferences"])
    restored = preferences(directory / manifest["configurations"]["restored"])
    require(
        original["name"] == restored["name"] == b"",
        "Original empty name was not restored",
    )
    require(
        original["bytes"] == restored["bytes"],
        "Full native preference bytes were not restored",
    )
    agreement = (
        (directory / "original-agreement.data").read_bytes().replace(b"\r\n", b"\r")
    )
    require(len(agreement) == 242, "Original agreement length differs")
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    for group, inventory in [("setup", "setup_cases"), ("initial", "initial_cases")]:
        require(
            {p.name for p in (directory / group).iterdir()} == set(manifest[inventory]),
            "Login-extra auxiliary inventory differs",
        )
        for name in manifest[inventory]:
            root = directory / group / name
            verify_capture(root)
            report = json.loads((root / "report.json").read_text())
            if group == "setup":
                require(
                    report["status"] == "completed",
                    "Login-extra setup did not complete",
                )
            if group == "initial" and name == "name-change-90s-waiting-expired":
                check_failed_lifetime(report, host, guest)
            else:
                tails = {
                    k: bytes.fromhex(v)
                    for k, v in manifest["other_unread_output"]
                    .get(group + "/" + name, {})
                    .items()
                }
                reconcile(report, host, guest, tails)
    results = []
    for name, (steps, expected) in expected_cases.items():
        root = directory / "captures" / name
        verify_capture(root)
        plan = json.loads((root / "plan.json").read_text())
        report = json.loads((root / "report.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expected,
            "Retained login-extra plan differs",
        )
        require(report["status"] == "completed", "Login-extra case did not complete")
        check_quiet(report, plan)
        for action, step in enumerate(plan["steps"]):
            if step["op"] == "pause":
                pauses = [
                    e
                    for e in report["events"]
                    if e["action"] == action and e["event"] == "pause"
                ]
                previous = [e for e in report["events"] if e["action"] < action]
                require(
                    len(pauses) == 1
                    and pauses[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
                    >= step["seconds"] * 1e9,
                    "Login-extra pause was shorter than planned",
                )
        if expected["kind"] == "configured-login-extras":
            result = check_configured(report, expected, agreement)
        elif expected["kind"] == "login-name-lifetime":
            result = check_lifetime(report, agreement)
        else:
            result = check_downloads(report, agreement)
        tails = {
            k: bytes.fromhex(v)
            for k, v in manifest.get("unread_output", {}).get(name, {}).items()
        }
        result["case"] = name
        result["packets"] = reconcile(report, host, guest, tails)
        results.append(result)
    for root in (directory / "oracle-queries").glob("*.json"):
        query = json.loads(root.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"]["isError"],
            "Login-extra oracle query identity/error differs",
        )
    return {"cases": len(results), "results": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    print(f"Verified {result['cases']} configured login-extra and lifetime cases")


if __name__ == "__main__":
    main()
