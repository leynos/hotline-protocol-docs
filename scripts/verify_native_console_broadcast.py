#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from verify_mac_peer_first_session import field_map, parse_frames, require
from verify_native_account_updates import enumeration
from verify_native_mkdir import listing
from verify_native_resume import reply

NAMES = ("ConsoleSender", "ConsoleRefuse", "ConsoleWaiting", "ConsoleUnauth")
TEXT_CONSOLE = b"D1-console-message"
TEXT_BEFORE = b"D1-client-before"
TEXT_AFTER = b"D1-client-after"


def check_inventory(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["status"] == "bounded-native-console-broadcast", "Bad manifest")
    for name, expected in manifest["files"].items():
        require(
            hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
            f"File SHA differs: {name}",
        )


def delta(path_before: Path, path_after: Path, temp: Path) -> Path:
    before, after = path_before.read_bytes(), path_after.read_bytes()
    require(
        after.startswith(before) and len(after) > len(before),
        "Guest PCAP append boundary differs",
    )
    result = temp / (path_after.stem + "-delta.pcap")
    result.write_bytes(before[:24] + after[len(before) :])
    return result


def connection(report: dict, name: str) -> tuple[int, bytes, bytes]:
    events = [
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == name
    ]
    require(len(events) == 1, f"Connection witness differs: {name}")
    port = events[0]["local_address"][1]
    streams = report["streams"][name]
    return (
        port,
        bytes.fromhex(streams["sent_hex"]),
        bytes.fromhex(streams["received_hex"]),
    )


def packets_for(
    packets: list[dict], src: tuple[str, int], dst: tuple[str, int]
) -> tuple[list[dict], bytes, bytes]:
    syns = [
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == src
        and (p["dst_ip"], p["dst_port"]) == dst
        and p["flags"] & 2
        and not p["flags"] & 16
    ]
    require(len(syns) == 1, "SYN lifetime differs")
    selected = lifetime(packets, src, dst, syns[0]["timestamp_us"])
    return selected, stream(selected, src, dst), stream(selected, dst, src)


def partial(packets: list[dict], src: tuple[str, int], dst: tuple[str, int]) -> bytes:
    """Reassemble a known missing-SYN direction from its first retained byte."""
    chunks = [
        (p["sequence"], bytes.fromhex(p["payload_hex"]))
        for p in packets
        if (p["src_ip"], p["src_port"]) == src
        and (p["dst_ip"], p["dst_port"]) == dst
        and p["payload_hex"]
        and not p["flags"] & 4
    ]
    require(bool(chunks), "Empty partial host stream")
    start = min(seq for seq, _ in chunks)
    result = bytearray()
    for seq, data in sorted(chunks):
        offset = seq - start
        require(0 <= offset <= len(result), "Partial host TCP sequence gap")
        overlap = min(len(result) - offset, len(data))
        require(
            result[offset : offset + overlap] == data[:overlap],
            "Partial host overlap differs",
        )
        result.extend(data[overlap:])
    return bytes(result)


def check_tail(raw: bytes, expected_id: int) -> None:
    frames = parse_frames(raw)
    require(len(frames) == 1, "Teardown tail frame count differs")
    frame = frames[0]
    require(
        (frame["flags"], frame["is_reply"], frame["type"], frame["id"], frame["error"])
        == (0, 0, 302, expected_id, 0)
        and field_map(frame) == {103: b"\x00\x12"},
        "Teardown tail differs",
    )


def check_frames(report: dict) -> dict:
    expected_out = {
        "ConsoleSender": [107, 355, 355],
        "ConsoleRefuse": [107],
        "ConsoleWaiting": [107, 121],
        "ConsoleUnauth": [],
    }
    expected_in = {
        "ConsoleSender": [0, 354, 109, 301, 0, 104, 301, 0],
        "ConsoleRefuse": [0, 354, 109, 355, 104, 301, 355],
        "ConsoleWaiting": [0, 109, 0, 354, 122, 355],
        "ConsoleUnauth": [],
    }
    for name in NAMES:
        _, sent, received = connection(report, name)
        require(
            sent.startswith(bytes.fromhex("54525450484f544c00010002")),
            "Handshake request differs",
        )
        require(
            received.startswith(bytes.fromhex("5452545000000000")),
            "Handshake reply differs",
        )
        outbound = parse_frames(sent[12:])
        inbound = parse_frames(received[8:])
        require(
            [f["type"] for f in outbound] == expected_out[name],
            f"Outbound frame sequence differs: {name}",
        )
        require(
            [f["type"] for f in inbound] == expected_in[name],
            f"Inbound frame sequence differs: {name}",
        )
        require(all(f["error"] == 0 for f in inbound), "Unexpected frame status")
        if name == "ConsoleSender":
            require(
                [field_map(f) for f in outbound[1:]]
                == [{101: TEXT_BEFORE}, {101: TEXT_AFTER}],
                "Client broadcast requests differ",
            )
            require(
                all(
                    f["is_reply"] == 1 and f["id"] == identifier
                    for f, identifier in zip(
                        (inbound[4], inbound[7]), (2, 3), strict=True
                    )
                ),
                "Sender 355 ACK differs",
            )
        if name == "ConsoleWaiting":
            require(
                field_map(outbound[1]) == {102: b"ConsoleWaiting", 104: b"\x00\x01"},
                "Waiting activation differs",
            )
        if name == "ConsoleRefuse":
            require(field_map(outbound[0])[113] == b"\x00\x03", "Refuse options differ")
        if name != "ConsoleUnauth":
            require(
                field_map(outbound[0]).get(102, b"")
                == (name.encode() if name != "ConsoleWaiting" else b""),
                "Client name/state differs",
            )
    sender, refuse, waiting = [
        parse_frames(bytes.fromhex(report["streams"][n]["received_hex"])[8:])
        for n in NAMES[:3]
    ]
    for frame in (sender[5], refuse[4]):
        require(
            frame["type"] == 104 and field_map(frame) == {101: TEXT_CONSOLE},
            "Console 104 is not data-only",
        )
    for frame, text in (
        (refuse[3], TEXT_BEFORE),
        (refuse[6], TEXT_AFTER),
        (waiting[5], TEXT_AFTER),
    ):
        fields = field_map(frame)
        require(
            frame["type"] == 355
            and set(fields) == {101, 102, 103}
            and fields[101] == text
            and fields[102] == b"ConsoleSender"
            and len(fields[103]) == 2,
            "355 sender fields differ",
        )
    require(
        field_map(refuse[3])[103]
        == field_map(refuse[6])[103]
        == field_map(waiting[5])[103],
        "355 sender UID differs",
    )
    require(all(f["type"] != 355 for f in sender), "Self-recipient 355 appeared")
    require(
        all(f["type"] not in (104, 355) for f in waiting[:5]),
        "Waiting peer received early broadcast",
    )
    return {
        "sender_uid_hex": field_map(refuse[3])[103].hex(),
        "console_104_recipients": ["ConsoleSender", "ConsoleRefuse"],
        "before_355_recipients": ["ConsoleRefuse"],
        "after_355_recipients": ["ConsoleRefuse", "ConsoleWaiting"],
    }


def check_capture(root: Path, report: dict) -> dict:
    before = root / "guest-before.pcap"
    after = root / "guest-after.pcap"
    with TemporaryDirectory() as temporary:
        guest = read_packets(delta(before, after, Path(temporary)))
    host = read_packets(root / "host.pcap")
    require(
        len([p for p in guest if p["flags"] & 2 and not p["flags"] & 16]) == 4,
        "Guest connection count differs",
    )
    require(
        len([p for p in host if p["flags"] & 2 and not p["flags"] & 16]) == 3,
        "Host missing-SYN scope differs",
    )
    for name, tail_id in zip(NAMES, (6, 7, 5, None), strict=True):
        port, sent, received = connection(report, name)
        guest_src, guest_dst = ("10.0.2.2", port), ("10.0.2.15", 5500)
        host_src, host_dst = ("127.0.0.1", port), ("127.0.0.1", 15500)
        _, go, gi = packets_for(guest, guest_src, guest_dst)
        require(
            go == sent and gi.startswith(received), f"Guest/report bytes differ: {name}"
        )
        tail = gi[len(received) :]
        if tail_id is None:
            require(not tail, "Unauthenticated teardown tail differs")
        else:
            check_tail(tail, tail_id)
        if name == "ConsoleSender":
            require(
                partial(host, host_src, host_dst) == sent[12:],
                "Host sender suffix differs",
            )
            require(
                partial(host, host_dst, host_src) == gi, "Host sender inbound differs"
            )
        else:
            _, ho, hi = packets_for(host, host_src, host_dst)
            require((ho, hi) == (go, gi), f"Host/guest bytes differ: {name}")
    require(
        report["status"] == "completed" and report["completed_actions"] == 50,
        "D1 action completion differs",
    )
    return {
        "guest_connections": 4,
        "host_complete_connections": 3,
        "host_sender_missing": "SYN and 12-byte handshake",
        "teardown_tails": "three full 302 frames retained",
    }


def check_postflight(root: Path) -> dict:
    post = verify_capture(root / "postflight")
    base = verify_capture(root / "baseline")
    require(
        post["status"] == "completed" and post["completed_actions"] == 29,
        "Postflight incomplete",
    )
    require(
        json.loads((root / "postflight/plan.json").read_text())["expectation"]
        == json.loads((root / "baseline/plan.json").read_text())["expectation"],
        "Postflight expectation differs",
    )
    for identifier in (10, 11, 12, 14, 16, 17):
        require(
            reply(post, identifier)["fields"] == reply(base, identifier)["fields"],
            f"A7 baseline changed: {identifier}",
        )
    require(len(enumeration(reply(post, 10))) == 2, "Account count differs")
    require(len(listing(reply(post, 11))) == 41, "Files root count differs")
    require(
        post["streams"]["download"]["received_hex"]
        == base["streams"]["download"]["received_hex"],
        "Full fixture stream changed",
    )
    with TemporaryDirectory() as temporary:
        guest = read_packets(
            delta(
                root / "guest-after.pcap",
                root / "guest-postflight.pcap",
                Path(temporary),
            )
        )
    require(
        len([p for p in guest if p["flags"] & 2 and not p["flags"] & 16]) == 2,
        "Postflight guest connection count differs",
    )
    for name, destination in (("a", 5500), ("download", 5501)):
        port, sent, received = connection(post, name)
        _, out, inbound = packets_for(
            guest, ("10.0.2.2", port), ("10.0.2.15", destination)
        )
        require(
            (out, inbound) == (sent, received),
            f"Postflight guest/report bytes differ: {name}",
        )
    return {
        "status": "restored-a7-baseline",
        "accounts": 2,
        "files_root": 41,
        "download_bytes": 1_049_073,
    }


def verify(root: Path) -> dict:
    check_inventory(root)
    report = verify_capture(root / "capture")
    require(
        report["oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "Oracle identity differs",
    )
    require(
        json.loads((root / "operator-actions.json").read_text())["result"].startswith(
            "Exactly one console send"
        ),
        "Operator scope differs",
    )
    return {
        "status": "verified-finite-native-console-broadcast",
        "frames": check_frames(report),
        "capture": check_capture(root, report),
        "postflight": check_postflight(root),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
