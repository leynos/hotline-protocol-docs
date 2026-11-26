#!/usr/bin/env python3
"""Verify A12's failed capture and its earlier positive 303 observation."""

import datetime
import hashlib
import json
import sys
from pathlib import Path

BATCH = Path(__file__).resolve().parent
MOTHRA = BATCH.parents[3]
sys.path.insert(0, str(MOTHRA.parent / "hotline-protocol-docs" / "scripts"))

from native_diagnostic_near_cases import ACTIVE_IDS, QUEUED_IDS
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_diagnostic,
    check_references,
    current_uid,
    require,
    section_witness,
    semantic,
    values,
)
from verify_native_diagnostic_near import expected_ids, sent_ids

A7 = (
    MOTHRA
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture"
)


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def guest_ack_tail(tail: bytes) -> dict:
    """Require the guest-only tail to be one successful cancellation acknowledgement and describe it."""
    require(len(tail) == 22, "Guest-only control tail is not one 22-byte ACK")
    frame = decode_frame(tail)
    require(
        frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["id"] == 207
        and frame["error"] == 0
        and frame["payload_hex"] == "0000",
        "Guest-only tail is not successful cancellation ACK 207",
    )
    return {"bytes": len(tail), "sha256": digest(tail), "frame": frame}


def packet_views(report: dict, filename: str, *, guest: bool) -> dict:
    """Reassemble each connection of a packet capture for the report."""
    start_us = int(
        datetime.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * 1_000_000
    )
    client, server, base = (
        ("10.0.2.2", "10.0.2.15", 5500) if guest else ("127.0.0.1", "127.0.0.1", 15500)
    )
    packets = read_packets(BATCH / filename)
    result = {}
    for event in (e for e in report["events"] if e["event"] == "connect"):
        name = event["connection"]
        port = event["local_address"][1]
        destination = base + (name != "a")
        selected = lifetime(
            packets,
            (client, port),
            (server, destination),
            start_us + event["elapsed_ns"] // 1000,
        )
        sent = stream(selected, (client, port), (server, destination))
        received = stream(selected, (server, destination), (client, port))
        recorder_sent = bytes.fromhex(report["streams"][name]["sent_hex"])
        recorder_received = bytes.fromhex(report["streams"][name]["received_hex"])
        require(sent == recorder_sent, f"{filename} {name} client stream differs")
        require(
            received.startswith(recorder_received),
            f"{filename} {name} recorder receive prefix differs",
        )
        terminal = [
            {
                "packet": packet["index"],
                "from_server": packet["src_port"] == destination,
                "flags": packet["flags"],
                "payload_hex": packet["payload_hex"],
            }
            for packet in selected
            if packet["flags"] & 5
        ]
        for packet in terminal:
            if packet["flags"] & 4 and packet["payload_hex"]:
                require(
                    bytes.fromhex(packet["payload_hex"])
                    in {b"No TCP", b"tcp_disconnect"},
                    "Unknown RST diagnostic payload",
                )
        tail = received[len(recorder_received) :]
        result[name] = {
            "local_port": port,
            "packet_count": len(selected),
            "sent_bytes": len(sent),
            "received_bytes": len(received),
            "recorder_received_bytes": len(recorder_received),
            "unread_tail_bytes": len(tail),
            "unread_tail_sha256": digest(tail),
            "terminal_packets": terminal,
            "_sent": sent,
            "_received": received,
            "_tail": tail,
        }
    return result


def public_view(view: dict) -> dict:
    """Remove the private reassembled streams from a packet view."""
    return {
        name: {key: value for key, value in item.items() if not key.startswith("_")}
        for name, item in view.items()
    }


def check_plan_identity(report: dict) -> dict:
    """Require the prepared, executed and captured plans and the reported plan hash to agree."""
    prepared = json.loads((BATCH / "near-prepared-plan.json").read_text())
    executed = json.loads((BATCH / "near-execution-plan.json").read_text())
    require(
        {key: value for key, value in prepared.items() if key != "operator"}
        == {key: value for key, value in executed.items() if key != "operator"},
        "Execution plan differs beyond operator metadata",
    )
    require(
        executed == json.loads((BATCH / "near/plan.json").read_text()),
        "Captured plan differs",
    )
    require(
        report["plan_sha256"] == digest((BATCH / "near/plan.json").read_bytes()),
        "Reported plan hash differs",
    )
    return {
        "prepared_sha256": digest((BATCH / "near-prepared-plan.json").read_bytes()),
        "execution_sha256": digest((BATCH / "near-execution-plan.json").read_bytes()),
        "only_changed_key": "operator",
    }


def check_partial(report: dict, host: dict, guest: dict, full: bytes) -> dict:
    """Check that the near capture failed where it was recorded to fail and that its prefix is as planned."""
    require(report["status"] == "failed", "Near capture is not the saved failure")
    require(report["completed_actions"] == 94, "Failure action differs")
    require(
        report["error"] == "EOFError: EOF before 20 requested bytes", "Failure differs"
    )
    ids = sent_ids(report)
    require(
        ids == expected_ids()[: len(ids)] and ids[-1] == 207,
        "Sent request prefix differs",
    )
    uid = current_uid(report)
    references = check_references(report, list(ACTIVE_IDS), list(QUEUED_IDS))
    require(
        references["waiting_positions"] == list(range(1, 17)), "Queue positions differ"
    )
    diagnostics = {str(i): check_diagnostic(report, i, uid) for i in (140, 141)}
    witnesses = {
        "140": section_witness(bytes.fromhex(diagnostics["140"]["field101_hex"]), 8, 8),
        "141": section_witness(
            bytes.fromhex(diagnostics["141"]["field101_hex"]), 8, 16
        ),
    }
    require(
        all(w["status"] == "complete" for w in witnesses.values()),
        "303 rows incomplete",
    )
    require(
        [diagnostics[str(i)]["field101_bytes"] for i in (140, 141)] == [763, 995],
        "303 lengths differ",
    )
    saved = [bytes.fromhex(ref) for ref in references["references"]]
    check_cancellations(report, {200 + i: saved[8 + i] for i in range(8, 16)})
    sent_207 = [
        decode_frame(bytes.fromhex(e["hex"]))
        for e in report["events"]
        if e["event"] == "send"
        and e["connection"] == "a"
        and bytes.fromhex(e["hex"])[4:8] == (207).to_bytes(4, "big")
    ]
    require(
        len(sent_207) == 1
        and sent_207[0]["type"] == 214
        and values(sent_207[0]) == {107: saved[15]},
        "Unacknowledged cancellation 207 targeted another reference",
    )
    require(
        [f["id"] for f in report["frames"] if f["is_reply"] and 200 <= f["id"] <= 227]
        == list(range(215, 207, -1)),
        "Recorder-confirmed cancellation ACKs differ",
    )
    require(
        not any(f["id"] == 240 for f in report["frames"]),
        "Idle 303 unexpectedly reached",
    )
    require(
        set(host) == {"a", *(f"active{i}" for i in range(8))}
        and set(guest) == set(host),
        "Socket set differs",
    )
    control_host, control_guest = host["a"], guest["a"]
    require(
        (control_host["sent_bytes"], control_host["received_bytes"]) == (1514, 3617)
        and (control_guest["sent_bytes"], control_guest["received_bytes"])
        == (1514, 3639),
        "Control lengths differ",
    )
    require(
        control_host["_received"]
        == bytes.fromhex(report["streams"]["a"]["received_hex"]),
        "Host control differs",
    )
    require(
        control_guest["_received"].startswith(control_host["_received"]),
        "Guest control prefix differs",
    )
    tail = guest_ack_tail(control_guest["_tail"])
    require(not control_host["_tail"], "Host control has unread tail")
    require(
        any(
            p["flags"] & 4 and not p["from_server"]
            for p in control_guest["terminal_packets"]
        ),
        "Guest-side client RST absent",
    )
    require(
        all(
            not p["payload_hex"]
            for p in control_guest["terminal_packets"]
            + control_host["terminal_packets"]
        ),
        "Unexpected control terminal payload",
    )
    for index in range(8):
        name = f"active{index}"
        expected = b"HTXF" + saved[index] + bytes(8)
        left, right = host[name], guest[name]
        require(left["_sent"] == right["_sent"] == expected, f"{name} HTXF differs")
        require(
            not left["recorder_received_bytes"]
            and not right["recorder_received_bytes"]
            and 0 < len(left["_received"]) <= len(right["_received"])
            and right["_received"].startswith(left["_received"])
            and full.startswith(right["_received"]),
            f"{name} unread FILP prefix differs",
        )
    return {
        "status": "positive-partial-observation; capture-failed",
        "failed_action": 94,
        "error": report["error"],
        "references": references["references"],
        "queued_positions": references["waiting_positions"],
        "field101_bytes": {
            key: value["field101_bytes"] for key, value in diagnostics.items()
        },
        "witnesses": witnesses,
        "recorder_confirmed_cancel_ack_ids": list(range(215, 207, -1)),
        "guest_only_cancel_ack_207": tail,
        "missing_later_cancel_and_idle": True,
    }


def main() -> None:
    """Verify the partial near capture and the restored postflight against the baseline."""
    near = verify_capture(BATCH / "near")
    near["_plan_path"] = BATCH / "near/plan.json"
    postflight = verify_capture(BATCH / "postflight")
    postflight["_plan_path"] = BATCH / "postflight/plan.json"
    baseline = verify_capture(A7)
    restored = semantic("postflight", postflight, baseline)
    require(restored["status"] == "verified", "Restored postflight differs")
    full = bytes.fromhex(baseline["streams"]["download"]["received_hex"])
    require(len(full) == 1_049_073 and full.startswith(b"FILP\0\1"), "A7 FILP differs")
    host = packet_views(near, "host-near.pcap", guest=False)
    guest = packet_views(near, "guest-after-near-failure.pcap", guest=True)
    post_host = packet_views(postflight, "host-postflight.pcap", guest=False)
    post_guest = packet_views(postflight, "guest-after-postflight.pcap", guest=True)
    require(set(post_host) == set(post_guest) == {"a"}, "Postflight socket set differs")
    for view in (post_host, post_guest):
        require(
            view["a"]["_received"]
            == bytes.fromhex(postflight["streams"]["a"]["received_hex"]),
            "Postflight control differs",
        )
    result = {
        "plan_identity": check_plan_identity(near),
        "near": check_partial(near, host, guest, full),
        "postflight": restored,
        "packet_views": {
            "host_near": public_view(host),
            "guest_near": public_view(guest),
            "host_postflight": public_view(post_host),
            "guest_postflight": public_view(post_guest),
        },
        "scope": "Failed capture with positive pre-failure 303 reply; transport cause unknown",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
