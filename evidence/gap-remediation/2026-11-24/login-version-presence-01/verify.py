"""Replay the four login cases against the isolated loopback and guest streams."""

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, verify_capture
from protocol_capture_decode import decode_frame

ROOT = Path(__file__).resolve().parent
VERSIONS = {
    "version-absent": [],
    "version-empty": [""],
    "version-one-zero": ["00"],
    "version-two-zero": ["0000"],
}
COMMIT = "e1474a19ad21687e10f75d0af34375161edd0fb3"


def require(condition: bool, message: str) -> None:
    """Reject a comparison whose measured inputs differ."""
    if not condition:
        raise ValueError(message)


def load(name: str | Path) -> Any:
    """Read one retained JSON record."""
    return json.loads((ROOT / name).read_text())


def replay() -> None:
    """Check identity, field encodings, packet streams and the recorder identities."""
    manifest = load("manifest.json")
    require(manifest["planner_commit"] == COMMIT, "different planner")
    require(
        set(manifest["cases"])
        == set(VERSIONS)
        == {p.name for p in (ROOT / "captures").iterdir()},
        "case inventory",
    )
    env = load("environment.json")
    forks = manifest["installed_forks"]
    require(
        forks["data_sha256"]
        == ORACLE_SHA256
        == env["application"]["HLserver19"]["sha256"],
        "native data fork",
    )
    require(
        forks["resource_sha256"]
        == env["application"][".rsrc/HLserver19"]["sha256"]
        == "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
        "native resource fork",
    )
    require(
        forks["disk_fuser_exit"] == 1 and forks["disk_fuser_output_bytes"] == 0,
        "stopped disk",
    )
    require(
        all(
            v == ["ActiveState=inactive", "MainPID=0"]
            for v in manifest["retirement"].values()
        ),
        "retirement",
    )
    require(
        load("ns-route.json") == []
        and [i["ifname"] for i in load("ns-addr.json")] == ["lo"],
        "namespace isolation",
    )
    require(
        (ROOT / "host.pcap").stat().st_size == 24
        and not read_packets(ROOT / "host.pcap"),
        "host control",
    )
    packets = [read_packets(ROOT / name) for name in ("namespace.pcap", "guest.pcap")]
    recorded = {
        r["case"]: r
        for r in map(
            json.loads, (ROOT / "stream-comparison.jsonl").read_text().splitlines()
        )
    }
    require(set(recorded) == set(VERSIONS), "stream inventory")
    gates = {k: v["receipt"] for k, v in load("readiness.json").items()}
    baseline = None
    for case, values in VERSIONS.items():
        capture = ROOT / "captures" / case
        verify_capture(capture)
        plan, report = (load(capture / name) for name in ("plan.json", "report.json"))
        require(
            plan["environment"] == env and plan["gap_ids"] == ["GAP-016"],
            "case environment",
        )
        ident = report["driver_identity"]
        require(
            report["status"] == "completed"
            and report["oracle_sha256"] == ORACLE_SHA256
            and ident["commit"] == COMMIT
            and ident["dirty"] == [],
            "capture identity",
        )
        (sent,) = [
            e for e in report["events"] if e["action"] == 3 and e["event"] == "send"
        ]
        require(sent["hex"] == plan["steps"][3]["hex"], "planned login bytes")
        request = decode_frame(bytes.fromhex(sent["hex"]))
        require(
            request["type"] == 107 and request["id"] == 1 and not request["is_reply"],
            "login request",
        )
        fields = request["fields"]
        require(
            [f["hex"] for f in fields if f["id"] == 160] == values, "version encoding"
        )
        other = [f for f in fields if f["id"] != 160]
        require([f["id"] for f in other] == [106, 105], "credential fields")
        if baseline is None:
            baseline = other
        require(other == baseline, "different credentials")
        (reply,) = report["frames"]
        require(
            (reply["type"], reply["is_reply"], reply["id"], reply["error"])
            == (0, 1, 1, 0),
            "reply correlation",
        )
        require(
            [(f["id"], f["hex"]) for f in reply["fields"]]
            == [(160, "00be"), (161, "0000")],
            "reply fields",
        )
        (event,) = [e for e in report["events"] if e["event"] == "connect"]
        client = tuple(event["local_address"])
        server = tuple(event["peer_address"])
        require(
            client[0] == "127.0.0.1" and server == ("127.0.0.1", 16140),
            "socket endpoints",
        )
        connect_us = int(
            dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
            + event["elapsed_ns"] / 1000
        )
        sent_bytes = bytes.fromhex(report["streams"]["main"]["sent_hex"])
        consumed = bytes.fromhex(report["streams"]["main"]["received_hex"])
        require(
            len(consumed) == recorded[case]["consumed"] == 42, "driver read boundary"
        )
        for label, view, src, dst in (
            ("loopback", packets[0], client, server),
            ("guest", packets[1], ("10.0.2.2", client[1]), ("10.0.2.15", 5500)),
        ):
            flow = lifetime(view, src, dst, connect_us)
            require(stream(flow, src, dst) == sent_bytes, "wire request stream")
            response = stream(flow, dst, src)
            expected = recorded[case]["views"][label]
            require(
                len(response) == expected["received_bytes"] == 310
                and response.startswith(consumed),
                "wire response stream",
            )
            require(
                hashlib.sha256(response).hexdigest()
                == expected["received_sha256"]
                == "30de9b2d16cf5a8efeb3856630698bd7a42b7bd6bbbd6377893c62f2c390a105",
                "response differs",
            )
            tail = response[len(consumed) :]
            require(tail.hex() == expected["unread_hex"], "unread bytes")
            agreement = decode_frame(tail)
            require(
                agreement["type"] == 109
                and not agreement["is_reply"]
                and not agreement["unconsumed_hex"]
                and [f["id"] for f in agreement["fields"]] == [101],
                "unread agreement",
            )
        for suffix, reference in (
            ("guest", "guest-ready.json"),
            ("namespace", "namespace-ready.json"),
            ("host", "host-ready.json"),
        ):
            gate = gates[f"{case}-{suffix}-gate.json"]
            first = gates[reference]
            require(
                all(
                    gate[k] == first[k]
                    for k in ("pid", "start_ticks", "netns_inode", "deadline_utc")
                ),
                "readiness identity",
            )
    print("Verified four same-account login version cases at both packet boundaries")


if __name__ == "__main__":
    replay()
