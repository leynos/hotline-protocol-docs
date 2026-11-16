"""Replay the frozen C26 native settings corpus without a running Mac guest."""

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

from native_filp import decode, metadata
from native_packet_evidence import reconcile
from pcap_tcp import lifetime, read_packets, stream
from pinned_source import pinned_bytes
from protocol_capture import decode_frame, verify_capture
from verify_native_core import require
from verify_native_settings import semantic
from verify_native_settings import verify as verify_cases

RAW_INDEX_SHA = "f953f1146d5f89da3d33d1310c2364a56847514b23a9751daf0ceb2d2faa9b58"
ORACLE_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
DATA_SHA = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
RSRC_SHA = "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5"
FIELD_DIGESTS = {
    10: "9b50231527d14140c07f7a690db3f7feecf8428fb6181f3ee3711cbcfc2da958",
    11: "452607103fd8119ca4a71e733f62ebba8d7baa1f8da8962f753da24d877c0f1d",
    12: "1895a4d463c2be43ef6eb77fea5466fa47aaf82726138dee7a3c4a2da8c253a0",
    14: "ee9f3964d4dbfca175a3d9bbca42222f370dab0f92d51ae3ebeed3b0b12be56b",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reply(report: dict, identifier: int) -> dict:
    found = [
        f for f in report["frames"] if f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(
        len(found) == 1 and found[0]["error"] == 0, f"A7 reply {identifier} missing"
    )
    return found[0]


def values(frame: dict) -> dict[int, bytes]:
    return {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}


def a7_semantics(report: dict) -> dict:
    """Check full original A7 account, file, metadata, idle and fork controls."""
    require(
        report["status"] == "completed" and report["completed_actions"] == 29,
        "A7 29-action completion differs",
    )
    for identifier, prefix in FIELD_DIGESTS.items():
        fields = reply(report, identifier)["fields"]
        digest = sha(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode())
        require(digest == prefix, f"A7 field {identifier} baseline differs")
    require(len(reply(report, 11)["fields"]) == 41, "A7 Files count differs")
    require(values(reply(report, 12))[206] == b"MOTH", "A7 metadata creator differs")
    roster = reply(report, 13)["fields"]
    require(len(roster) == 1 and roster[0]["id"] == 300, "A7 admin roster differs")
    uid = bytes.fromhex(roster[0]["hex"])[:2]
    require(len(uid) == 2 and int.from_bytes(uid, "big") != 0, "A7 UID missing")
    require(
        reply(report, 14)["fields"] == reply(report, 17)["fields"],
        "A7 idle 303 changed",
    )
    ack = values(reply(report, 15))
    require(
        ack[108] == (1049073).to_bytes(4, "big")
        and ack[207] == (1048893).to_bytes(4, "big")
        and len(ack[107]) == 4,
        "A7 transfer advertisement differs",
    )
    require(reply(report, 16)["fields"] == [], "A7 transfer ACK differs")
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(len(transfer) == 1049073, "A7 FILP transfer length differs")
    forks = decode(transfer)
    require(
        sha(forks["DATA"]) == DATA_SHA and sha(forks["MACR"]) == RSRC_SHA,
        "A7 DATA/MACR fork differs",
    )
    info = metadata(forks["INFO"])
    require(
        (info["type"], info["creator"], info["name"], info["comment"])
        == (b"TEXT", b"MOTH", b"mothra-race-fixture", b"fixture-comment"),
        "A7 INFO metadata differs",
    )
    for action in (15, 26):
        sent = [
            e["hex"]
            for e in report["events"]
            if e["action"] == action and e["event"] == "send"
        ]
        require(
            len(sent) == 1 and sent[0].endswith(uid.hex()),
            "A7 same-connection UID differs",
        )
    return {"uid": uid.hex(), "accounts": 2, "files": 41, "filp_bytes": len(transfer)}


def a7_packets(report: dict, host: list[dict], guest: list[dict]) -> int:
    started = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
    paired = 0
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        name = event["connection"]
        source = tuple(event["local_address"])
        endpoint = tuple(event["peer_address"])
        when = int(started + event["elapsed_ns"] / 1000)
        for label, packets, client, server in [
            ("host", host, source, endpoint),
            (
                "guest",
                guest,
                ("10.0.2.2", source[1]),
                ("10.0.2.15", 5500 + endpoint[1] - 15500),
            ),
        ]:
            selected = lifetime(packets, client, server, when)
            require(
                stream(selected, client, server).hex()
                == report["streams"][name]["sent_hex"],
                f"A7 {name} {label} input differs",
            )
            require(
                stream(selected, server, client).hex()
                == report["streams"][name]["received_hex"],
                f"A7 {name} {label} output differs",
            )
        paired += 1
    require(paired == 2, "A7 paired socket count differs")
    return paired


def case_packets(
    raw: Path, results: list[dict], host: list[dict], guest: list[dict]
) -> int:
    retained = json.loads((raw / "packet-reconciliation.json").read_text())
    require(
        set(retained) == {r["case"] for r in results}, "Packet case inventory differs"
    )
    paired = 0
    for result in results:
        name = result["case"]
        report = json.loads((raw / "cases" / name / "report.json").read_text())
        started = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
        tails = {"host": {}, "guest": {}}
        for event in report["events"]:
            if event["event"] != "connect":
                continue
            connection = event["connection"]
            source = tuple(event["local_address"])
            endpoint = tuple(event["peer_address"])
            when = int(started + event["elapsed_ns"] / 1000)
            prefix = bytes.fromhex(report["streams"][connection]["received_hex"])
            for label, packets, client, server in [
                ("host", host, source, endpoint),
                (
                    "guest",
                    guest,
                    ("10.0.2.2", source[1]),
                    ("10.0.2.15", 5500 + endpoint[1] - 15500),
                ),
            ]:
                actual = stream(lifetime(packets, client, server, when), server, client)
                require(
                    actual.startswith(prefix), f"{name}: {label} output prefix differs"
                )
                tails[label][connection] = actual[len(prefix) :]
        require(
            tails["host"] == tails["guest"], f"{name}: host/guest unread tails differ"
        )
        require(
            set(tails["host"]) == {"main", "subject"},
            f"{name}: socket inventory differs",
        )
        require(tails["host"]["subject"] == b"", f"{name}: subject unread tail differs")
        tail = tails["host"]["main"]
        if tail:
            require(len(tail) == 28, f"{name}: unread tail length differs")
            frame = decode_frame(tail)
            require(
                frame["type"] == 302
                and values(frame) == {103: bytes.fromhex(result["subject_uid_hex"])},
                f"{name}: unread 302 differs",
            )
        recorded = retained[name]["tails"]
        require(
            all(
                recorded[c][label + "_hex"] == tails[label][c].hex()
                for c in tails["host"]
                for label in ("host", "guest")
            ),
            f"{name}: recorded tails differ",
        )
        reconcile(
            report, host, guest, tails["host"], guest_unread_output=tails["guest"]
        )
        paired += 2
    return paired


def inventory(raw: Path, manifest: dict) -> None:
    index = raw / "SHA256SUMS"
    require(
        sha(index.read_bytes()) == RAW_INDEX_SHA == manifest["raw_sha256sums_sha256"],
        "Frozen raw inventory identity differs",
    )
    entries = {}
    for line in index.read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(
            name not in entries
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts,
            "Unsafe raw inventory path",
        )
        entries[name] = digest
    require(
        set(entries)
        == {str(p.relative_to(raw)) for p in raw.rglob("*") if p.is_file()}
        - {"SHA256SUMS"},
        "Raw inventory coverage differs",
    )
    require(
        len(entries) + 1 == 73 == manifest["raw_file_count"], "Raw file count differs"
    )
    for name, digest in entries.items():
        require(
            sha((raw / name).read_bytes()) == digest, f"Raw file hash differs: {name}"
        )


def verify(bundle: Path) -> dict:
    raw = bundle / "raw"
    manifest = json.loads((bundle / "manifest.json").read_text())
    require(
        manifest["oracle_sha256"] == ORACLE_SHA and manifest["case_count"] == 10,
        "Manifest oracle/case identity differs",
    )
    source = json.loads((raw / "source/a7-plan.json").read_text())
    recorded = {
        Path(line.split()[1]).name: line.split()[0]
        for line in (raw / "source-hashes.txt").read_text().splitlines()[1:]
    }
    for name in (
        "native_settings_cases.py",
        "verify_native_settings.py",
        "protocol_capture.py",
    ):
        require(
            sha(pinned_bytes(name)) == recorded[name],
            f"Capture source differs: {name}",
        )
    for case in (raw / "cases").iterdir():
        if case.is_dir():
            plan = json.loads((case / "plan.json").read_text())
            semantic(
                json.loads((case / "report.json").read_text()), plan["expectation"]
            )
    results = verify_cases(raw / "cases")["cases"]
    host = read_packets(raw / "host.pcap")
    guest = read_packets(raw / "postflight/guest-cumulative.pcap")
    paired = case_packets(raw, results, host, guest)
    baselines = {}
    for phase in ("preflight", "postflight"):
        path = raw / phase
        plan = json.loads((path / "capture/plan.json").read_text())
        require(plan["steps"] == source["steps"], f"A7 {phase} immutable steps differ")
        baselines[phase] = a7_semantics(
            json.loads((path / "capture/report.json").read_text())
        )
        report = verify_capture(path / "capture")
        paired += a7_packets(
            report,
            read_packets(path / "host.pcap"),
            read_packets(path / "guest-cumulative.pcap"),
        )
    require(
        "3754 packets captured" in (raw / "recorder.log").read_text()
        and "0 packets dropped by kernel" in (raw / "recorder.log").read_text(),
        "Recorder counters differ",
    )
    require(
        "Result=success" in (raw / "recorder-terminal.txt").read_text()
        and "ExecMainStatus=0" in (raw / "recorder-terminal.txt").read_text(),
        "Recorder terminal status differs",
    )
    inventory(raw, manifest)
    return {
        "status": "verified",
        "cases": results,
        "a7": baselines,
        "paired_sockets": paired,
    }


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
