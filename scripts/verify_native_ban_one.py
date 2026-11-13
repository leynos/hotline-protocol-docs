#!/usr/bin/env python3
"""Replay the disposable native option-one ban witness from frozen files."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from native_filp import decode, metadata
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture

BASE_PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
SOURCE_DISK_SHA = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM_SHA = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
APP_DATA_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
APP_RSRC_SHA = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
NOTICE = b"You are temporarily banned on this server."


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loaded(path: Path) -> dict:
    return json.loads(path.read_text())


# fmt: off
def frame(report: dict, connection: str, identifier: int) -> dict:
    matches = [item for item in report["frames"] if item["connection"] == connection and item["is_reply"] == 1 and item["id"] == identifier]
    need(len(matches) == 1, f"Reply {connection}/{identifier} missing or repeated")
    return matches[0]


def fields(item: dict) -> dict[int, bytes]:
    return {entry["id"]: bytes.fromhex(entry["hex"]) for entry in item["fields"]}


def inventory(corpus: Path) -> dict:
    manifest = loaded(corpus / "manifest.json")
    need(manifest["schema"] == "native-ban-one-01", "Manifest schema differs")
    expected = manifest["files"]
    actual = {str(path.relative_to(corpus)) for path in corpus.rglob("*") if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}}
    need(actual == set(expected), "Corpus file inventory differs")
    for name, sha in expected.items():
        need(digest(corpus / name) == sha, f"Corpus SHA differs: {name}")
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    need(
        lines == [f"{sha}  {name}" for name, sha in sorted(expected.items())],
        "SHA256SUMS differs from manifest",
    )
    return manifest


def verify_a7(corpus: Path, mothra: Path) -> dict:
    fixture = corpus / "fixture"
    original = loaded(fixture / "a7-original-plan.json")
    plan = loaded(fixture / "a7-as-run-plan.json")
    need(
        digest(fixture / "a7-original-plan.json") == BASE_PLAN_SHA,
        "A7 plan source differs",
    )
    for key in original.keys() - {"environment", "endpoints"}:
        need(original[key] == plan[key], f"A7 {key} changed")
    need(len(plan["steps"]) == 29, "A7 action count differs")
    need(
        plan["endpoints"]
        == {"control": {"host": "127.0.0.1", "port": 15720}, "data": {"host": "127.0.0.1", "port": 15721}},
        "A7 lab endpoints differ",
    )
    report = verify_capture(fixture / "a7-capture")
    need(
        report["status"] == "completed" and report["completed_actions"] == 29,
        "A7 incomplete",
    )
    reference = loaded(corpus / "reference/diagnostic-preflight-report.json")
    for identifier in (10, 11):
        value = frame(report, "a", identifier)
        need(
            value["error"] == 0 and value["fields"] == frame(reference, "a", identifier)["fields"],
            f"A7 baseline reply {identifier} differs",
        )
    need(len(frame(report, "a", 11)["fields"]) == 41, "A7 Files count differs")
    info = fields(frame(report, "a", 12))
    need(
        {key: info[key] for key in (201, 205, 206, 207, 213)}
        == {201: b"mothra-race-fixture", 205: b"Text File", 206: b"MOTH", 207: bytes.fromhex("0010013d"), 213: b"TEXT"},
        "A7 metadata differs",
    )
    need(
        frame(report, "a", 14)["fields"] == frame(report, "a", 17)["fields"],
        "A7 idle 303 changed",
    )
    ack = fields(frame(report, "a", 15))
    need(
        ack[108] == (1049073).to_bytes(4, "big") and ack[207] == (1048893).to_bytes(4, "big"),
        "A7 fork sizes differ",
    )
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    need(len(transfer) == 1049073, "A7 FILP length differs")
    forks = decode(transfer)
    old = mothra / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
    need(
        forks["DATA"] == (old / "mothra-race-fixture.data").read_bytes(),
        "A7 DATA differs",
    )
    need(
        forks["MACR"] == (old / "mothra-race-fixture.rsrc").read_bytes(),
        "A7 RSRC differs",
    )
    meta = metadata(forks["INFO"])
    need(
        (meta["type"], meta["creator"], meta["name"], meta["comment"]) == (b"TEXT", b"MOTH", b"mothra-race-fixture", b"fixture-comment"),
        "A7 INFO differs",
    )
    return {"actions": 29, "accounts": 2, "files": 41, "filp_bytes": len(transfer)}


def verify_ban(corpus: Path) -> dict:
    fixture = corpus / "fixture"
    reports = {name: verify_capture(fixture / f"{name}-capture") for name in ("guard", "seed", "ban-opt1", "probe")}
    for name in ("guard", "seed", "ban-opt1"):
        report = reports[name]
        need(
            report["status"] == "completed" and report["completed_actions"] == len(loaded(fixture / f"{name}.json")["steps"]),
            f"{name} incomplete",
        )
    need(
        frame(reports["guard"], "main", 30)["error"] == 1,
        "Owned account was not absent",
    )
    need(frame(reports["seed"], "main", 31)["error"] == 0, "Owned account seed failed")
    created = frame(reports["seed"], "main", 32)
    need(
        created["error"] == 0 and fields(created)[110] == bytes(8),
        "Owned account is not unprotected and zero privilege",
    )
    ban = reports["ban-opt1"]
    for connection in ("main", "target"):
        need(frame(ban, connection, 1)["error"] == 0, f"{connection} login failed")
    updates = [item for item in ban["frames"] if item["connection"] == "main" and item["type"] == 301]
    need(len(updates) == 1 and updates[0]["is_reply"] == 0, "Dynamic target 301 differs")
    uid = fields(updates[0])[103]
    need(len(uid) == 2 and uid != b"\0\0", "Dynamic target UID invalid")
    sends = [bytes.fromhex(event["hex"]) for event in ban["events"] if event["event"] == "send" and len(event["hex"]) >= 40 and int(event["hex"][4:8], 16) == 110]
    need(len(sends) == 1, "110 must be sent exactly once")
    request = decode_frame(sends[0])
    need(
        request["id"] == 33 and fields(request) == {103: uid, 113: b"\0\x01"},
        "110 target or option differs",
    )
    notices = [item for item in ban["frames"] if item["connection"] == "target" and item["type"] == 104]
    need(
        len(notices) == 1 and notices[0]["is_reply"] == 0 and fields(notices[0]) == {101: NOTICE},
        "Option-one 104 notice differs",
    )
    need(
        any(event["connection"] == "target" and event["event"] == "eof" for event in ban["events"]),
        "Target EOF missing",
    )
    need(frame(ban, "main", 33)["error"] == 0, "Ban ACK failed")
    probe = reports["probe"]
    need(
        probe["status"] == "failed" and probe["completed_actions"] == 2 and probe["error"] == "TimeoutError: timed out",
        "Probe failure was recast",
    )
    observed = [(event["event"], event["hex"]) for event in probe["events"]]
    need(
        observed
        == [("connect", ""), ("send", "54525450484f544c00010002"), ("receive", "5452545000000000"), ("close", "")],
        "Probe prefix differs or login was attempted",
    )
    return {
        "target_uid_hex": uid.hex(),
        "notice_hex": NOTICE.hex(),
        "probe": "failed_after_successful_handshake_before_login",
    }


def verify_packets(corpus: Path, uid: bytes) -> None:
    boot = corpus / "boot"
    host = read_packets(boot / "primary-host.pcap")
    namespace = read_packets(boot / "lab-namespace.pcap")
    need(not host, "Primary host recorder has packets")
    need(
        not [packet for packet in namespace if packet["src_port"] in {15500, 15501} or packet["dst_port"] in {15500, 15501}],
        "Lab touched primary relay",
    )
    need(
        "0 packets dropped by kernel" in (boot / "ns-recorder.log").read_text(),
        "Namespace packet drops unknown",
    )
    need(
        "0 packets dropped by kernel" in (boot / "host-recorder.log").read_text(),
        "Host packet drops unknown",
    )
    report = loaded(corpus / "fixture/ban-opt1-capture/report.json")
    start_us = int(dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000)
    frozen = loaded(corpus / "fixture/ban-stream-views.json")
    for label, packets, client, server, port in (
        ("namespace", namespace, "127.0.0.1", "127.0.0.1", 15720),
        ("guest", read_packets(boot / "lab-guest.pcap"), "10.0.2.2", "10.0.2.15", 5500),
    ):
        for event in report["events"]:
            if event["event"] != "connect":
                continue
            name = event["connection"]
            local = event["local_address"][1]
            packets_for_socket = lifetime(
                packets,
                (client, local),
                (server, port),
                start_us + event["elapsed_ns"] // 1000,
            )
            received = stream(packets_for_socket, (server, port), (client, local))
            sent = stream(packets_for_socket, (client, local), (server, port))
            view = frozen[label][name]
            need(
                view["local_port"] == local and view["sent_sha256"] == hashlib.sha256(sent).hexdigest() and view["received_sha256"] == hashlib.sha256(received).hexdigest(),
                f"{label}/{name} packet view differs",
            )
            if name == "main":
                need(
                    received[398:420] == bytes.fromhex("00010000000000210000000000000002000000020000"),
                    "ACK bytes before 302 differ",
                )
                notification = decode_frame(received[420:])
                need(
                    notification["type"] == 302 and notification["id"] == 4 and notification["is_reply"] == 0 and fields(notification) == {103: uid},
                    "302 after ACK differs",
                )
                need(
                    [(entry["type"], entry["id"], entry["fields"]) for entry in view["frames"][-2:]] == [(0, 33, []), (302, 4, notification["fields"])],
                    "Frozen ACK/302 view differs",
                )
            else:
                closing_flag = 1 if label == "namespace" else 4
                need(
                    any(packet["src_port"] == port and packet["flags"] & closing_flag for packet in packets_for_socket),
                    f"{label} target server close missing",
                )


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    mothra = corpus.parents[3]
    prep = loaded(corpus / "preparation/postflight.json")
    need(
        prep["source_after"]["sha256"] == SOURCE_DISK_SHA and prep["target_base"]["sha256"] == SOURCE_DISK_SHA and prep["target_working"]["sha256"] == SOURCE_DISK_SHA,
        "Prepared disk provenance differs",
    )
    need(
        prep["rom_after"]["sha256"] == ROM_SHA and prep["target_rom"]["sha256"] == ROM_SHA,
        "ROM provenance differs",
    )
    extracted = loaded(corpus / "preparation/preboot-app/extraction.json")
    need(
        len(extracted["records"]) == 1 and extracted["records"][0]["path"] == "/Hotline19/HLserver19",
        "App catalogue differs",
    )
    need(
        digest(corpus / "preparation/preboot-app/catalog-11183.data") == APP_DATA_SHA and digest(corpus / "preparation/preboot-app/catalog-11183.rsrc") == APP_RSRC_SHA,
        "App forks differ",
    )
    a7 = verify_a7(corpus, mothra)
    ban = verify_ban(corpus)
    verify_packets(corpus, bytes.fromhex(ban["target_uid_hex"]))
    terminal = loaded(corpus / "fixture/terminal.json")
    need(
        not terminal["processes"]["lab"]["exists"] and all(value["syn_lines"] == 0 for value in terminal["primary_syn"].values()),
        "Lab retirement or zero-primary proof differs",
    )
    need(
        terminal["processes"]["primary"]["fd6"].endswith("hotline22-recovery/working.dsk")
        and terminal["processes"]["client"]["fd6"].endswith("hotline-client-isolated-01/working.dsk"),
        "Original runtime FD identities differ",
    )
    return {"status": "verified_option_one_notice_only", "a7": a7, **ban, "primary_syn": 0, "lab_retired": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
