#!/usr/bin/env python3
"""Verify owned duplicate, kick-protected deletion and self-deletion captures."""

import argparse
import json
from datetime import datetime
from pathlib import Path

import native_account_identity_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from native_plan import payload
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_mkdir import listing
from verify_native_shx import fields, sha


def account(frame: dict, label: str, lookup_key: bytes | None = None) -> None:
    require(
        frame["error"] == 0
        and fields(frame)
        == {
            102: b"Identity29-" + label.encode(),
            105: complement(cases.KEYS[label] if lookup_key is None else lookup_key),
            106: b"x",
            110: cases.ACCESS[label],
        },
        "Identity account record differs",
    )


def duplicate(report: dict, uppercase: bool) -> None:
    key = cases.KEYS["duplicate"]
    if uppercase:
        key = key.upper()
    require(
        reply(report, 10)["error"] == 1
        and fields(reply(report, 10))
        == {
            100: b"Cannot create account \xd2"
            + key
            + b"\xd3 because there is already an account with that login."
        },
        "Duplicate create rejection differs",
    )
    account(reply(report, 20), "duplicate")
    account(reply(report, 21), "duplicate", cases.KEYS["duplicate"].upper())
    require(reply(report, 90)["error"] == 0, "Duplicate control liveness differs")


def deletion(report: dict, label: str, observation: dict, tail: bytes) -> None:
    subject = selected(report, "target")
    access = next(f for f in subject if f["type"] == 354)
    require(fields(access) == {110: cases.ACCESS[label]}, "Protection mask differs")
    announce = next(f for f in selected(report, "main") if f["type"] == 301)
    uid = fields(announce)[103]
    require(
        fields(announce)
        == {
            103: uid,
            104: b"\0\x1d",
            112: b"\0\0",
            102: b"Identity29-" + label.encode(),
        }
        and len(uid) == 2
        and int.from_bytes(uid, "big") > 0,
        "Owned target announcement differs",
    )
    kick = reply(report, 11)
    require(
        kick["error"] == 1
        and fields(kick)
        == {
            100: b"You are not allowed to disconnect user \xd2Identity29-"
            + label.encode()
            + b"\xd3 (user is protected)."
        },
        "Kick protection rejection differs",
    )
    require(
        reply(report, 80, "target")["error"] == 0, "Protected subject lost liveness"
    )
    connection = "target" if label == "self" else "main"
    ack = reply(report, 12, connection)
    require(ack["error"] == 0 and fields(ack) == {}, "Deletion ACK differs")
    notice = next(f for f in subject if f["type"] == 104)
    require(
        not notice["is_reply"]
        and notice["error"] == 0
        and fields(notice)
        == {101: b"You are logged in with an account which was deleted."},
        "Deletion notice differs",
    )
    if label == "self":
        require(
            subject.index(ack) < subject.index(notice),
            "Self-delete notice precedes ACK",
        )
    require(
        observation["target"]["guest_server_initiated_close"]
        and observation["target"]["guest_server_close_kind"] == "FIN",
        "Protected/self-delete guest close differs",
    )
    require(
        reply(report, 20)["error"] == 1
        and fields(reply(report, 20))
        == {100: b"No account with login \xd2" + cases.KEYS[label] + b"\xd3."},
        "Deleted account still readable or wrong lookup failure",
    )
    snapshot = roster(reply(report, 30))
    require(
        len(snapshot) == 2
        and any(r["uid"] == int.from_bytes(uid, "big") for r in snapshot),
        "Bounded post-delete stale roster differs",
    )
    require(len(tail) == 28, "Unread target removal size differs")
    removed = decode_frame(tail)
    require(
        removed["type"] == 302
        and not removed["is_reply"]
        and removed["error"] == 0
        and fields(removed) == {103: uid},
        "Unread target removal identity differs",
    )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases.suites()
    require(
        set(expected)
        == set(manifest["reports"])
        == {p.parent.name for p in directory.glob("*/report.json")},
        "Identity report inventory differs",
    )
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["identity_observation"]["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
        and "ActiveState=active" in runtime["identity_observation"]["service_state"],
        "Identity runtime provenance differs",
    )
    require(
        len(host) == 394
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Identity recorder count or drops differ",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    require(set(tails) == {"protected", "self"}, "Unread identity cases differ")
    reports, observations = {}, {}
    for name, (steps, expectation) in expected.items():
        case = directory / name
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps
            and plan["expectation"] == expectation
            and plan["environment"] == runtime,
            "Identity plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"]
            == manifest["as_run_sources"]["sources/protocol_capture.py.as-run.txt"],
            "Identity capture status or oracle differs",
        )
        waits(report, steps)
        uid = ""
        if name in {"protected", "self"}:
            uid = fields(next(f for f in selected(report, "main") if f["type"] == 301))[
                103
            ].hex()
        for connection, recorded in report["streams"].items():
            sent = "".join(
                s["hex"].replace("{target_uid}", uid)
                for s in steps
                if s["op"] == "send" and s["connection"] == connection
            )
            require(sent == recorded["sent_hex"], "Identity wire request differs")
        unread = {k: bytes.fromhex(v) for k, v in tails.get(name, {}).items()}
        require(
            not unread or set(unread) == {"main"}, "Unexpected unread identity socket"
        )
        observations[name] = reconcile(report, host, guest, unread)
        reports[name] = report
    for first, second in [
        ("preflight", "seed"),
        ("seed", "duplicate-exact"),
        ("duplicate-exact", "duplicate-uppercase"),
        ("duplicate-uppercase", "duplicate-original-login"),
        ("duplicate-original-login", "duplicate-changed-login"),
        ("protected", "protected-login"),
        ("after-protected", "self"),
        ("self", "self-login"),
        ("after-self", "cleanup"),
        ("cleanup", "final"),
    ]:
        require(
            datetime.fromisoformat(reports[first]["recorded_at_utc"])
            < datetime.fromisoformat(reports[second]["started_at_utc"]),
            "Identity stage chronology differs",
        )
    require(
        observations
        == json.loads((directory / "packet-observations.json").read_text()),
        "Retained packet observations differ",
    )
    baseline = enumeration(reply(reports["preflight"], 10))
    original_files = listing(reply(reports["preflight"], 11))
    require(
        len(baseline) == 2 and len(original_files) == 41, "Original inventory differs"
    )
    for identifier in range(20, 23):
        require(
            reply(reports["preflight"], identifier)["error"] == 1, "Owned name occupied"
        )
    for identifier, label in enumerate(cases.KEYS, 20):
        account(reply(reports["seed"], identifier), label)
    for name, uppercase in [("duplicate-exact", False), ("duplicate-uppercase", True)]:
        duplicate(reports[name], uppercase)
    for name in [
        "duplicate-original-login",
        "duplicate-changed-login",
        "protected-login",
        "self-login",
    ]:
        ok = name == "duplicate-original-login"
        require(
            reply(reports[name], 1)["error"] == (0 if ok else 1),
            "Identity login contrast differs",
        )
        require(
            len(reports[name]["frames"]) == (4 if ok else 1),
            "Identity login sequence differs",
        )
        if ok:
            require(
                fields(next(f for f in reports[name]["frames"] if f["type"] == 354))
                == {110: bytes(8)}
                and reply(reports[name], 90)["error"] == 0,
                "Original duplicate-account login role or liveness differs",
            )
        else:
            require(
                fields(reply(reports[name], 1)) == {100: b"Incorrect login."},
                "Identity login failure family differs",
            )

    def inventory(labels: list[str]) -> list[str]:
        return sorted(
            baseline
            + [
                payload(
                    [
                        (102, b"Identity29-" + label.encode()),
                        (105, complement(cases.KEYS[label])),
                        (106, b"x"),
                        (110, cases.ACCESS[label]),
                    ]
                ).hex()
                for label in labels
            ]
        )

    for name, labels, identifier in [
        ("duplicate-exact", list(cases.KEYS), 30),
        ("duplicate-uppercase", list(cases.KEYS), 30),
        ("after-protected", ["self", "duplicate"], 10),
        ("after-self", ["duplicate"], 10),
        ("cleanup", [], 20),
        ("final", [], 10),
    ]:
        require(
            enumeration(reply(reports[name], identifier)) == inventory(labels),
            "Identity enumeration differs",
        )
    for name in ["after-protected", "after-self", "final"]:
        require(
            listing(reply(reports[name], 11)) == original_files,
            "Original Files baseline differs",
        )
    for label in ["protected", "self"]:
        deletion(
            reports[label],
            label,
            observations[label],
            bytes.fromhex(tails[label]["main"]),
        )
    for name, expected_hash in manifest["as_run_sources"].items():
        require(
            sha(directory / name) == expected_hash,
            "Identity as-run source changed",
        )
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        {p.stem for p in queries}
        == {
            "ID-D-" + address
            for address in [
                "100146f0",
                "100149e0",
                "10014df0",
                "10007340",
                "10005f90",
                "10015e70",
                "100541e0",
                "100071a0",
                "1002af80",
                "1002ba20",
            ]
        },
        "Identity oracle query inventory differs",
    )
    for path in queries:
        query = json.loads(path.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"].get("isError", False)
            and query["query"]["tool"] == "decompile_function_by_address"
            and query["query"]["arguments"] == {"address": path.stem[5:]}
            and query["result"]["structuredContent"]["code"]
            == path.with_suffix(".c").read_text(),
            "Identity oracle query failed",
        )
    return {
        "completed_reports": len(reports),
        "paired_connections": sum(map(len, observations.values())),
        "protected_delete_variants": 2,
        "duplicate_create_variants": 2,
        "unread_removal_tails": 2,
        "oracle_queries": len(queries),
        "scope": "Owned bit-23 protection and self-delete, exact/ASCII-case collisions and wire cleanup. No built-in-account deletion, native Trash fork, forced I/O, restart or universal name-folding claim.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
