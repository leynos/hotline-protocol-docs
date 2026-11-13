#!/usr/bin/env python3
"""Verify native room permissions, invitations, subjects and local event order."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_room_cases as cases
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


def pushes(report: dict, connection: str, kind: int) -> list[dict]:
    return [
        fields(f)
        for f in selected(report, connection)
        if f["type"] == kind and not f["is_reply"]
    ]


def identities(report: dict) -> tuple[bytes, dict[str, bytes]]:
    created = fields(reply(report, 10))
    room, owner = created[114], created[103]
    require(
        len(room) == 4 and int.from_bytes(room, "big") != 0 and len(owner) == 2,
        "Room/owner ID width differs",
    )
    ids = {"main": owner}
    for label in cases.ROLES:
        matches = [
            f
            for f in pushes(report, "main", 301)
            if f.get(102) == b"Room30-" + label.encode()
        ]
        require(bool(matches), "Owned room participant not announced")
        ids[label] = matches[0][103]
        access = pushes(report, label, 354)[0]
        require(
            access == {110: cases.ROLES[label]}, "Room participant privilege differs"
        )
    require(len(set(ids.values())) == 4, "Room participant identity collision")
    return room, ids


def members(
    report: dict,
    connection: str,
    identifier: int,
    expected: set[bytes],
    topic: bytes = b"",
) -> None:
    frame = reply(report, identifier, connection)
    require(frame["error"] == 0, "Room join failed")
    rows = [f for f in frame["fields"] if f["id"] == 300]
    others = [f for f in frame["fields"] if f["id"] != 300]
    require(
        others == ([{"id": 115, "hex": topic.hex()}] if topic else []),
        "Room join subject presence differs",
    )
    require(
        {r["uid"] for r in roster({**frame, "fields": rows})}
        == {int.from_bytes(v, "big") for v in expected},
        "Room roster inclusion differs",
    )


def missing(report: dict, connection: str, identifier: int) -> None:
    frame = reply(report, identifier, connection)
    require(
        frame["error"] == 1
        and fields(frame)
        == {100: b"Cannot join private chat because it has been closed already."},
        "Missing-room join outcome differs",
    )


def formatted(name: bytes, value: bytes, action: bool = False) -> bytes:
    prefix = (
        b"\r *** " + name + b" "
        if action
        else b"\r" + name[:13].rjust(13, b" ") + b":  "
    )
    return prefix + value.replace(b"\r", prefix)


def semantic(name: str, report: dict) -> None:
    room, ids = identities(report)
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    # Every room notification must name this room and an actual participant.
    for connection in ["main", *cases.ROLES]:
        for kind in [117, 118]:
            for event in pushes(report, connection, kind):
                require(
                    event.get(114) == room and event.get(103) in ids.values(),
                    "Room event identity differs",
                )
                actor = next(label for label, uid in ids.items() if uid == event[103])
                expected_event = {114: room, 103: ids[actor]}
                if kind == 117:
                    icon = 1 if actor == "main" else 30 + list(cases.ROLES).index(actor)
                    status = (
                        0x12
                        if actor == "main"
                        else 0x20
                        if actor == "zero"
                        else 8
                        if name == "refusals" and actor == "reader"
                        else 0
                    )
                    expected_event.update(
                        {
                            104: icon.to_bytes(2, "big"),
                            112: status.to_bytes(2, "big"),
                            102: b"framing-fixture"
                            if actor == "main"
                            else b"Room30-" + actor.encode(),
                        }
                    )
                require(
                    event == expected_event,
                    "Room membership notification schema differs",
                )
    if name == "basics":
        require(
            reply(report, 11, "zero")["error"] == 1
            and fields(reply(report, 11, "zero"))
            == {100: b"You are not allowed to create a new chat."},
            "Create-chat denial differs",
        )
        require(
            pushes(report, "main", 119) == [{114: room, 115: b"outsider-topic30"}]
            and not pushes(report, "zero", 119),
            "Non-member topic permissions differ",
        )
        members(report, "reader", 13, {main, reader}, b"outsider-topic30")
        members(report, "zero", 14, {main, reader, zero}, b"outsider-topic30")
        for connection in ["main", "reader"]:
            expected = [
                {
                    101: formatted(b"Room30-speaker", b"room-message30-speaker"),
                    114: room,
                }
            ]
            expected += [
                {101: formatted(b"Room30-speaker", text)}
                for text in [b"main-implicit30", b"main-zero30"]
            ]
            require(
                pushes(report, connection, 106) == expected,
                "Room/main-chat fanout differs",
            )
        require(
            pushes(report, "speaker", 106)
            == [
                {101: formatted(b"Room30-speaker", text)}
                for text in [b"main-implicit30", b"main-zero30"]
            ],
            "Non-member sender eligibility differs",
        )
        require(not pushes(report, "zero", 106), "Zero-access subject received chat")
        for connection in ["zero", "reader"]:
            require(
                pushes(report, connection, 104)
                == [
                    {109: b"\0\1", 101: b"You are not allowed to participate in chat."}
                ],
                "Denied-chat notice differs",
            )
        missing(report, "zero", 20)
        missing(report, "zero", 21)
    elif name == "topics":
        values = [
            b"",
            b"",
            b"topic30",
            b"A\0B\rC\nD\x80\xff",
            b"X" * 255,
            b"Y" * 255,
            b"Z" * 255,
            b"",
        ]
        expected = [{114: room, **({115: value} if value else {})} for value in values]
        for connection in ["main", "reader"]:
            require(
                pushes(report, connection, 119) == expected,
                "Topic cap/default/byte preservation differs",
            )
        for connection in ["zero", "speaker"]:
            require(
                not pushes(report, connection, 119), "Non-member received topic update"
            )
        members(report, "reader", 11, {main, reader})
        for identifier, value in enumerate(values, 220):
            members(report, "reader", identifier, {main, reader}, value)
        require(
            len(pushes(report, "main", 117)) == 1, "Repeated topic read joined twice"
        )
    elif name == "lifecycle":
        members(report, "reader", 11, {main, reader})
        members(report, "reader", 12, {main, reader})
        members(report, "zero", 13, {main, reader, zero})
        require(
            [e[103] for e in pushes(report, "main", 117)] == [reader, zero],
            "Repeated join emitted extra event",
        )
        require(
            pushes(report, "main", 118) == [{114: room, 103: zero}],
            "Non-member leave or last leave emitted extra event",
        )
        require(
            pushes(report, "reader", 118)
            == [{114: room, 103: zero}, {114: room, 103: main}],
            "Leave recipient order differs",
        )
        missing(report, "zero", 18)
    elif name == "concurrent":
        snapshots = []
        for connection, identifier in [("reader", 11), ("zero", 12)]:
            frame = reply(report, identifier, connection)
            rows = {r["uid"] for r in roster(frame)}
            require(
                {int.from_bytes(main, "big"), int.from_bytes(ids[connection], "big")}
                <= rows,
                "Concurrent join omitted self/creator",
            )
            snapshots.append(rows)
        require(
            sorted(map(len, snapshots)) == [2, 3]
            and set.union(*snapshots)
            == {int.from_bytes(i, "big") for i in [main, reader, zero]},
            "Concurrent join snapshots are inconsistent",
        )
        require(
            {e[103] for e in pushes(report, "main", 117)} == {reader, zero}
            and len(pushes(report, "main", 117)) == 2,
            "Concurrent join fanout differs",
        )
        require(
            sum(len(pushes(report, c, 117)) for c in ["reader", "zero"]) == 1,
            "Concurrent join recipient cut differs",
        )
        require(
            {e[103] for e in pushes(report, "main", 118)} == {reader, zero}
            and len(pushes(report, "main", 118)) == 2,
            "Concurrent leave lost/duplicated membership",
        )
        require(
            sum(len(pushes(report, c, 118)) for c in ["reader", "zero"]) == 1,
            "Concurrent leave recipient cut differs",
        )
        missing(report, "zero", 16)
    elif name == "create_invites":
        invitation = {114: room, 103: main, 102: b"framing-fixture"}
        for connection, count in [
            ("reader", 2),
            ("speaker", 1),
            ("zero", 1),
            ("main", 0),
        ]:
            require(
                pushes(report, connection, 113) == [invitation] * count,
                "Create mixed-target invitation differs",
            )
        rejection = {
            114: room,
            101: b'\r<<< "Room30-reader" declined invitation to chat >>>',
        }
        require(
            pushes(report, "main", 106) == [rejection, rejection],
            "Repeated rejection fanout differs",
        )
        require(
            all(not pushes(report, c, 106) for c in cases.ROLES),
            "Unjoined invitee received room rejection",
        )
        members(report, "reader", 13, {main, reader})
    elif name == "invites":
        invitation = {114: room, 103: zero, 102: b"Room30-zero"}
        require(
            pushes(report, "reader", 113) == [invitation] * 3
            and pushes(report, "speaker", 113) == [invitation],
            "Retry/disconnected/mixed invitation differs",
        )
        require(
            not pushes(report, "zero", 113) and not pushes(report, "main", 113),
            "Self/member invitation filter differs",
        )
        members(report, "reader", 13, {main, reader})
        members(report, "zero", 15, {main, reader, zero})
    elif name == "refusals":
        base = {103: reader, 102: b"Room30-reader"}
        require(
            pushes(report, "zero", 104)
            == [
                {
                    **base,
                    113: b"\0\3",
                    101: b"Room30-reader does not accept private chats.",
                },
                {**base, 113: b"\0\4", 101: b"automatic30"},
            ],
            "Invitation refusal/automatic/sender-suppression feedback differs",
        )
        require(
            not pushes(report, "reader", 113), "Refusing invitee received invitation"
        )
        require(
            pushes(report, "speaker", 113)
            == [{114: room, 103: zero, 102: b"Room30-zero"}] * 3,
            "Refusal stopped other target delivery",
        )
        members(report, "reader", 14, {main, reader})
    elif name == "formatting":
        expected = [
            {114: room, 101: formatted(b"Room30-speaker", text or b"", option == 1)}
            for option, text in cases.format_values()
        ]
        expected.append({114: room, 101: b"\r       Talk30:  short-name30"})
        for connection in ["main", "reader"]:
            require(
                pushes(report, connection, 106) == expected,
                "Chat option/format/newline/NUL bytes differ",
            )
        require(
            not pushes(report, "zero", 106) and not pushes(report, "speaker", 106),
            "Chat recipient membership/receive gate differs",
        )


def tail_frames(raw: bytes) -> list[dict]:
    result = []
    while raw:
        require(len(raw) >= 20, "Incomplete room tail header")
        size = 20 + int.from_bytes(raw[16:20], "big")
        require(len(raw) >= size, "Incomplete room tail payload")
        result.append(decode_frame(raw[:size]))
        raw = raw[size:]
    return result


def validate_tail(raw: bytes, room: bytes, ids: dict[str, bytes]) -> None:
    for frame in tail_frames(raw):
        values = fields(frame)
        require(
            frame["type"] in {118, 301, 302}
            and not frame["is_reply"]
            and frame["error"] == 0
            and values.get(103) in ids.values(),
            "Unread room message identity differs",
        )
        if frame["type"] == 118:
            require(
                values == {114: room, 103: values[103]}, "Unread room departure differs"
            )
        elif frame["type"] == 302:
            require(set(values) == {103}, "Unread roster removal differs")
        else:
            require(
                set(values) == {103, 104, 112, 102}, "Unread profile schema differs"
            )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases.suites()
    failures = {
        "basics-width-failure": ("EOFError:", 37),
        "refusals-ack-timeout": ("TimeoutError:", 34),
    }
    require(
        set(manifest["reports"])
        == set(expected) | set(failures)
        == {p.parent.name for p in directory.glob("*/report.json")},
        "Room report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == 2095
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Room recorder count/drops differ",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    observations, reports = {}, {}
    for name in manifest["reports"]:
        case = directory / name
        plan = json.loads((case / "plan.json").read_text())
        report = verify_capture(case)
        require(plan["environment"] == runtime, "Room plan runtime differs")
        require(
            report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256,
            "Room oracle/profile differs",
        )
        require(
            report["driver_sha256"]
            == manifest["as_run_sources"]["sources/protocol_capture.py.final.txt"],
            "Room recorder source differs",
        )
        if name in failures:
            prefix, completed = failures[name]
            require(
                report["status"] == "failed"
                and report["error"].startswith(prefix)
                and report["completed_actions"] == completed
                and sha(case / "plan.json") == manifest["frozen_failed_plans"][name],
                "Failed room expectation was erased/reclassified",
            )
        else:
            steps, expectation = expected[name]
            require(
                report["status"] == "completed"
                and plan["steps"] == steps
                and plan["expectation"] == expectation,
                "Room completed plan differs",
            )
            waits(report, steps)
            variables = {}
            if name in [
                "basics",
                "topics",
                "lifecycle",
                "concurrent",
                "create_invites",
                "invites",
                "refusals",
                "formatting",
            ]:
                room, ids = identities(report)
                variables["room"] = room.hex()
                variables.update(
                    {label + "_uid": ids[label].hex() for label in cases.ROLES}
                )
            for connection, recorded in report["streams"].items():
                sent = ""
                for step in steps:
                    if step["op"] != "send" or step["connection"] != connection:
                        continue
                    value = step["hex"]
                    for key, data in variables.items():
                        value = value.replace("{" + key + "}", data)
                    sent += value
                require(sent == recorded["sent_hex"], "Room request bytes differ")
            if "room" in variables:
                semantic(name, report)
                # No normal success ACK exists for these request kinds. Check
                # each caller's actual request IDs rather than notification IDs.
                for step in steps:
                    if step["op"] != "send":
                        continue
                    value = step["hex"]
                    for key, data in variables.items():
                        value = value.replace("{" + key + "}", data)
                    raw = bytes.fromhex(value)
                    if len(raw) < 20:
                        continue
                    request_frame = decode_frame(raw)
                    if request_frame["type"] in {105, 113, 114, 116, 120, 304}:
                        require(
                            not any(
                                f["is_reply"] and f["id"] == request_frame["id"]
                                for f in selected(report, step["connection"])
                            ),
                            "Invented room/settings direct ACK",
                        )
        retained = tails[name]
        observations[name] = reconcile(
            report,
            host,
            guest,
            {c: bytes.fromhex(v) for c, v in retained["host"].items()},
            guest_unread_output={
                c: bytes.fromhex(v) for c, v in retained["guest"].items()
            },
        )
        for view in ["host", "guest"]:
            for raw in retained[view].values():
                room, ids = identities(report)
                validate_tail(bytes.fromhex(raw), room, ids)
        reports[name] = report
    chronology = [
        "preflight",
        "seed",
        "basics-width-failure",
        "recovery-inspect",
        "basics",
        "topics",
        "lifecycle",
        "concurrent",
        "create_invites",
        "invites",
        "refusals-ack-timeout",
        "refusals",
        "formatting",
        "cleanup",
        "final",
    ]
    for first, second in pairwise(chronology):
        require(
            datetime.fromisoformat(reports[first]["recorded_at_utc"])
            < datetime.fromisoformat(reports[second]["started_at_utc"]),
            "Room stage chronology differs",
        )
    require(
        observations
        == json.loads((directory / "packet-observations.json").read_text()),
        "Room packet observations differ",
    )
    baseline = enumeration(reply(reports["preflight"], 10))
    files = listing(reply(reports["preflight"], 11))
    require(len(baseline) == 2 and len(files) == 41, "Room original baseline differs")
    for i in range(20, 23):
        require(
            reply(reports["preflight"], i)["error"] == 1
            and reply(reports["final"], i)["error"] == 1,
            "Room owned name preflight/cleanup differs",
        )
    expected_accounts = []
    for label, access in cases.ROLES.items():
        expected_accounts.append(
            payload(
                [
                    (102, b"Room30-" + label.encode()),
                    (105, complement(cases.key(label))),
                    (106, b"x"),
                    (110, access),
                ]
            ).hex()
        )
    require(
        enumeration(reply(reports["recovery-inspect"], 10))
        == sorted(baseline + expected_accounts),
        "Same-session recovery inventory differs",
    )
    require(
        enumeration(reply(reports["cleanup"], 20))
        == baseline
        == enumeration(reply(reports["final"], 10))
        and listing(reply(reports["cleanup"], 21))
        == files
        == listing(reply(reports["final"], 11)),
        "Room final baseline restoration differs",
    )
    for name, digest in manifest["as_run_sources"].items():
        require(sha(directory / name) == digest, "Room as-run source changed")
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(len(queries) == 16, "Room oracle query count differs")
    for path in queries:
        q = json.loads(path.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False),
            "Room oracle query failed",
        )
    require(
        runtime["room_observation"]["emulator_pid"] == 1259319
        and "ActiveState=active" in runtime["room_observation"]["service_state"],
        "Room running epoch provenance differs",
    )
    return {
        "completed_reports": 13,
        "retained_failed_expectations": 2,
        "paired_connections": 45,
        "room_scenarios": 8,
        "oracle_queries": 16,
        "host_packets": 2095,
        "scope": "Owned room permission, topic, lifecycle, invitation and formatting fixtures with explicit per-view unread tails. Local send/recipient ordering; no universal cross-socket delivery, restart or historical-client claim.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
