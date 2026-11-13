#!/usr/bin/env python3
"""Verify live account events, orderly close and application restart persistence."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_live_account_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields, sha


def waits(report: dict, steps: list[dict]) -> None:
    for action, step in enumerate(steps):
        if step["op"] not in {"pause", "expect_quiet"}:
            continue
        event = "pause" if step["op"] == "pause" else "quiet"
        matches = [
            i
            for i, e in enumerate(report["events"])
            if e["action"] == action and e["event"] == event
        ]
        require(len(matches) == 1 and matches[0] > 0, "Missing live account wait event")
        index = matches[0]
        duration = step.get("seconds", step.get("timeout"))
        require(
            report["events"][index]["elapsed_ns"]
            - report["events"][index - 1]["elapsed_ns"]
            >= duration * 1e9,
            "Short live account wait",
        )


def subjects(report: dict, name: bytes) -> dict[str, int]:
    rows = roster(reply(report, 10))
    require(len(rows) == 3, "Live account initial roster cardinality differs")
    result = {}
    for connection, icon in [("one", 7), ("two", 8)]:
        matches = [r for r in rows if r["icon"] == icon and r["name_hex"] == name.hex()]
        require(len(matches) == 1, "Live account subject identity differs")
        result[connection] = matches[0]["uid"]
        access = next(f for f in selected(report, connection) if f["type"] == 354)
        require(
            fields(access) == {110: bytes.fromhex("2000000000000000")},
            "Initial live access differs",
        )
    return result


def check_edit(report: dict) -> dict[str, int]:
    uids = subjects(report, b"Stored Alpha27")
    main = selected(report, "main")
    ack = reply(report, 11)
    require(ack["error"] == 0 and fields(ack) == {}, "Live edit ACK differs")
    for connection in ["main", "one", "two"]:
        frames = selected(report, connection)
        updates = [
            f
            for f in frames
            if f["type"] == 301 and fields(f).get(102) == b"Stored Beta27"
        ]
        require(
            len(updates) == 2
            and {int.from_bytes(fields(f)[103], "big") for f in updates}
            == set(uids.values()),
            "Live rename recipients differ",
        )
        for frame in updates:
            uid = int.from_bytes(fields(frame)[103], "big")
            icon = 7 if uid == uids["one"] else 8
            require(
                fields(frame)
                == {
                    103: uid.to_bytes(2, "big"),
                    104: icon.to_bytes(2, "big"),
                    112: b"\0\x20",
                    102: b"Stored Beta27",
                },
                "Live rename field bytes differ",
            )
        if connection == "main":
            require(
                all(
                    frames.index(ack)
                    < frames.index(f)
                    < frames.index(reply(report, 12))
                    for f in updates
                ),
                "Caller ACK/rename/roster order differs",
            )
        else:
            access = [f for f in frames if f["type"] == 354]
            own = next(
                f
                for f in updates
                if int.from_bytes(fields(f)[103], "big") == uids[connection]
            )
            require(
                len(access) == 2
                and fields(access[1]) == {110: bytes(8)}
                and frames.index(access[1]) < frames.index(own),
                "Own 354 must precede own rename",
            )
            require(
                fields(reply(report, 91, connection))
                == {100: b"You are not allowed to download files."}
                and reply(report, 91, connection)["error"] == 1,
                "Live revocation not enforced",
            )
            for identifier in [80, 90, 92, 93]:
                require(
                    reply(report, identifier, connection)["error"] == 0
                    and fields(reply(report, identifier, connection)) == {},
                    "Password change interrupted live control",
                )
    for identifier in [12, 22, 32]:
        rows = roster(reply(report, identifier))
        require(
            {r["uid"] for r in rows if r["name_hex"] == b"Stored Beta27".hex()}
            == set(uids.values()),
            "Live post-edit snapshot differs",
        )
    for identifier in [21, 31]:
        require(
            reply(report, identifier)["error"] == 0
            and fields(reply(report, identifier)) == {},
            "Password/attribute-only ACK differs",
        )
    for identifier in [40, 41]:
        require(
            not (
                set(uids.values())
                & {r["uid"] for r in roster(reply(report, identifier))}
            ),
            "Closed live subjects remain in final edit roster",
        )
    removals = [fields(f) for f in main if f["type"] == 302]
    require(
        removals
        == [
            {103: uids["one"].to_bytes(2, "big")},
            {103: uids["two"].to_bytes(2, "big")},
        ],
        "Live EOF removal notifications differ",
    )
    return uids


def check_delete(report: dict, tail: bytes, observations: dict) -> dict[str, int]:
    uids = subjects(report, b"Delete Target27")
    require(
        reply(report, 11)["error"] == 0 and fields(reply(report, 11)) == {},
        "Live deletion ACK differs",
    )
    for connection in ["one", "two"]:
        notices = [f for f in selected(report, connection) if f["type"] == 104]
        require(
            len(notices) == 1
            and notices[0]["is_reply"] == 0
            and notices[0]["error"] == 0
            and fields(notices[0])
            == {101: b"You are logged in with an account which was deleted."},
            "Deleted account notice differs",
        )
        require(
            observations[connection]["guest_server_initiated_close"]
            and observations[connection]["guest_server_close_kind"] == "FIN",
            "Deletion must retain native first FIN",
        )
    for identifier in [12, 13]:
        require(
            set(uids.values()) <= {r["uid"] for r in roster(reply(report, identifier))},
            "Deletion stale roster observation changed",
        )
    require(
        not any(f["type"] == 302 for f in report["frames"]),
        "Deletion report must preserve unread removal tail",
    )
    require(
        reply(report, 14)["error"] == 1
        and fields(reply(report, 14))
        == {100: b"No account with login \xd2m-delete27\xd3."},
        "Live deleted account lookup differs",
    )
    removals = []
    while tail:
        require(len(tail) >= 20, "Truncated late removal header")
        size = 20 + int.from_bytes(tail[16:20], "big")
        frame = decode_frame(tail[:size])
        require(
            size <= len(tail)
            and frame["type"] == 302
            and frame["is_reply"] == 0
            and frame["error"] == 0
            and set(fields(frame)) == {103},
            "Unexpected unread deletion output",
        )
        removals.append(fields(frame)[103])
        tail = tail[size:]
    require(
        removals == [uids["one"].to_bytes(2, "big"), uids["two"].to_bytes(2, "big")],
        "Late removal UIDs differ",
    )
    return uids


def stopped(report: dict, host: list[dict], guest: list[dict]) -> None:
    require(
        report["status"] == "failed"
        and "ConnectionResetError" in report["error"]
        and report["completed_actions"] == 2
        and report["frames"] == [],
        "Stopped native witness must remain a reset failure",
    )
    event = next(e for e in report["events"] if e["event"] == "connect")
    source, target = tuple(event["local_address"]), tuple(event["peer_address"])
    when = int(
        datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
        + event["elapsed_ns"] / 1000
    )
    host_packets = lifetime(host, source, target, when)
    require(
        stream(host_packets, source, target).hex()
        == report["streams"]["main"]["sent_hex"]
        == "54525450484f544c00010002"
        and stream(host_packets, target, source) == b"",
        "Stopped host handshake bytes differ",
    )
    gs, gt = ("10.0.2.2", source[1]), ("10.0.2.15", 5500)
    packets = lifetime(guest, gs, gt, when)
    outgoing = direction(packets, gt, gs)
    require(
        any(p["flags"] & 4 for p in outgoing)
        and not any(p["flags"] & 2 for p in outgoing)
        and all(
            p["payload_hex"] == (b"No listener".hex() if p["flags"] & 4 else "")
            for p in packets
        ),
        "Stopped guest must reject SYN without application bytes",
    )


def native_record(deleted: bool) -> bytes:
    value = bytearray(734)
    value[:2] = b"\0\1"
    value[4:12] = cases.ACCESS if deleted else bytes(8)
    for offset, data in [
        (528, b"Delete Target27" if deleted else b"Stored Beta27"),
        (596, b"live27" if deleted else b"attribute-only27"),
        (664, b"m-delete27" if deleted else b"m-live27"),
        (700, complement(b"delete-pass27" if deleted else b"live-final27")),
    ]:
        value[offset : offset + 2] = len(data).to_bytes(2, "big")
        value[offset + 2 : offset + 2 + len(data)] = data
    return bytes(value)


def storage(directory: Path) -> None:
    before = directory / "native-before-restart"
    rows = json.loads((before / "extraction.json").read_text())["records"]
    require(
        {r["path"] for r in rows}
        == {
            "/Hotline19/Users/m-live27",
            "/Hotline19/Users/m-live27/UserData",
            "/Trash/m-delete27",
            "/Trash/m-delete27/UserData",
            "/Hotline19/Files/m-live27-flush",
        },
        "Live pre-restart catalogue differs",
    )
    for row in rows:
        if row["path"].endswith("/UserData"):
            require(
                (before / (row["key"] + ".data")).read_bytes()
                == native_record("m-delete27" in row["path"]),
                "Live stored account bytes differ",
            )
    for phase, count in [
        ("native-after-restart", 5),
        ("native-cleanup", 5),
        ("native-published", 6),
    ]:
        base = directory / phase
        moved = {
            r["catalog"]: r
            for r in json.loads((base / "extraction.json").read_text())["records"]
        }
        require(
            len(moved) == count and {r["catalog"] for r in rows} <= set(moved),
            "Live post-restart/cleanup identities differ",
        )
        if phase == "native-published":
            extra = [
                r
                for identifier, r in moved.items()
                if identifier not in {r["catalog"] for r in rows}
            ]
            require(
                len(extra) == 1
                and extra[0]["path"] == "/Hotline19/Files/m-live27-publish",
                "Separate live publisher differs",
            )
        for row in rows:
            target = moved[row["catalog"]]
            path = (
                row["path"]
                if phase == "native-after-restart"
                else row["path"]
                .replace("/Hotline19/Users/", "/Trash/")
                .replace("/Hotline19/Files/", "/Trash/")
            )
            require(
                target["path"] == path and target["directory"] == row["directory"],
                "Live persistence/Trash path differs",
            )
            if not row["directory"]:
                for fork in ["data", "rsrc"]:
                    require(
                        (before / (row["key"] + "." + fork)).read_bytes()
                        == (base / (target["key"] + "." + fork)).read_bytes(),
                        "Server restart/cleanup changed stored fork",
                    )
    identities = json.loads(
        (directory / "restart-application-identities.json").read_text()
    )
    require(
        identities["before"] == identities["after"]
        and identities["before"]["/Hotline19/HLserver19"]["data_sha256"]
        == ORACLE_SHA256
        and identities["before"]["/Hotline19/HLserver19"]["rsrc_sha256"]
        == "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
        "Restart application fork identities differ",
    )
    for phase in ["before", "after"]:
        base = directory / ("native-application-" + phase)
        records = json.loads((base / "extraction.json").read_text())["records"]
        require(
            {r["path"] for r in records}
            == {"/Hotline19/HLserver19", "/Hotline19/Prefs"},
            "Application metadata inventory differs",
        )
        for row in records:
            require(
                identities[phase][row["path"]]["catalog"] == row["catalog"],
                "Application catalogue identity differs",
            )
            if row["path"].endswith("/Prefs"):
                require(
                    all(
                        sha(base / (row["key"] + "." + fork))
                        == identities[phase][row["path"]][fork + "_sha256"]
                        for fork in ["data", "rsrc"]
                    ),
                    "Restart changed recorded Prefs bytes",
                )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtimes = {
        phase: json.loads((directory / ("runtime-" + phase + ".json")).read_text())
        for phase in ["before", "after"]
    }
    require(
        all(
            r["emulator_pid"] == 1259319
            and r["running_executable_sha256"]
            == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
            for r in runtimes.values()
        )
        and runtimes["before"]["server_epoch"] != runtimes["after"]["server_epoch"],
        "Live runtime epochs differ",
    )
    expected = {
        "preflight": cases.preflight(),
        "seed": cases.seed(),
        "edit": cases.edit(),
        "delete": cases.delete(),
    }
    expected.update(
        {
            "before-login-" + label: cases.probe(label)
            for label in ["old", "intermediate", "final", "deleted"]
        }
    )
    expected.update(
        {
            "before-final": cases.finalize(),
            "stopped": cases.stopped(),
            "after-inspect": cases.inspect(),
        }
    )
    expected.update(
        {
            "after-login-" + label: cases.probe(label)
            for label in ["old", "intermediate", "final", "deleted"]
        }
    )
    expected.update(
        {
            "after-inspect-confirmation": cases.inspect(),
            "cleanup": cases.cleanup(),
            "publish": cases.publish_cleanup(),
            "remove-publisher": cases.remove_publisher(),
        }
    )
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Live report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == 551
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Live packet recorder count/drop differs",
    )
    tails = json.loads((directory / "delete-unread-tails.json").read_text())
    require(set(tails) == {"main"}, "Unexpected unread live socket")
    reports, observations, sockets = {}, {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        phase = (
            "after"
            if key.startswith("after-")
            or key in {"cleanup", "publish", "remove-publisher"}
            else "before"
        )
        require(
            plan["steps"] == steps
            and plan["expectation"] == expectation
            and plan["environment"] == runtimes[phase],
            "Live as-run plan differs",
        )
        report = verify_capture(case)
        status = "failed" if key == "stopped" else "completed"
        require(
            report["status"] == manifest["reports"][key] == status
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"]
            == sha(directory / "sources/protocol_capture.py"),
            "Live capture provenance/status differs",
        )
        reference = (
            fields(reply(report, 80))[107].hex()
            if key in {"before-final", "publish"}
            else ""
        )
        for connection, recorded in report["streams"].items():
            sent = "".join(
                bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
                for s in steps[: report["completed_actions"]]
                if s["op"] == "send" and s["connection"] == connection
            )
            require(
                recorded["sent_hex"] == sent, "Live recorded request differs from plan"
            )
        if key == "stopped":
            stopped(report, host, guest)
        else:
            observations[key] = reconcile(
                report,
                host,
                guest,
                {"main": bytes.fromhex(tails["main"])} if key == "delete" else None,
            )
            waits(report, steps)
        sockets += len(report["streams"])
        reports[key] = report
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(expected)
        ),
        "Live epoch chronology differs",
    )
    check_edit(reports["edit"])
    check_delete(
        reports["delete"], bytes.fromhex(tails["main"]), observations["delete"]
    )
    for key, report in reports.items():
        if "-login-" in key:
            frame = reply(report, 1)
            if key.endswith("-final"):
                require(
                    [(f["type"], f["error"]) for f in report["frames"]]
                    == [(0, 0), (354, 0), (109, 0), (0, 0)]
                    and fields(report["frames"][1]) == {110: bytes(8)},
                    "Persisted password/access login differs",
                )
            else:
                require(
                    len(report["frames"]) == 1
                    and frame["error"] == 1
                    and fields(frame) == {100: b"Incorrect login."},
                    "Old/deleted reconnect result differs",
                )
    live_fields = {
        102: b"Stored Beta27",
        105: complement(b"m-live27"),
        106: b"x",
        110: bytes(8),
    }
    missing = {100: b"No account with login \xd2m-delete27\xd3."}
    for key in ["before-final", "after-inspect", "after-inspect-confirmation"]:
        require(
            reply(reports[key], 10)["error"] == 0
            and fields(reply(reports[key], 10)) == live_fields
            and reply(reports[key], 11)["error"] == 1
            and fields(reply(reports[key], 11)) == missing,
            "Account replacement/deletion did not persist across restart",
        )
    baseline = enumeration(reply(reports["preflight"], 10))
    for identifier, key in [(20, b"m-live27"), (21, b"m-delete27")]:
        require(
            reply(reports["preflight"], identifier)["error"] == 1
            and fields(reply(reports["preflight"], identifier))
            == {100: b"No account with login \xd2" + key + b"\xd3."},
            "Owned live account was not initially absent",
        )
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Live account seed failed",
    )
    require(
        len(baseline) == 2
        and enumeration(reply(reports["before-final"], 20))
        == enumeration(reply(reports["after-inspect"], 20))
        == enumeration(reply(reports["after-inspect-confirmation"], 20)),
        "Restart changed account enumeration",
    )
    files = listing(reply(reports["preflight"], 11))
    require(len(files) == 41, "Live Files baseline differs")
    for key in ["after-inspect", "after-inspect-confirmation"]:
        observed = listing(reply(reports[key], 21))
        require(b"m-live27-flush" in observed, "Persisted live flush object missing")
        observed.pop(b"m-live27-flush")
        require(observed == files, "Restart changed unrelated Files entries")
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            enumeration(reply(reports[key], 20)) == baseline,
            "Live account cleanup did not restore baseline",
        )
        after = listing(reply(reports[key], 21))
        if key == "publish":
            require(b"m-live27-publish" in after, "Live publisher missing")
            after.pop(b"m-live27-publish")
        require(after == files, "Live helper cleanup did not restore Files")
    storage(directory)
    ui = [
        json.loads(line)
        for line in (directory / "ui-events.jsonl").read_text().splitlines()
    ]
    require(
        [e["command"][2:] for e in ui]
        == [
            ["click", "500", "350"],
            ["click", "285", "39"],
            ["click", "936", "248"],
            ["click", "408", "234"],
            ["key", "Alt_L+o"],
            ["click", "629", "310"],
        ]
        and all(e["exit_code"] == 0 for e in ui),
        "Controlled quit/relaunch journal differs",
    )
    require(
        datetime.fromisoformat(reports["before-final"]["recorded_at_utc"])
        < datetime.fromisoformat(ui[2]["started_at_utc"])
        < datetime.fromisoformat(reports["stopped"]["started_at_utc"])
        < datetime.fromisoformat(ui[4]["started_at_utc"])
        < datetime.fromisoformat(reports["after-inspect"]["started_at_utc"]),
        "Restart witness boundary order differs",
    )
    host_exit = json.loads((directory / "after-stage-host-exit.json").read_text())
    require(
        host_exit["observed_tool_exit_code"] == 143
        and host_exit["complete_reports"]
        == [
            "after-inspect",
            "after-login-old",
            "after-login-intermediate",
            "after-login-final",
            "after-login-deleted",
        ],
        "Host exit observation was lost",
    )
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "10014df0",
        "100149e0",
        "10005d30",
        "10005f90",
        "10004f30",
        "10011870",
        "10007340",
        "100073c0",
        "100075e0",
        "10007ad0",
        "10018620",
        "10058400",
        "10058320",
        "1006db60",
        "10073f70",
        "10070700",
    }
    require(
        len(queries) == 16
        and {p.stem.removeprefix("LA-D-") for p in queries} == addresses,
        "Live oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Live oracle identity/code differs",
        )
    require(
        len(reports) == 19
        and manifest["completed_reports"] == 18
        and manifest["expected_failed_reports"] == 1
        and sockets == manifest["host_socket_lifetimes"] == 25
        and manifest["established_guest_connections"] == 24
        and manifest["stopped_guest_attempts"] == 1,
        "Live aggregate counts differ",
    )
    return {
        "completed_reports": 18,
        "expected_stopped_report_failure": 1,
        "host_socket_lifetimes": sockets,
        "established_guest_connections": 24,
        "matching_live_sessions": 2,
        "deleted_live_sessions": 2,
        "late_unread_removals": 2,
        "persisted_original_objects": 5,
        "oracle_queries": 16,
        "scope": "Normal native server application restart in the same emulator; no OS/power-loss restart, all-disconnect deadline, forced-write atomicity or historical-client claim. Host stage exit143 retained with independent confirmation.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
