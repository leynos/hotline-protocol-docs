#!/usr/bin/env python3
"""Verify native alias observations against plans, paired TCP and positive forks."""

import argparse
import json
from pathlib import Path

from native_alias_cases import (
    DATA,
    ROOT,
    cleanup,
    create,
    damage,
    downloads,
    information,
    seed,
    supplementary,
)
from native_filp import decode
from native_mkdir_cases import exchange
from native_packet_evidence import reconcile
from native_plan import close, login
from native_transfer_cases import resource_fork
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing
from verify_native_shx import fields, sha

FAILURES = {
    "missing-source",
    "missing-destination",
    "destination-not-directory",
    "directory-collision",
    "permission-new",
    "permission-conflict",
}


def metadata(report: dict, label: str, name: bytes) -> dict:
    """Assert field presence as well as bytes; zero tags are present values."""
    actual = fields(reply(report, 10))
    expected = {201: name}
    if label == "self-after-create":
        expected.update({205: b"Unattached Alias", 206: b"n/a", 213: b"alis"})
    elif "directory" in label:
        expected.update(
            {
                205: b"Folder" if label == "ordinary-directory" else b"Folder Alias",
                206: b"n/a",
                213: b"fldr",
            }
        )
    elif label == "zero-tags":
        expected.update({205: bytes(4), 206: bytes(4), 213: bytes(4), 207: b"\0\x09"})
    elif label == "unknown-tags":
        expected.update(
            {
                205: b"XxYz",
                206: b"ZzQq",
                213: b"XxYz",
                207: b"\0\x0c",
                210: b"unknown-comment",
            }
        )
    else:
        ordinary = label in {"ordinary-file", "empty-file"}
        expected.update(
            {
                205: b"Text File" if ordinary else b"TEXT (alias)",
                206: b"MOTH",
                213: b"TEXT",
            }
        )
        expected[207] = b"\0\0" if label == "empty-file" else b"\x01M"
        if label != "empty-file":
            expected[210] = b"alias-comment"
    dates = set() if label == "self-after-create" else {208, 209}
    require(set(actual) == set(expected) | dates, f"{label}: metadata presence differs")
    require(
        all(actual[k] == v for k, v in expected.items()),
        f"{label}: metadata bytes differ",
    )
    require(
        all(len(actual[k]) == 8 and actual[k] != bytes(8) for k in dates),
        "Metadata date width/value differs",
    )
    return actual


def creation(report: dict, expected: dict) -> None:
    label = expected["case"]
    before, after = listing(reply(report, 10)), listing(reply(report, 14))
    response = reply(report, 12)
    privileges = bytes(8) if expected["role"] == "low" else ADMIN
    require(
        fields(report["frames"][1]) == {110: privileges},
        "Alias privilege control differs",
    )
    if label in FAILURES:
        if label.startswith("permission"):
            message = b"You are not allowed to make aliases."
        elif label == "missing-source":
            message = b"Cannot make alias because there is no file/folder named \xd2missing\xd3."
        elif label in {"missing-destination", "destination-not-directory"}:
            message = b"Cannot make alias of \xd2file\xd3 because the destination folder could not be found."
        else:
            message = b"Cannot make alias of \xd2dir\xd3 because there is already a file/folder in the destination folder with the same name."
        require(
            response["error"] == 1 and fields(response) == {100: message},
            "Alias error outcome differs",
        )
        require(before == after, "Rejected alias changed the visible directory")
    else:
        require(response["error"] == 0 and fields(response) == {}, "Alias ACK differs")
        target = bytes.fromhex(expected["target_hex"])
        require(target in after, "Alias target name differs")
        if label in {"file-collision", "same-location"}:
            require(
                set(before) == set(after) and before[target] != after[target],
                "Alias replacement effect differs",
            )
        else:
            require(
                set(after) - set(before) == {target} and set(before) <= set(after),
                "Alias addition differs",
            )
        require(
            all(after[k] == v for k, v in before.items() if k != target),
            "Alias changed unrelated entry",
        )
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Alias control lost liveness",
    )


def download(report: dict, *, folder: bool = False, collision: bool = False) -> None:
    ack = fields(reply(report, 10))
    require(
        reply(report, 10)["error"] == 0 and len(ack[107]) == 4,
        "Alias download reference differs",
    )
    value = bytes.fromhex(report["streams"]["transfer"]["received_hex"])
    if folder:
        # Descriptor length, descriptor bytes, FILP length, then complete FILP.
        length = int.from_bytes(value[:2], "big")
        descriptor = value[2 : 2 + length]
        require(descriptor[-4:] == b"leaf", "Alias directory leaf differs")
        offset = 2 + length
        size = int.from_bytes(value[offset : offset + 4], "big")
        value = value[offset + 4 :]
        require(len(value) == size, "Alias folder transfer length differs")
    else:
        require(
            len(value) == int.from_bytes(ack[108], "big"),
            "Alias transfer advertised length differs",
        )
        require(
            reply(report, 11)["error"] == 0 and fields(reply(report, 11)) == {},
            "Alias cancellation ACK differs",
        )
    forks = decode(value)
    require(
        forks["DATA"]
        == (b"dir-leaf" if folder else b"same-source" if collision else DATA),
        "Alias resolved data fork differs",
    )
    require(
        forks["MACR"] == (b"" if folder or collision else resource_fork()),
        "Alias resolved resource fork differs",
    )
    info = forks["INFO"]
    n = int.from_bytes(info[70:72], "big")
    require(
        info[72 : 72 + n] == (b"leaf" if folder else b"same" if collision else b"file"),
        "Alias FILP resolved name differs",
    )
    require(reply(report, 90)["error"] == 0, "Alias transfer control lost liveness")


def catalogue(directory: Path) -> dict:
    snapshot = directory / "native-final"
    records = json.loads((snapshot / "extraction.json").read_text())["records"]
    require(len(records) == 33, "Final positive catalogue inventory differs")
    records = {r["path"]: r for r in records}
    prefix = "/Hotline19/Files/" + ROOT.decode()
    for suffix, physical in [
        ("/A/file", b""),
        ("/B/file", b""),
        ("/self", b"self-source"),
        ("/C/same", b"collision-destination"),
        ("/A/dir", b""),
    ]:
        record = records[prefix + suffix]
        key = record["key"]
        stat = (snapshot / (key + ".stat.txt")).read_text()
        require(
            not record["directory"]
            and "Is alias\n" in stat
            and "Type: alis" in stat
            and "ID: 0" in stat,
            "Missing physical alias flag/resource",
        )
        require(
            (snapshot / (key + ".data")).read_bytes() == physical,
            "Alias physical data fork differs",
        )
        require(
            len((snapshot / (key + ".rsrc")).read_bytes()) >= 540,
            "Missing physical alias resource bytes",
        )
        if suffix == "/A/dir":
            require(
                "66647270  fdrp" in stat and "4d414353  MACS" in stat,
                "Directory alias physical tags differ",
            )
    for suffix, data in [("/dir/leaf", b"dir-leaf"), ("/C/dir/keep", b"keep")]:
        require(
            (snapshot / (records[prefix + suffix]["key"] + ".data")).read_bytes()
            == data,
            "Alias changed ordinary directory child",
        )
    partial = json.loads((directory / "native-cleanup/extraction.json").read_text())[
        "records"
    ]
    require(
        len(partial) == 3
        and all(r["path"].startswith("/Trash/" + ROOT.decode() + "/") for r in partial),
        "Partial Trash observation differs",
    )
    return {
        "positive_before": 33,
        "positive_after": 3,
        "cleanup_disk_coverage": "Partial; not a persistence or exhaustive Trash proof",
    }


def listing_views(reports: dict) -> None:
    """Pin observed native enumeration sequences, without inventing a comparator."""
    root = listing(reply(reports["info/ordinary-file"], 11))
    require(
        list(root)
        == [
            b"A",
            b"B",
            b"C",
            b"D",
            b"dir",
            b"empty",
            b"file",
            b"hi-\x9a",
            b"m-al20-absent",
            b"m-al20-empty",
            b"m-al20-zero",
            b"same",
            b"self",
            b"unknown-tags",
            b"zero-tags",
        ],
        "Native root listing order/name bytes differ",
    )
    require(
        root[b"file"][:16] == b"TEXTMOTH" + (333).to_bytes(4, "big") + bytes(4),
        "File listing does not sum both forks",
    )
    require(
        root[b"self"][:16] == b"alis" + bytes(12), "Unattached alias listing differs"
    )
    require(
        root[b"dir"][:16] == b"fldr" + bytes(4) + (1).to_bytes(4, "big") + bytes(4),
        "Directory listing valence differs",
    )
    require(
        root[b"zero-tags"][:16] == bytes(8) + (9).to_bytes(4, "big") + bytes(4),
        "Zero-tag listing differs",
    )
    require(
        not listing(reply(reports["create/live-file"], 10)),
        "Empty directory representation differs",
    )
    for key in ["info/file-alias", "info/file-chain"]:
        alias = listing(reply(reports[key], 11))
        require(
            list(alias) == [b"dir", b"file"]
            and alias[b"file"] == root[b"file"]
            and alias[b"dir"] == root[b"dir"],
            "Alias listing exposes physical fork/tag or different ordering",
        )
    derived = listing(reply(reports["info/derived-alias"], 11))
    require(
        list(derived)
        == [b"derived-dir", b"derived-empty", b"derived-link", b"hi-\x9a"],
        "Derived alias listing order differs",
    )
    collision = listing(reply(reports["create/file-collision"], 14))[b"same"]
    require(
        collision[:16] == b"TEXTMOTH" + (11).to_bytes(4, "big") + bytes(4),
        "Collision alias listing uses physical destination size",
    )


def transfer_quiet(report: dict, plan: dict) -> None:
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(step["timeout"] == 3, "Alias transfer quiet interval differs")
        observations = [
            e
            for e in report["events"]
            if e["action"] == action and e["event"] == "quiet"
        ]
        previous = [e for e in report["events"] if e["action"] < action]
        require(
            len(observations) == 1
            and bool(previous)
            and observations[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
            >= 3_000_000_000,
            "Alias transfer quiet observation missing/short",
        )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = {
        "baseline": (
            login()
            + exchange(200, 10, [(202, b"\0\0")])
            + exchange(500, 90, [])
            + [close()],
            None,
        ),
        "seed": next(iter(seed().values())),
        "cleanup": next(iter(cleanup().values())),
    }
    for group, cases in [
        ("create", create()),
        ("info", information()),
        ("download", downloads()),
        ("damage", damage()),
        ("supplementary", supplementary()),
    ]:
        expected.update({group + "/" + key: value for key, value in cases.items()})
    for step in expected["baseline"][0]:
        step.pop("match_frame", None)
    failed = "initial/download-eof-file-alias"
    require(
        set(manifest["reports"]) == set(expected) | {failed},
        "Alias report inventory differs",
    )
    require(
        {str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")}
        == set(manifest["reports"]),
        "Unexpected/missing capture report",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 1504
        and manifest["host_kernel_drops"] == 0,
        "Alias host recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports = {}
    connections = 0
    for key in sorted(manifest["reports"]):
        case = directory / key
        report = verify_capture(case)
        plan = json.loads((case / "plan.json").read_text())
        require(
            report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Alias capture provenance differs",
        )
        require(
            report["status"]
            == manifest["reports"][key]
            == ("failed" if key == failed else "completed"),
            "Alias report disposition differs",
        )
        if key != failed:
            steps, expectation = expected[key]
            require(
                plan["steps"] == steps
                and (expectation is None or plan["expectation"] == expectation),
                "Alias plan differs",
            )
        else:
            require(
                report["completed_actions"] == 12
                and report["error"].startswith("TimeoutError:"),
                "Initial EOF failure differs",
            )
            require(
                len(bytes.fromhex(report["streams"]["transfer"]["received_hex"]))
                == 496,
                "Initial transfer was not complete before EOF timeout",
            )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith("create/"):
            creation(report, plan["expectation"])
            creation_quiet(report, plan)
        elif key.startswith("info/"):
            metadata(
                report,
                key.split("/")[1],
                bytes.fromhex(plan["expectation"]["name_hex"]),
            )
            listing(reply(report, 11))
        elif key.startswith("download/"):
            download(report, folder=plan["expectation"]["folder"])
            transfer_quiet(report, plan)
    require(
        connections == manifest["paired_connections"] == 66
        and manifest["completed_reports"] == 44
        and manifest["failed_reports"] == 1,
        "Alias aggregate counts differ",
    )
    download(reports["supplementary/collision-alias-download"], collision=True)
    transfer_quiet(
        reports["supplementary/collision-alias-download"],
        json.loads(
            (directory / "supplementary/collision-alias-download/plan.json").read_text()
        ),
    )
    listing_views(reports)
    repeated = reports["damage/repeat-existing-alias"]
    require(
        reply(repeated, 12)["error"] == 1
        and fields(reply(repeated, 12))
        == {
            100: b"Cannot make alias of \xd2file\xd3 because there is already a file/folder in the destination folder with the same name."
        },
        "Repeat-existing-alias rejection differs",
    )
    require(
        listing(reply(repeated, 10)) == listing(reply(repeated, 14))
        and fields(reply(repeated, 15))[207] == (333).to_bytes(2, "big"),
        "Repeated alias damaged a resolved chain",
    )
    rejected = reply(reports["supplementary/unattached-download-rejected"], 10)
    require(
        rejected["error"] == 1
        and fields(rejected)
        == {100: b"Cannot download because there is no file named \xd2self\xd3."},
        "Unattached alias download failure differs",
    )
    comment = reports["supplementary/directory-comment-through-alias"]
    for identifier in [20, 30, 40, 50]:
        require(
            reply(comment, identifier)["error"] == 0, "Directory comment update failed"
        )
        source, alias = (
            fields(reply(comment, identifier + 1)),
            fields(reply(comment, identifier + 2)),
        )
        require(
            source.get(210)
            == alias.get(210)
            == (b"directory-comment" if identifier in {20, 40} else None),
            "Resolved directory comment differs",
        )
    initial = listing(reply(reports["baseline"], 10))
    require(
        len(initial) == 41 and ROOT not in initial, "Alias baseline directory differs"
    )
    require(
        listing(reply(reports["seed"], 9)) == initial
        and listing(reply(reports["cleanup"], 90)) == initial,
        "Owned alias cleanup did not restore Files wire listing",
    )
    require(
        all(f["error"] == 0 for f in reports["cleanup"]["frames"]),
        "Owned alias cleanup ACK failed",
    )
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == 881007
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Alias runtime identity differs",
    )
    addresses = {
        "10017c10",
        "1002fb00",
        "1002b6f0",
        "10016ba0",
        "1002f600",
        "1002f5a0",
        "1002cf90",
        "1002b0e0",
        "1002e3d0",
        "100121a0",
        "100055a0",
        "1002cb20",
        "1002ce00",
        "1002f310",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == 14
        and {p.stem.removeprefix("AL-D-") for p in queries} == addresses,
        "Alias oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Alias oracle code/identity differs",
        )
    return {
        "completed_reports": 44,
        "failed_reports": 1,
        "paired_connections": connections,
        "metadata_kinds": 11,
        "creation_successes": 13,
        "creation_failures": 6,
        "oracle_queries": 14,
        "catalogue": catalogue(directory),
        "scope": "Native alias observations; no genuine deleted-target fixture, exhaustive filter/order policy, restart durability or mxd conformance proof",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
