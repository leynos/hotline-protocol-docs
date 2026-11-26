#!/usr/bin/env python3
"""Verify native205 inputs, actual effects, paired streams and owned Trash cleanup."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from native_folder_cases import path
from native_mkdir_cases import (
    BASE,
    ROOT,
    cleanup,
    creation,
    empty_root,
    finalization,
    seed,
    specs,
)
from native_packet_evidence import reconcile
from native_transfer_cases import file_stream
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_shx import fields, sha

FAILURES = {
    "existing-directory",
    "existing-file",
    "case-collision",
    "name-absent",
    "name-empty",
    "parent-file",
    "parent-missing",
    "low-permission-new",
    "low-permission-conflict",
}


def listing(frame: dict) -> dict[bytes, bytes]:
    """Decode a file list reply into names and records."""
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "Listing failed",
    )
    result = {}
    for record in frame["fields"]:
        value = bytes.fromhex(record["hex"])
        require(
            record["id"] == 200
            and len(value) >= 20
            and int.from_bytes(value[16:20], "big") == len(value) - 20
            and value[12:16] == bytes(4),
            "File-list record grammar differs",
        )
        name = value[20:]
        require(name not in result, "Repeated file-list name")
        result[name] = value
    return result


def created_name(expected: dict) -> bytes:
    """Return the name that the server should give the created folder."""
    label = expected["case"]
    if label == "path-supplies-name":
        return b"via-path"
    if label == "empty-name-path-supplies":
        return b"via-empty"
    value = bytes.fromhex(expected["name_hex"])
    if label == "long-extension":
        return value[:27] + b".txt"
    return value[:31].replace(b":", b"-")


def check_creation(report: dict, expected: dict, agreement: bytes) -> dict:
    """Check one creation case's replies, listings and created name."""
    frames = report["frames"]
    require(
        [(f["type"], f["is_reply"], f["id"]) for f in frames]
        == [
            (0, 1, 1),
            (354, 0, 1),
            (109, 0, 2),
            (0, 1, 10),
            (0, 1, 11),
            (0, 1, 12),
            (0, 1, 90),
        ],
        "Creation response sequence differs",
    )
    require(
        fields(frames[0]) == {160: b"\0\xbe", 161: bytes(2)}
        and fields(frames[2]) == {101: agreement},
        "Creation bootstrap changed",
    )
    privileges = bytes(8) if expected["role"] == "low" else ADMIN
    require(
        fields(frames[1]) == {110: privileges}, "Creation permission control differs"
    )
    require(
        all(f["error"] == 0 for f in frames if f["id"] != 11), "Creation control failed"
    )
    before, after = listing(reply(report, 10)), listing(reply(report, 12))
    response = reply(report, 11)
    label = expected["case"]
    if label in FAILURES:
        if expected["role"] == "low":
            message = b"You are not allowed to create folders."
        else:
            name = bytes.fromhex(expected["name_hex"] or "")
            suffix = (
                b"the enclosing folder could not be found."
                if label in {"parent-file", "parent-missing"}
                else b"there is already a file or folder with that name."
            )
            message = b"Cannot create folder \xd2" + name + b"\xd3 because " + suffix
        require(
            response["error"] == 1 and fields(response) == {100: message},
            "Creation error outcome differs",
        )
        require(after == before, "Failed creation changed the visible directory")
        added = None
    else:
        added = created_name(expected)
        require(
            response["error"] == 0 and fields(response) == {},
            "Successful create ACK differs",
        )
        require(
            set(after) - set(before) == {added} and not (set(before) - set(after)),
            "Creation target or name bytes differ",
        )
        require(
            all(after[k] == v for k, v in before.items()),
            "Creation altered another listing record",
        )
        value = after[added]
        require(value[:16] == b"fldr" + bytes(12), "New directory record differs")
    require(fields(reply(report, 90)) == {}, "Creation liveness ACK differs")
    if label in {
        "path-dot-component",
        "path-dotdot-component",
        "path-colon-component",
        "path-high-component",
        "path-nul-component",
    }:
        require(
            not before, "Special component did not address its literal empty directory"
        )
    return {
        "case": label,
        "status": response["error"],
        "added_name_hex": None if added is None else added.hex(),
        "before_names_hex": [n.hex() for n in before],
        "after_names_hex": [n.hex() for n in after],
    }


def creation_quiet(report: dict, plan: dict) -> None:
    """Check only the explicitly bounded one-second post-liveness observation."""
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(step["timeout"] == 1, "Unexpected creation quiet interval")
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
            >= 1_000_000_000,
            "Missing or short creation quiet observation",
        )


def check_root_empty(report: dict, initial: dict[bytes, bytes]) -> None:
    """Check that creating at an empty root path fails each time and that the final root listing is unchanged."""
    message = b"Cannot create folder \xd2\xd3 because there is already a file or folder with that name."
    require(
        [f["id"] for f in report["frames"] if f["is_reply"]]
        == [1, 10, 20, 21, 22, 23, 24, 25, 90, 91],
        "Empty-root matrix shape differs",
    )
    for identifier in range(20, 26):
        frame = reply(report, identifier)
        require(
            frame["error"] == 1 and fields(frame) == {100: message},
            "Empty-root creation outcome differs",
        )
    require(
        listing(reply(report, 10)) == listing(reply(report, 90)) == initial
        and reply(report, 91)["error"] == 0
        and fields(reply(report, 91)) == {},
        "Empty-root inputs changed Files or lost liveness",
    )


def uploaded(report: dict, data: bytes) -> None:
    """Check the upload reference, taken from the first reply that has field 107, and the bytes sent for the fixture file."""
    values = fields(
        next(
            f
            for f in report["frames"]
            if f["is_reply"] and any(v["id"] == 107 for v in f["fields"])
        )
    )
    reference = values[107]
    require(
        len(reference) == 4 and int.from_bytes(reference, "big") != 0,
        "Missing native upload reference",
    )
    body = file_stream(data, b"")
    require(
        report["streams"]["upload"]["sent_hex"]
        == (b"HTXF" + reference + len(body).to_bytes(4, "big") + bytes(4) + body).hex()
        and report["streams"]["upload"]["received_hex"] == "",
        "Native setup upload bytes differ",
    )


def catalogue(directory: Path) -> dict:
    """Check the storage catalogues before and after the cleanup."""
    before_dir, after_dir = (
        directory / "native-before-cleanup",
        directory / "native-after-cleanup",
    )
    before_report = json.loads((before_dir / "extraction.json").read_text())
    after_report = json.loads((after_dir / "extraction.json").read_text())
    before = {r["catalog"]: r for r in before_report["records"]}
    after = {r["catalog"]: r for r in after_report["records"]}
    required = {
        "",
        "/exists",
        "/nest",
        "/nest/leaf",
        "/nest/leaf/nested-child",
        "/ordinary",
        "/plain",
    }
    prefix = "/Hotline19/Files/" + ROOT.decode()
    require(
        {prefix + tail for tail in required} <= {r["path"] for r in before.values()},
        "Missing positive native directory/file controls",
    )
    require(
        len(before) == 36 and len(after) == 44 and set(before) <= set(after),
        "Owned catalogue inventory differs",
    )
    for catalog, record in before.items():
        moved = after[catalog]
        require(
            moved["path"] == record["path"].replace("/Hotline19/Files/", "/Trash/", 1)
            and moved["directory"] == record["directory"],
            "Owned catalogue identity did not move intact to Trash",
        )
        for root, selected in [(before_dir, record), (after_dir, moved)]:
            text = (root / (selected["key"] + ".stat.txt")).read_text()
            require(
                "File Path: " + selected["path"] in text,
                "Positive native path evidence differs",
            )
        if record["path"] == prefix + "/ordinary":
            for root, selected in [(before_dir, record), (after_dir, moved)]:
                require(
                    selected["attributes"]["data"]["exit_code"] == 0
                    and (root / (selected["key"] + ".data")).read_bytes()
                    == b"mkdir-fixture",
                    "Trash move lost ordinary file bytes",
                )
    extra_names = [
        bytes.fromhex(c["name_hex"]).decode()
        for c in specs()
        if c["view_hex"] == "0000"
    ] + ["m-fs19-flush"]
    require(
        {r["path"] for k, r in after.items() if k not in before}
        == {"/Trash/" + n for n in extra_names},
        "Owned root cleanup targets differ",
    )
    return {
        "positive_before": len(before),
        "positive_after": len(after),
        "scope": "TSK paths render control/high bytes; raw filename claims use native listing bytes. Positive catalogue IDs and payload survive parent move; no recursive erase or universal durability inferred.",
    }


def verify(directory: Path) -> dict:
    """Verify the folder creation corpus and return the summary."""
    manifest = json.loads((directory / "manifest.json").read_text())
    cases = creation()
    require(
        set(manifest["cases"]) == set(cases)
        and {p.name for p in (directory / "captures").iterdir()} == set(cases)
        and len(cases) == 47,
        "Creation matrix inventory differs",
    )
    require(
        set(manifest["auxiliary"]) == {"seed", "final", "cleanup", "root-empty"},
        "Auxiliary inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 1417
        and manifest["host_kernel_drops"] == 0,
        "Recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    agreement = (
        (directory.parent / "native-agreement-01/original-agreement.data")
        .read_bytes()
        .replace(b"\r\n", b"\r")
    )
    reports = {}
    expected_all = {
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
        "root-empty": next(iter(empty_root().values())),
    }
    expected_all.update({"captures/" + name: value for name, value in cases.items()})
    connections = 0
    for key, (steps, expectation) in expected_all.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Native creation plan differs",
        )
        report = verify_capture(case)
        require(
            report["profile"] == "native-mac-oracle"
            and report["status"] == "completed"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Invalid native creation provenance",
        )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        creation_quiet(report, plan)
        reports[key] = report
    timeline = sorted(cases, key=lambda n: reports["captures/" + n]["started_at_utc"])
    require(
        timeline == [c["case"] for c in specs()], "Creation execution order differs"
    )
    require(
        datetime.fromisoformat(reports["seed"]["recorded_at_utc"])
        < datetime.fromisoformat(reports["captures/" + timeline[0]]["started_at_utc"])
        and reports["captures/" + timeline[-1]]["recorded_at_utc"]
        < reports["final"]["started_at_utc"]
        < reports["cleanup"]["started_at_utc"],
        "Native setup/final/cleanup chronology differs",
    )
    observed = [
        check_creation(reports["captures/" + c["case"]], c, agreement) for c in specs()
    ]
    seeded, final, cleaned = (reports[k] for k in ["seed", "final", "cleanup"])
    require(
        all(f["error"] == 0 for r in [seeded, final, cleaned] for f in r["frames"]),
        "Native auxiliary operation failed",
    )
    initial = listing(reply(seeded, 9))
    require(
        ROOT not in initial
        and not any(name.startswith(b"m-fs19-") for name in initial),
        "Owned preflight was not empty",
    )
    require(
        set(listing(reply(seeded, 15))) == {b"exists", b"nest", b"ordinary"},
        "Seed fixture differs",
    )
    uploaded(seeded, b"mkdir-fixture")
    uploaded(final, b"")
    expected_views = {
        path(()): set(initial) | {ROOT, b"m-fs19-flush"},
        BASE: {b"exists", b"nest", b"ordinary"},
        path((ROOT, b"nest")): {b"leaf"},
    }
    for c in specs():
        if c["case"] not in FAILURES:
            expected_views.setdefault(bytes.fromhex(c["view_hex"]), set()).add(
                created_name(c)
            )
    final_views = [
        (20, ()),
        (21, (ROOT,)),
        (22, (ROOT, b"nest")),
        (23, (ROOT, b"nest", b"leaf")),
        (24, (ROOT, b".")),
        (25, (ROOT, b"..")),
        (26, (ROOT, b"co-lon")),
        (27, (ROOT, b"hi-\x9a")),
        (28, (ROOT, b"\0nul")),
    ]
    for identifier, parts in final_views:
        require(
            set(listing(reply(final, identifier))) == expected_views[path(parts)],
            "Final native view differs from exact creation effects",
        )
    for identifier, expected_info in [
        (30, {205: b"Folder", 206: b"n/a", 213: b"fldr", 201: ROOT}),
        (
            31,
            {
                213: b"TEXT",
                205: b"Text File",
                206: b"MOTH",
                207: b"\0\r",
                201: b"ordinary",
                210: b"fixture-comment",
            },
        ),
    ]:
        info = fields(reply(final, identifier))
        require(
            set(info) == set(expected_info) | {208, 209}
            and all(info[key] == value for key, value in expected_info.items())
            and all(
                len(info[key]) == 8 and info[key] != bytes(8) for key in [208, 209]
            ),
            "Final native file-info kind matrix differs",
        )
    require(
        listing(reply(cleaned, 10)) == listing(reply(final, 20))
        and listing(reply(cleaned, 90)) == initial,
        "Owned cleanup did not restore the initial Files listing",
    )
    check_root_empty(reports["root-empty"], initial)
    require(
        reports["cleanup"]["recorded_at_utc"] < reports["root-empty"]["started_at_utc"],
        "Post-cleanup root controls were reordered",
    )
    require(
        (directory / "host.pcap").read_bytes()
        == (directory / "host-initial.pcap").read_bytes()
        + (directory / "host-empty.pcap").read_bytes()[24:],
        "Merged capture differs from literal recorder files",
    )
    snapshots = catalogue(directory)
    addresses = {
        "100143f0",
        "1002c070",
        "1002f080",
        "1002b0e0",
        "1002b670",
        "1002e8b0",
        "1002e3d0",
        "1002f800",
        "1002f0c0",
        "1002a9f0",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        {p.stem.removeprefix("FS-D-") for p in queries} == addresses
        and len(queries) == 10,
        "Missing native creation oracle queries",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["query"]["tool"] == "decompile_function_by_address"
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Oracle query identity/code differs",
        )
    return {
        "cases": 47,
        "auxiliary_reports": 4,
        "paired_connections": connections,
        "successes": 38,
        "expected_failures": 15,
        "root_empty_negative_inputs": 6,
        "observations": observed,
        "catalogue": snapshots,
        "scope": "Native205 on the recorded OS9 profile; field202 cases do not prove field212/325 equivalence, alias containment, portable name rules or all delete failures.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
