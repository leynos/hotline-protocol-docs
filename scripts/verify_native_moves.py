#!/usr/bin/env python3
"""Verify bounded native move/Trash effects without asserting untested failures."""

import argparse
import json
from pathlib import Path

from native_move_cases import (
    COMMENT,
    ROOT,
    cleanup,
    deletion_specs,
    deletions,
    finalization,
    move_specs,
    moves,
    preflight,
    seed,
)
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing
from verify_native_shx import fields, sha

FAILED_MOVES = {
    "file-collision",
    "folder-collision",
    "missing-source",
    "missing-destination",
    "destination-file",
    "low-permission",
    "own-child",
    "own-self",
}


def move(report: dict, spec: dict) -> dict:
    name, label = bytes.fromhex(spec["name_hex"]), spec["label"]
    expected_error = None
    if label == "missing-source":
        expected_error = (
            b"Cannot move because there is no file/folder named \xd2" + name + b"\xd3."
        )
    elif label in {"missing-destination", "destination-file"}:
        expected_error = (
            b"Cannot move \xd2"
            + name
            + b"\xd3 because the destination folder could not be found."
        )
    elif label in {"file-collision", "folder-collision"}:
        expected_error = (
            b"Cannot move \xd2"
            + name
            + b"\xd3 because there is already a file/folder in the destination folder with the same name."
        )
    elif label == "low-permission":
        expected_error = b"You are not allowed to move " + (
            b"folders." if spec["folder"] else b"files."
        )
    elif label in {"own-child", "own-self"}:
        expected_error = (
            b"Cannot move \xd2"
            + name
            + b"\xd3 into itself or into a subfolder of itself."
        )
    ack = reply(report, 13)
    require(
        ack["error"] == (1 if expected_error else 0)
        and fields(ack) == ({100: expected_error} if expected_error else {}),
        "Move ACK/error differs",
    )
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access) == {110: bytes(8) if spec["role"] == "low" else ADMIN},
        "Move privilege bitmap differs",
    )
    before, destination = listing(reply(report, 10)), listing(reply(report, 11))
    after, new_destination = listing(reply(report, 20)), listing(reply(report, 21))
    changed = label not in FAILED_MOVES | {"same-parent"}
    if changed:
        require(
            name in before
            and name not in destination
            and set(after) == set(before) - {name}
            and set(new_destination) == set(destination) | {name},
            "Move did not remove/add exact source entry",
        )
        require(
            new_destination[name] == before[name],
            "Move changed listing metadata/name bytes",
        )
        require(
            reply(report, 22)["error"] == 1 and reply(report, 23)["error"] == 0,
            "Moved old/new name resolution differs",
        )
        old_info, new_info = fields(reply(report, 12)), fields(reply(report, 23))
        require(
            all(
                old_info.get(k) == new_info.get(k)
                for k in [201, 205, 206, 207, 210, 213]
            ),
            "Move changed exposed metadata",
        )
    else:
        require(
            before == after and destination == new_destination,
            "Failed/same-parent move changed a listing",
        )
        require(
            reply(report, 22)["error"] == (1 if label == "missing-source" else 0),
            "Rejected move source resolution differs",
        )
    require(
        all(after[k] == v for k, v in before.items() if k != name),
        "Move changed unrelated source entry",
    )
    require(
        all(new_destination[k] == v for k, v in destination.items() if k != name),
        "Move changed unrelated destination entry",
    )
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Move control lost liveness",
    )
    return {
        "case": spec["case"],
        "error": expected_error is not None,
        "changed_location": changed,
    }


def deletion(report: dict, spec: dict) -> dict:
    label = spec["case"]
    name = (
        b"del-path-only"
        if spec["name_hex"] is None
        else bytes.fromhex(spec["name_hex"])
    )
    if label == "missing-source":
        error = b"Cannot delete \xd2no-such-delete\xd3 because it does not exist or cannot be found."
    elif label in {"denied-file", "denied-directory"}:
        error = b"You are not allowed to delete " + (
            b"folders." if label.endswith("directory") else b"files."
        )
    else:
        error = None
    ack = reply(report, 12)
    require(
        ack["error"] == (1 if error else 0)
        and fields(ack) == ({100: error} if error else {}),
        "Delete ACK/error differs",
    )
    before, after = listing(reply(report, 10)), listing(reply(report, 20))
    if error:
        require(before == after, "Rejected delete changed listing")
    else:
        require(
            name in before and set(after) == set(before) - {name},
            "Delete did not remove exactly the owned entry",
        )
        require(
            all(after[k] == v for k, v in before.items() if k != name),
            "Delete changed another listing record",
        )
        require(
            reply(report, 21)["error"] == 1,
            "Deleted source still resolves through original path",
        )
    if label == "alias-target-to-trash":
        values = fields(reply(report, 30))
        require(
            reply(report, 30)["error"] == 0
            and values[205] == b"TEXT (alias)"
            and values[207] == (332).to_bytes(2, "big")
            and values[210] == COMMENT,
            "Alias no longer resolves target moved to Trash",
        )
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access) == {110: bytes(8) if spec["role"] == "low" else ADMIN},
        "Delete privilege bitmap differs",
    )
    require(reply(report, 90)["error"] == 0, "Delete control lost liveness")
    return {"case": label, "error": error is not None}


def catalogue(directory: Path) -> dict:
    stages = {}
    for stage, count in [
        ("native-seeded", 72),
        ("native-final", 73),
        ("native-cleanup", 70),
    ]:
        rows = json.loads((directory / stage / "extraction.json").read_text())[
            "records"
        ]
        require(len(rows) == count, "Positive catalogue inventory differs")
        stages[stage] = {r["catalog"]: r for r in rows}
    before, after, cleaned = (
        stages[s] for s in ["native-seeded", "native-final", "native-cleanup"]
    )
    require(
        set(before) <= set(after) and len(set(after) - set(before)) == 1,
        "Move/delete lost seeded catalogue identity",
    )
    prefix = "/Hotline19/Files/" + ROOT.decode()
    original = {r["path"]: r for r in before.values()}
    changes = []
    for spec in move_specs():
        if spec["label"] in FAILED_MOVES | {"same-parent"}:
            continue
        name = bytes.fromhex(spec["name_hex"]).decode()
        old = prefix + "/S/" + name
        new = (
            "/Hotline19/Files/" + name
            if spec["label"].startswith("destination-")
            else prefix + "/D/" + name
        )
        changes.append((old, new))
    changes += [
        (prefix + "/del-file", "/Trash/del-file"),
        (prefix + "/del-nonempty", "/Trash/del-nonempty"),
        (prefix + "/del-path-only", "/Trash/del-path-only"),
        (prefix + "/del-c1/m-del22-dupe", "/Trash/m-del22-dupe"),
        (prefix + "/del-c2/m-del22-dupe", "/Trash/m-del22-dupe1"),
        (prefix + "/del-alias-target", "/Trash/del-alias-target"),
    ]
    for identifier, row in before.items():
        expected = row["path"]
        for old, new in changes:
            if expected == old or expected.startswith(old + "/"):
                expected = new + expected[len(old) :]
                break
        require(
            after[identifier]["path"] == expected,
            "Move/Trash catalogue path or child identity differs",
        )
        if row["directory"]:
            continue
        for fork in ["data", "rsrc"]:
            a = (directory / "native-seeded" / (row["key"] + "." + fork)).read_bytes()
            b = (
                directory / "native-final" / (after[identifier]["key"] + "." + fork)
            ).read_bytes()
            if row["path"] == prefix + "/del-alias" and fork == "rsrc":
                require(
                    a != b and len(a) == len(b) == 554,
                    "Alias resource refresh after target Trash move differs",
                )
            else:
                require(a == b, "Move/delete changed physical data/resource fork")
    require(
        set(cleaned) <= set(after)
        and all(r["path"].startswith("/Trash/") for r in cleaned.values()),
        "Partial cleanup observations do not identify Trash objects",
    )
    missing = {after[i]["path"] for i in set(after) - set(cleaned)}
    require(
        missing == {"/Hotline19/Files/m-mv22-f" + n for n in ["08", "09", "10"]},
        "Unobserved cleanup inventory differs",
    )
    for identifier, row in cleaned.items():
        prior = after[identifier]
        expected = prior["path"]
        if expected.startswith(prefix):
            expected = "/Trash/" + ROOT.decode() + expected[len(prefix) :]
        elif expected.startswith("/Hotline19/Files/"):
            expected = "/Trash/" + expected.removeprefix("/Hotline19/Files/")
        require(
            row["path"] == expected, "Owned cleanup changed subtree path or identity"
        )
    # A collision preserves both separately identified ordinary children.
    for source in [prefix + "/del-c1/m-del22-dupe", prefix + "/del-c2/m-del22-dupe"]:
        row = original[source]
        data = (
            directory / "native-final" / (after[row["catalog"]]["key"] + ".data")
        ).read_bytes()
        require(
            data == b"delete-child-" + source.split("/")[-2].encode(),
            "Trash collision lost distinct source bytes",
        )
    return {
        "positive_seeded": 72,
        "positive_final": 73,
        "positive_cleanup": 70,
        "all_seeded_identities_retained_before_cleanup": True,
        "cleanup_disk_coverage": "Partial: three root file markers lack positive post-move probes",
    }


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime-check.json").read_text())
    require(
        runtime["emulator_pid"] == 881007
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Move runtime identity differs",
    )
    expected = {
        "preflight": next(iter(preflight().values())),
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
    }
    expected.update({"moves/" + k: v for k, v in moves().items()})
    expected.update({"deletions/" + k: v for k, v in deletions().items()})
    require(
        set(manifest["reports"])
        == set(expected)
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Move report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 1875
        and manifest["host_kernel_drops"] == 0,
        "Move packet inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Move as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Move capture provenance/completion differs",
        )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith(("moves/", "deletions/")):
            creation_quiet(report, plan)
    observed_moves = [move(reports["moves/" + s["case"]], s) for s in move_specs()]
    observed_deletes = [
        deletion(reports["deletions/" + s["case"]], s) for s in deletion_specs()
    ]
    initial = listing(reply(reports["preflight"], 10))
    require(
        len(initial) == 41
        and ROOT not in initial
        and not any(n.startswith(b"m-mv22-") for n in initial),
        "Move preflight names were not absent",
    )
    require(
        fields(reply(reports["preflight"], 20))[110] == bytes(8),
        "Low-account preflight bitmap differs",
    )
    require(
        all(
            f["error"] == 0
            for r in [reports["seed"], reports["final"], reports["cleanup"]]
            for f in r["frames"]
        ),
        "Move auxiliary operation failed",
    )
    require(
        listing(reply(reports["cleanup"], 90)) == initial,
        "Owned move cleanup did not restore Files wire listing",
    )
    require(
        manifest["completed_reports"] == len(reports) == 39
        and manifest["paired_connections"] == connections == 75,
        "Move aggregate counts differ",
    )
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "100177d0",
        "1002c130",
        "100140e0",
        "1002ba20",
        "1002bf70",
        "10080140",
        "1002b0e0",
        "1002c630",
        "1002e120",
        "1007f230",
        "10008ab0",
    }
    require(
        len(queries) == 11
        and {p.stem.removeprefix("MV-D-") for p in queries} == addresses,
        "Move oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Move oracle identity/code differs",
        )
    return {
        "completed_reports": 39,
        "paired_connections": connections,
        "move_successes": 12,
        "move_errors": 14,
        "delete_successes": 6,
        "delete_errors": 3,
        "moves": observed_moves,
        "deletions": observed_deletes,
        "catalogue": catalogue(directory),
        "scope": "Same-volume OS9 fixtures; cross-volume, locked/protected targets, interrupted I/O, root deletion, every refresh and restart durability remain unproven. Trash-target alias remains live, not a missing-target fixture.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
