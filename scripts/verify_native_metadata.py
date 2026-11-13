#!/usr/bin/env python3
"""Verify native207 presence, permission and partial-effect observations."""

import argparse
import json
from pathlib import Path

from native_auth_cases import complement
from native_metadata_cases import (
    ACCOUNTS,
    ROOT,
    account_cleanup,
    boundaries,
    cleanup,
    combined_empty,
    final_name,
    finalization,
    mutations,
    preflight,
    seed,
    specs,
)
from native_packet_evidence import reconcile
from native_plan import packet, payload
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing
from verify_native_shx import fields, sha


def expected_comment(spec: dict) -> bytes | None:
    value = spec["comment_hex"]
    if value is None or spec["role"] in {"rename", "neither"}:
        return b"base-comment"
    value = bytes.fromhex(value)
    return None if value in {b"", b"\0"} else value[:199]


def info(frame: dict, name: bytes, folder: bool, comment: bytes | None) -> None:
    require(frame["error"] == 0, "Expected final metadata failed")
    actual = fields(frame)
    expected = {
        201: name,
        205: b"Folder" if folder else b"Text File",
        206: b"n/a" if folder else b"MOTH",
        213: b"fldr" if folder else b"TEXT",
    }
    if not folder:
        expected[207] = b"\0\r"
    if comment is not None:
        expected[210] = comment
    require(set(actual) == set(expected) | {208, 209}, "Metadata presence differs")
    require(
        all(actual[k] == v for k, v in expected.items()),
        "Metadata name/comment/type bytes differ",
    )
    require(all(len(actual[k]) == 8 for k in [208, 209]), "Metadata date width differs")


def mutation(report: dict, spec: dict) -> dict:
    name, new = bytes.fromhex(spec["name_hex"]), final_name(spec)
    folder, role = spec["folder"], spec["role"]
    info(reply(report, 10), name, folder, b"base-comment")
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access) == {110: ADMIN if role == "admin" else ACCOUNTS[role][1]},
        "Mutation privilege bitmap differs",
    )
    ack = reply(report, 12)
    conflict = spec["case"].endswith("comment-before-conflict")
    denied_comment = role in {"rename", "neither"} and spec["comment_hex"] is not None
    denied_rename = role == "comment" and spec["new_hex"] is not None
    noun = b"folders" if folder else b"files"
    if conflict:
        error = (
            b"Cannot set info for \xd2"
            + name
            + b"\xd3:\rA file or folder with the specified name already exists.\rID 4/115 [-48]"
        )
    elif denied_comment:
        error = b"You are not allowed set comments for " + noun + b"."
    elif denied_rename:
        error = b"You are not allowed to rename " + noun + b"."
    else:
        error = None
    require(
        ack["error"] == (1 if error else 0)
        and fields(ack) == ({100: error} if error else {}),
        "Mutation ACK/error differs",
    )
    if new != name:
        old = reply(report, 20)
        require(
            old["error"] == 1
            and fields(old)
            == {
                100: b"Cannot get info because there is no file/folder named \xd2"
                + name
                + b"\xd3."
            },
            "Old name still resolves after rename",
        )
    else:
        info(reply(report, 20), name, folder, expected_comment(spec))
    if new != name or spec["new_hex"] in {None, "", spec["name_hex"]}:
        info(reply(report, 21), new, folder, expected_comment(spec))
    elif conflict:
        info(reply(report, 21), b"occupied", False, b"base-comment")
    else:
        require(
            reply(report, 21)["error"] == 1,
            "Denied rename unexpectedly created destination",
        )
    before, after = listing(reply(report, 11)), listing(reply(report, 22))
    if new != name:
        require(
            set(after) == (set(before) - {name}) | {new},
            "Rename listing effect differs",
        )
        require(
            after[new] == before[name][:16] + len(new).to_bytes(4, "big") + new,
            "Rename changed size/type or name grammar",
        )
    else:
        require(before == after, "Comment/no-op/rejected rename changed listing")
    require(
        all(after[k] == v for k, v in before.items() if k != name),
        "Mutation changed another listing entry",
    )
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Mutation control lost liveness",
    )
    comment = expected_comment(spec)
    return {
        "case": spec["case"],
        "error": error is not None,
        "renamed": new != name,
        "comment_hex": None if comment is None else comment.hex(),
    }


def comment_boundaries(report: dict) -> None:
    for index, size in enumerate([0, 1, 198, 199, 200, 201, 254, 255, 256, 300, 65535]):
        identifier = 100 + index * 2
        require(
            reply(report, identifier)["error"] == 0
            and fields(reply(report, identifier)) == {},
            "Boundary write failed",
        )
        values = fields(reply(report, identifier + 1))
        require(
            reply(report, identifier + 1)["error"] == 0
            and values.get(210) == (None if size == 0 else b"x" * min(size, 199)),
            "Comment readback boundary differs",
        )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = {
        "preflight": next(iter(preflight().values())),
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
        "account-cleanup": next(iter(account_cleanup().values())),
    }
    expected.update({"mutations/" + k: v for k, v in mutations().items()})
    expected.update({"boundaries/" + k: v for k, v in boundaries().items()})
    expected.update({"combined-empty/" + k: v for k, v in combined_empty().items()})
    # Preserve the actual initial mistake rather than silently replacing its plan.
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 30):
        encoded = packet(351, identifier, payload([(105, complement(name))]))
        for step in expected["cleanup"][0]:
            if step.get("hex") == encoded:
                step["hex"] = packet(351, identifier, payload([(105, name)]))
    require(
        set(manifest["reports"])
        == set(expected)
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Metadata corpus inventory differs",
    )
    require(
        (directory / "host.pcap").read_bytes()
        == (directory / "host-initial.pcap").read_bytes()
        + (directory / "host-account-cleanup.pcap").read_bytes()[24:]
        + (directory / "host-combined-empty.pcap").read_bytes()[24:],
        "Merged host capture differs from literal recordings",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 2161
        and manifest["host_kernel_drops"] == 0,
        "Metadata host recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Metadata as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Metadata provenance/completion differs",
        )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith("mutations/"):
            creation_quiet(report, plan)
    observed = [mutation(reports["mutations/" + s["case"]], s) for s in specs()]
    for label in ["file", "dir"]:
        comment_boundaries(reports["boundaries/" + label])
    baseline = listing(reply(reports["preflight"], 10))
    require(
        len(baseline) == 41 and ROOT not in baseline,
        "Owned tree preflight was not empty",
    )
    for label, (_, expectation) in combined_empty().items():
        report = reports["combined-empty/" + label]
        name, final = (
            bytes.fromhex(expectation["name_hex"]),
            bytes.fromhex(expectation["final_hex"]),
        )
        require(
            name not in baseline and final not in baseline,
            "Supplementary owned name was not absent",
        )
        info(reply(report, 10), name, expectation["folder"], b"base-comment")
        require(
            reply(report, 12)["error"] == 0 and fields(reply(report, 12)) == {},
            "Combined empty mutation failed",
        )
        info(
            reply(report, 21),
            final,
            expectation["folder"],
            bytes.fromhex(expectation["comment_hex"]) or None,
        )
        if name != final:
            require(
                reply(report, 20)["error"] == 1, "Combined clear/rename left old name"
            )
        require(
            reply(report, 40)["error"] == 0
            and listing(reply(report, 9)) == listing(reply(report, 90)) == baseline,
            "Combined empty cleanup did not restore Files",
        )
        creation_quiet(
            report,
            json.loads(
                (directory / "combined-empty" / label / "plan.json").read_text()
            ),
        )
    for identifier, (name, privileges) in enumerate(ACCOUNTS.values(), 20):
        require(
            reply(reports["preflight"], identifier)["error"] == 1
            and fields(reply(reports["preflight"], identifier))
            == {100: b"No account with login \xd2" + name + b"\xd3."},
            "Owned account preflight was not empty",
        )
        require(
            reply(reports["seed"], identifier)["error"] == 0
            and fields(reply(reports["seed"], identifier + 10))[110] == privileges,
            "Seed account creation/bitmap differs",
        )
        require(
            reply(reports["cleanup"], identifier + 10)["error"] == 1
            and reply(reports["cleanup"], identifier + 20)["error"] == 0,
            "Initial cleanup mistake was not preserved",
        )
        require(
            reply(reports["account-cleanup"], identifier + 10)["error"] == 0,
            "Corrected account deletion failed",
        )
        absent = reply(reports["account-cleanup"], identifier + 20)
        require(
            absent["error"] == 1
            and fields(absent)
            == {100: b"No account with login \xd2" + name + b"\xd3."},
            "Owned account remains after corrected cleanup",
        )
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Native metadata seed failed",
    )
    for identifier, spec in enumerate(specs(), 100):
        info(
            reply(reports["final"], identifier),
            final_name(spec),
            spec["folder"],
            expected_comment(spec),
        )
    require(
        reply(reports["cleanup"], 20)["error"] == 0
        and listing(reply(reports["cleanup"], 90))
        == listing(reply(reports["account-cleanup"], 90))
        == baseline,
        "Owned cleanup did not restore Files wire listing",
    )
    require(
        manifest["completed_reports"] == len(reports) == 49
        and manifest["paired_connections"] == connections == 72,
        "Metadata aggregate counts differ",
    )
    addresses = {
        "100170c0",
        "1002c690",
        "1002bc30",
        "1002c070",
        "1002f600",
        "100564c0",
        "10056c70",
        "10008ab0",
        "1002e120",
        "1007ea90",
        "1002c740",
        "1007ee40",
        "1007ed00",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == 13
        and {p.stem.removeprefix("MT-D-") for p in queries} == addresses,
        "Metadata oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Metadata oracle identity/code differs",
        )
    return {
        "completed_reports": 49,
        "paired_connections": connections,
        "mutation_cases": 36,
        "combined_empty_cases": 6,
        "boundary_writes": 22,
        "oracle_queries": 13,
        "observations": observed,
        "scope": "Native207 metadata effects and bounded silence; no all-or-nothing guarantee, restart durability, portable comment storage capacity or complete error/notification coverage",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
