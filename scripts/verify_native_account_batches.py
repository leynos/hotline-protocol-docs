#!/usr/bin/env python3
"""Verify sequential batch outcomes, credential collisions and native storage."""

import argparse
import copy
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_account_batch_cases as cases
import native_account_batch_model as model
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_mkdir import listing
from verify_native_shx import fields, sha

SAVE_ERROR = b"Error saving list of accounts."
ERRORS = {
    **{
        name: SAVE_ERROR
        for name in [
            "empty-copy-continues",
            "empty-tlv-continues",
            "empty-batch",
            "identity-after-limit",
            "rename-collision",
            "distinct-rename-collision",
        ]
    },
    "create-update-denied": b"You are not allowed to modify account information.",
    "zero-role-denied": b"You are not allowed to modify account information.",
    "delete-create-denied": b"You are not allowed to create new accounts.",
    "update-delete-denied": b"You are not allowed to delete accounts.",
    "subset-denied": b"Cannot create account with more access than yourself.",
}


def batch_result(report: dict, spec: dict) -> None:
    frame = reply(report, 10)
    message = ERRORS.get(spec["case"])
    require(
        frame["error"] == (1 if message else 0)
        and fields(frame) == ({100: message} if message else {}),
        "Batch terminal ACK/error differs",
    )
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access)
        == {110: ADMIN if spec["role"] == "admin" else model.ROLES[spec["role"]]},
        "Batch role admission mask differs",
    )
    notices = [f for f in report["frames"] if f["type"] == 104]
    if spec["case"] == "collision-continues":
        require(
            len(notices) == 1
            and notices[0]["is_reply"] == 0
            and notices[0]["error"] == 0
            and fields(notices[0])
            == {
                101: b"Cannot create account \xd2m-b28-collision\xd3 because there is already an account with that login.",
                109: b"\0\1",
            }
            and report["frames"].index(notices[0]) < report["frames"].index(frame),
            "Batch collision notice/continuation differs",
        )
    else:
        require(not notices, "Unexpected per-item batch notice")
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Batch error lost control liveness",
    )


def inspect(
    report: dict, names: list[str], states: dict[str, model.State], baseline: list[str]
) -> None:
    for identifier, label in enumerate(names, 100):
        model.account_reply(reply(report, identifier), label, states)
    require(
        enumeration(reply(report, 90)) == model.enumeration(states, baseline),
        "Batch inspection global account state differs",
    )


def catalogue(directory: Path, snapshots: dict[str, dict[str, model.State]]) -> None:
    helpers = [
        "m-b28-seed-flush",
        "m-b28-final-flush",
        "m-b28-supp-seed-flush",
        "m-b28-supp-final-flush",
    ]
    counts = {
        "native-seed": 29,
        "native-final": 54,
        "native-distinct-seed": 59,
        "native-distinct-final": 64,
    }
    by_phase = {}
    for phase, states in snapshots.items():
        base = directory / phase
        rows = json.loads((base / "extraction.json").read_text())["records"]
        count = counts[phase]
        require(
            len(rows) == count and len({r["catalog"] for r in rows}) == count,
            "Batch positive catalogue count differs",
        )
        by_phase[phase] = {r["catalog"]: r for r in rows}
        expected_paths = {
            "/Hotline19/Users/m-b28-" + label + suffix
            for label in states
            for suffix in ["", "/UserData"]
        }
        if phase != "native-seed":
            expected_paths |= {
                "/Trash/m-b28-delete-a",
                "/Trash/m-b28-delete-a/UserData",
            }
        helper_count = [
            "native-seed",
            "native-final",
            "native-distinct-seed",
            "native-distinct-final",
        ].index(phase) + 1
        expected_paths |= {
            "/Hotline19/Files/" + name for name in helpers[:helper_count]
        }
        require(
            {r["path"] for r in rows} == expected_paths, "Batch native paths differ"
        )
        for row in rows:
            if not row["path"].endswith("/UserData"):
                continue
            label = row["path"].split("/")[-2].removeprefix("m-b28-")
            state = states.get(label, model.seed_states().get(label))
            require(
                state is not None
                and not row["directory"]
                and (base / (row["key"] + ".data")).read_bytes()
                == model.record(label, state)
                and (base / (row["key"] + ".rsrc")).read_bytes() == b"",
                "Batch stored account record differs",
            )
    seed = by_phase["native-seed"]
    final = by_phase["native-distinct-final"]
    for identifier, original in seed.items():
        expected_path = original["path"].replace(
            "/m-b28-rename-old", "/m-b28-rename-new"
        )
        if "/m-b28-delete-a" in expected_path:
            expected_path = expected_path.replace("/Hotline19/Users/", "/Trash/")
        require(
            identifier in final and final[identifier]["path"] == expected_path,
            "Batch rename/delete changed original catalogue identity",
        )
    distinct_seed = by_phase["native-distinct-seed"]
    for identifier, original in distinct_seed.items():
        require(
            identifier in final and final[identifier]["path"] == original["path"],
            "Rename collision must preserve both directory identities",
        )
    before = directory / "native-distinct-final"
    for phase, count in [("native-cleanup", 64), ("native-published", 65)]:
        base = directory / phase
        moved = {
            r["catalog"]: r
            for r in json.loads((base / "extraction.json").read_text())["records"]
        }
        require(
            len(moved) == count and set(final) <= set(moved),
            "Batch positive cleanup inventory differs",
        )
        for identifier, row in final.items():
            target = moved[identifier]
            expected = (
                row["path"]
                .replace("/Hotline19/Users/", "/Trash/")
                .replace("/Hotline19/Files/", "/Trash/")
            )
            require(
                target["path"] == expected and target["directory"] == row["directory"],
                "Batch cleanup path/identity differs",
            )
            if not row["directory"]:
                for fork in ["data", "rsrc"]:
                    require(
                        (before / (row["key"] + "." + fork)).read_bytes()
                        == (base / (target["key"] + "." + fork)).read_bytes(),
                        "Batch cleanup changed native fork",
                    )
        if phase == "native-published":
            extra = moved[next(iter(set(moved) - set(final)))]
            require(
                extra["path"] == "/Hotline19/Files/m-b28-publish",
                "Separate batch publisher differs",
            )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == 1259319
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
        and cases.OWNED == model.OWNED
        and cases.EXTRA == model.EXTRA,
        "Batch runtime/owned inventory differs",
    )
    specifications = cases.specifications()
    require(
        [s["case"] for s in specifications] == list(model.effects()),
        "Batch case order/inventory differs",
    )
    expected = {"preflight": cases.preflight(), "seed": cases.seed()}
    for spec in specifications:
        expected["before-" + spec["case"]] = cases.inspect(spec)
        expected["batch-" + spec["case"]] = cases.batch(spec)
        expected["after-" + spec["case"]] = cases.inspect(spec)
    distinct = cases.supplementary_spec()
    expected.update(
        {
            "nul-password-login": cases.probe_nul(),
            "final": cases.finalization(),
            "distinct-preflight": cases.inspect(distinct),
            "distinct-seed": cases.supplementary_seed(),
            "distinct-before": cases.inspect(distinct),
            "distinct-batch": cases.batch(distinct),
            "distinct-after": cases.inspect(distinct),
        }
    )
    expected.update(
        {
            "distinct-login-" + name: cases.supplementary_probe(name)
            for name in ["source", "destination-source", "destination-old"]
        }
    )
    inventory = json.loads((directory / "cleanup-inventory.json").read_text())
    expected.update(
        {
            "distinct-final": cases.supplementary_final(),
            "cleanup": cases.cleanup(inventory),
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
        "Batch report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == 1967
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Batch packet recorder count/drop differs",
    )
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps
            and plan["expectation"] == expectation
            and plan["environment"] == runtime,
            "Batch as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == manifest["reports"][key] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"]
            == sha(directory / "sources/protocol_capture.py"),
            "Batch capture provenance/completion differs",
        )
        reference = (
            fields(reply(report, 80))[107].hex()
            if key in {"seed", "final", "distinct-seed", "distinct-final", "publish"}
            else ""
        )
        for connection, recorded in report["streams"].items():
            sent = "".join(
                bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
                for s in steps
                if s["op"] == "send" and s["connection"] == connection
            )
            require(
                recorded["sent_hex"] == sent, "Batch recorded request differs from plan"
            )
        reconcile(report, host, guest)
        waits(report, steps)
        connections += len(report["streams"])
        reports[key] = report
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(expected)
        ),
        "Batch capture chronology differs",
    )
    baseline = enumeration(reply(reports["preflight"], 10))
    require(len(baseline) == 2, "Batch original account baseline differs")
    for identifier, label in enumerate(model.OWNED, 100):
        model.account_reply(reply(reports["preflight"], identifier), label, {})
    states = model.seed_states()
    snapshots = {"native-seed": copy.deepcopy(states)}
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Batch owned seed failed",
    )
    for identifier, label in enumerate(model.OWNED[:14], 200):
        model.account_reply(reply(reports["seed"], identifier), label, states)
    for spec in specifications:
        label = spec["case"]
        inspect(reports["before-" + label], spec["names"], states, baseline)
        batch_result(reports["batch-" + label], spec)
        model.apply(states, model.effects()[label])
        inspect(reports["after-" + label], spec["names"], states, baseline)
    snapshots["native-final"] = copy.deepcopy(states)
    for identifier, label in enumerate(model.OWNED, 100):
        model.account_reply(reply(reports["final"], identifier), label, states)
    require(
        enumeration(reply(reports["final"], 90)) == model.enumeration(states, baseline),
        "Main batch final enumeration differs",
    )
    inspect(reports["distinct-preflight"], model.EXTRA, states, baseline)
    inspect(
        reports["distinct-before"],
        model.EXTRA,
        {
            **states,
            "clash2-old": (
                b"Distinct28-clash2-old",
                b"source-pass28",
                bytes(8),
                b"distinct28",
            ),
            "clash2-new": (
                b"Distinct28-clash2-new",
                b"target-pass28",
                bytes(8),
                b"distinct28",
            ),
        },
        baseline,
    )
    for identifier, label in enumerate(model.EXTRA, 100):
        model.account_reply(reply(reports["distinct-seed"], identifier), label, states)
    model.distinct_seed(states)
    snapshots["native-distinct-seed"] = copy.deepcopy(states)
    batch_result(reports["distinct-batch"], distinct)
    model.distinct_effects(states)
    inspect(reports["distinct-after"], model.EXTRA, states, baseline)
    snapshots["native-distinct-final"] = copy.deepcopy(states)
    for identifier, label in enumerate(model.OWNED + model.EXTRA, 100):
        model.account_reply(reply(reports["distinct-final"], identifier), label, states)
    require(
        enumeration(reply(reports["distinct-final"], 90))
        == model.enumeration(states, baseline),
        "Distinct collision final enumeration differs",
    )
    for key in [
        "nul-password-login",
        "distinct-login-source",
        "distinct-login-destination-source",
        "distinct-login-destination-old",
    ]:
        report = reports[key]
        if key.endswith("-destination-old"):
            require(
                len(report["frames"]) == 1
                and reply(report, 1)["error"] == 1
                and fields(reply(report, 1)) == {100: b"Incorrect login."},
                "Collision destination retained old password",
            )
        else:
            require(
                [(f["type"], f["error"]) for f in report["frames"]]
                == [(0, 0), (354, 0), (109, 0), (0, 0)]
                and fields(report["frames"][1]) == {110: bytes(8)},
                "NUL/source collision credential login differs",
            )
    require(
        inventory == [name for name in model.OWNED + model.EXTRA if name in states]
        and len(inventory) == 29,
        "Observed batch cleanup inventory differs",
    )
    files = listing(reply(reports["preflight"], 11))
    require(len(files) == 41, "Batch Files baseline differs")
    for key in ["cleanup", "publish", "remove-publisher"]:
        report = reports[key]
        require(
            all(f["error"] == 0 for f in report["frames"])
            and enumeration(reply(report, 90)) == baseline,
            "Batch cleanup account baseline differs",
        )
        after = listing(reply(report, 91))
        if key == "publish":
            require(b"m-b28-publish" in after, "Batch publisher missing")
            after.pop(b"m-b28-publish")
        require(after == files, "Batch cleanup Files baseline differs")
    catalogue(directory, snapshots)
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "10015500",
        "10007510",
        "100076b0",
        "100071a0",
        "100075e0",
        "10007340",
        "100566b0",
        "10056d70",
        "10053a60",
        "1002bc30",
        "100565b0",
    }
    require(
        len(queries) == 12
        and {
            p.stem.removeprefix("BA-D-") for p in queries if p.name.startswith("BA-D-")
        }
        == addresses,
        "Batch oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False),
            "Batch oracle identity/result differs",
        )
        if p.name.startswith("BA-D-"):
            require(
                q["result"]["structuredContent"]["code"]
                == p.with_suffix(".c").read_text(),
                "Batch oracle code differs",
            )
        else:
            assembly = q["result"]["structuredContent"]
            require(
                p.name == "BA-A-10015500.json"
                and len(assembly["items"]) == assembly["total"] == 555
                and not assembly["has_more"],
                "Batch complete assembly inventory differs",
            )
    require(
        len(reports) == manifest["completed_reports"] == 70
        and connections == manifest["paired_connections"] == 75,
        "Batch aggregate counts differ",
    )
    return {
        "completed_reports": 70,
        "paired_connections": connections,
        "main_batch_cases": 18,
        "distinct_password_collision": 1,
        "terminal_batch_successes": 8,
        "terminal_batch_errors": 11,
        "owned_accounts_present_before_cleanup": 29,
        "original_objects_in_trash": 64,
        "oracle_queries": 12,
        "scope": "Owned 349 framing/default/permission/mixed-outcome fixtures; rename collision overwrites destination and continues, without rollback. No protected/self-delete, arbitrary I/O, all-exception translation or historical-client claim.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
