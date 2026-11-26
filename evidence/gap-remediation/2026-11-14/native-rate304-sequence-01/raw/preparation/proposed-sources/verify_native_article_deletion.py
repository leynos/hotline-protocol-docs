#!/usr/bin/env python3
"""Check isolated native article deletion, paired packets and physical caches."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_news_delete_cases as cases
from native_news_decode import articles, categories
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields, sha

# These expected graphs are independent of the request generator. A zero flag
# promotes the first child and reparents the other children under that child.
TREES = {
    "unchanged": ([1, 2, 3], {2: [4, 5, 6], 4: [7, 8]}),
    "promote-parent": ([1, 4, 3], {4: [7, 8, 5, 6]}),
    "recursive-parent": ([1, 3], {}),
    "leaf": ([1, 2, 3], {2: [4, 5, 6], 4: [8]}),
    "promote-middle": ([1, 2, 3], {2: [7, 5, 6], 7: [8]}),
    "recursive-middle": ([1, 2, 3], {2: [5, 6]}),
    "head": ([2, 3], {2: [4, 5, 6], 4: [7, 8]}),
    "tail": ([1, 2], {2: [4, 5, 6], 4: [7, 8]}),
}
TITLES = {1: b"L", 2: b"A", 3: b"R", 4: b"B", 5: b"C", 6: b"F", 7: b"D", 8: b"E"}
BODY_ERROR = b"Cannot get article data because an invalid category was specified."
ID_ERROR = b"Cannot delete article because an invalid category or item was specified."
CATEGORY_ERROR = (
    b"Cannot delete article because the specified category could not be found."
)


def scalar_controls(specifications: list[dict]) -> None:
    """Check that the deletion cases have the expected scalar values and recursion flags."""
    expected = {
        "absent": (None, False),
        "empty": ("", False),
        "one-zero": ("00", False),
        "two-zero": ("0000", False),
        "four-zero": ("00000000", False),
        "one-one": ("01", True),
        "one-two": ("02", True),
        "one-ff": ("ff", True),
        "two-one": ("0001", True),
        "two-high": ("8000", True),
        "four-high": ("00010000", True),
        "three-one": ("000001", False),
        "five-one": ("00000001ff", True),
        "five-zero": ("00000000ff", False),
    }
    actual = {
        s["case"].removeprefix("parent-"): (
            s["value_hex"],
            s["mode"] == "recursive-parent",
        )
        for s in specifications
        if s["case"].startswith("parent-")
    }
    require(actual == expected, "Deletion scalar controls differ")


def graph(mode: str) -> tuple[list[int], dict[int, tuple[int, int, int, int]]]:
    """Return the traversal order and the link fields of the article tree in a mode."""
    roots, children = TREES[mode]
    order, links = [], {}

    def visit(siblings: list[int], parent: int) -> None:
        """Record the links of one sibling list and then of each sibling's descendants."""
        for index, identifier in enumerate(siblings):
            descendants = children.get(identifier, [])
            links[identifier] = (
                siblings[index - 1] if index else 0,
                siblings[index + 1] if index + 1 < len(siblings) else 0,
                parent,
                descendants[0] if descendants else 0,
            )
            order.append(identifier)
            visit(descendants, identifier)

    visit(roots, 0)
    return order, links


def list_records(value: bytes, mode: str) -> dict[int, dict]:
    """Decode an article list and check its order and metadata against the tree."""
    rows = articles(value)
    order, links = graph(mode)
    require([r["id"] for r in rows] == order, "Deletion traversal differs")
    for row in rows:
        identifier = row["id"]
        require(
            row["title"] == TITLES[identifier]
            and row["poster"] == b"framing-fixture"
            and row["parent"] == links[identifier][2]
            and row["flags"] == 0
            and row["flavours"] == [(b"text/plain", 6)]
            and row["date"][:4] == b"\x07p\0\0"
            and row["date"][4:] != bytes(4),
            "Deletion article metadata differs",
        )
    return {r["id"]: r for r in rows}


def error(frame: dict, message: bytes) -> None:
    """Require a failed reply with the given message."""
    require(
        frame["error"] == 1 and fields(frame) == {100: message},
        "Deletion error differs",
    )


def body(frame: dict, identifier: int, rows: dict[int, dict], mode: str) -> None:
    """Check the reply that reads an article body, or its error when the article is gone."""
    if identifier not in rows:
        error(frame, BODY_ERROR)
        return
    _, links = graph(mode)
    expected = {
        333: b"body-" + TITLES[identifier],
        328: TITLES[identifier],
        329: b"framing-fixture",
        327: b"text/plain",
        330: rows[identifier]["date"],
        **{
            key: n.to_bytes(2, "big")
            for key, n in zip([331, 332, 335, 336], links[identifier])
        },
    }
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Deletion body/navigation differs",
    )


def measured_wait(report: dict, operation: str) -> None:
    """Require a pause or quiet event that lasted at least three seconds."""
    event_name = "quiet" if operation == "expect_quiet" else "pause"
    events = report["events"]
    found = [i for i, e in enumerate(events) if e["event"] == event_name]
    require(len(found) == 1 and found[0] > 0, "Missing bounded pacing/quiet event")
    index = found[0]
    require(
        events[index]["elapsed_ns"] - events[index - 1]["elapsed_ns"] >= 3_000_000_000,
        "Short bounded pacing/quiet observation",
    )


def deletion(report: dict, spec: dict) -> bytes:
    """Check one deletion case's replies and the surviving article list."""
    before = list_records(fields(reply(report, 10))[321], "unchanged")
    after_value = fields(reply(report, 20))[321]
    after = list_records(after_value, spec["mode"])
    require(
        fields(reply(report, 21)) == {321: after_value}, "Repeated cached list differs"
    )
    require(
        all(row["date"] == before[i]["date"] for i, row in after.items()),
        "Deletion changed surviving dates",
    )
    label = spec["case"]
    if label in {"missing-id", "missing-id-field"}:
        error(reply(report, 11), ID_ERROR)
    elif label == "missing-category":
        error(reply(report, 11), CATEGORY_ERROR)
    elif label == "denied":
        error(reply(report, 11), b"You are not allowed to delete articles.")
    else:
        require(
            reply(report, 11)["error"] == 0 and fields(reply(report, 11)) == {},
            "Deletion ACK differs",
        )
    if spec["repeat"]:
        error(reply(report, 12), ID_ERROR)
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access) == {110: bytes(8) if spec["role"] == "low" else ADMIN},
        "Deletion access mask differs",
    )
    if spec["role"] == "low":
        error(reply(report, 101), b"You are not allowed to read articles.")
    else:
        for identifier in TITLES:
            body(reply(report, 100 + identifier), identifier, after, spec["mode"])
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Deletion lost liveness",
    )
    measured_wait(report, "expect_quiet")
    return after_value


def catalogue(directory: Path, references: dict[str, bytes]) -> None:
    """Check the final storage catalogue against the article tree."""
    final = directory / "native-final"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(len(rows) == 27, "Deletion positive catalogue inventory differs")
    for name, value in references.items():
        row = next(
            r for r in rows if r["path"] == "/Hotline19/News/mothra-news24/" + name
        )
        data = (final / (row["key"] + ".data")).read_bytes()
        stat = (final / (row["key"] + ".stat.txt")).read_text()
        block, index, length, count = (
            int.from_bytes(data[n : n + 4], "big") for n in [32, 36, 40, 44]
        )
        offset = 512 + (index - 1) * block
        require(
            not row["directory"]
            and data[:8] == b"HLNZ\0\0\0\2"
            and "484c4e5a  HLNZ" in stat
            and "48544c53  HTLS" in stat
            and count == len(articles(value))
            and block == 256
            and index > 0
            and length == len(value)
            and data[offset : offset + length] == value,
            "Deletion storage count/cache differs",
        )
    require(
        json.loads((directory / "native-cleanup/extraction.json").read_text())[
            "records"
        ]
        == [],
        "Initial inconclusive probe differs",
    )
    published = directory / "native-published"
    moved = {
        r["catalog"]: r
        for r in json.loads((published / "extraction.json").read_text())["records"]
    }
    originals = {r["catalog"]: r for r in rows}
    require(
        len(moved) == 28 and set(originals) < set(moved),
        "Published catalogue identities differ",
    )
    publisher = moved[next(iter(set(moved) - set(originals)))]
    require(
        publisher["path"] == "/Hotline19/Files/m-nd24-publish",
        "Separate publisher differs",
    )
    for identifier, row in originals.items():
        target = moved[identifier]
        require(
            target["path"]
            == row["path"]
            .replace("/Hotline19/News/", "/Trash/")
            .replace("/Hotline19/Files/", "/Trash/"),
            "Trash identity/path differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (final / (row["key"] + "." + fork)).read_bytes()
                    == (published / (target["key"] + "." + fork)).read_bytes(),
                    "Trash changed stored fork/cache",
                )


def verify(directory: Path) -> dict:
    """Verify the article deletion corpus and return the summary."""
    manifest = json.loads((directory / "manifest.json").read_text())
    inventory = json.loads((directory / "resume-inventory.json").read_text())
    specifications = cases.specs()
    scalar_controls(specifications)
    require(
        len(specifications) == 25 and len(inventory) == 25,
        "Deletion case inventory differs",
    )
    factories = {
        "initial/preflight": cases.preflight,
        "initial/burst": cases.initial_burst_seed,
        "initial/banned-login": cases.preflight,
        "inventory-recovery": cases.inspect_seed,
        "final": cases.finalization,
        "cleanup": cases.cleanup,
        "publish": cases.publish_cleanup,
        "remove-publisher": cases.remove_publisher,
    }
    expected = {k: next(iter(f().values())) for k, f in factories.items()}
    expected.update({"deletions/" + k: v for k, v in cases.deletions().items()})
    for spec in specifications:
        name = spec["case"]
        prefix = inventory[name]
        expected["resumed/" + name] = cases.resume_category(
            name, prefix["completed"], prefix["exists"]
        )[name]
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Deletion report inventory differs",
    )
    packets = {}
    for phase, suffix, count in [("initial", "", 321), ("recovery", "-recovery", 2198)]:
        host = read_packets(directory / ("host" + suffix + ".pcap"))
        guest = read_packets(
            directory
            / ("guest-initial.pcap" if phase == "initial" else "guest-recovery.pcap")
        )
        require(len(host) == count, "Deletion host packet count differs")
        packets[phase] = (host, guest)
    reports, connections = {}, 0
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    runtimes = {
        "initial": json.loads((directory / "runtime.json").read_text()),
        "recovery": json.loads((directory / "runtime-recovery.json").read_text()),
    }
    executable = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
    require(
        runtimes["initial"]["emulator_pid"] == 881007
        and runtimes["recovery"]["emulator_pid"] == 1259319
        and all(
            r["running_executable_sha256"] == executable for r in runtimes.values()
        ),
        "Deletion runtime identities differ",
    )
    application = json.loads(
        (directory / "recovery-application-identity.json").read_text()
    )
    require(
        application["catalog"] == 11183
        and application["data_sha256"] == ORACLE_SHA256
        and application["resource_sha256"]
        == "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
        "Recovery native application identity differs",
    )
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        phase = "initial" if key.startswith("initial/") else "recovery"
        require(
            plan["environment"] == runtimes[phase], "As-run runtime provenance differs"
        )
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Deletion as-run plan differs",
        )
        report = verify_capture(case)
        status = (
            "failed"
            if key in {"initial/burst", "initial/banned-login"}
            else "completed"
        )
        require(
            report["status"] == manifest["reports"][key] == status
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Deletion capture provenance differs",
        )
        for connection, recorded in report["streams"].items():
            reference = (
                fields(reply(report, 80))[107].hex()
                if key in {"final", "publish"}
                else ""
            )
            sent = "".join(
                bytes.fromhex(step["hex"].replace("{ref80}", reference)).hex()
                for step in steps[: report["completed_actions"]]
                if step["op"] == "send" and step["connection"] == connection
            )
            require(
                recorded["sent_hex"] == sent,
                "Recorded requests differ from executed plan prefix",
            )
        reconcile(
            report, *packets["initial" if key.startswith("initial/") else "recovery"]
        )
        connections += len(report["streams"])
        reports[key] = report
    chronology = (
        [
            "initial/preflight",
            "initial/burst",
            "initial/banned-login",
            "inventory-recovery",
        ]
        + ["resumed/" + s["case"] for s in specifications]
        + ["deletions/" + s["case"] for s in specifications]
        + ["final", "cleanup", "publish", "remove-publisher"]
    )
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(chronology)
        ),
        "Deletion phase chronology differs",
    )
    burst = reports["initial/burst"]
    require(
        burst["completed_actions"] == 248
        and len([f for f in burst["frames"] if f["is_reply"]]) == 121
        and all(f["error"] == 0 for f in burst["frames"])
        and burst["events"][-1]["elapsed_ns"] < 60_000_000_000
        and "EOFError" in burst["error"],
        "Retained flood burst differs",
    )
    error(
        reply(reports["initial/banned-login"], 1),
        b"You are temporarily banned on this server.",
    )
    recovered = reports["inventory-recovery"]
    require(
        not categories(reply(reports["initial/preflight"], 10)),
        "Owned initial News root not empty",
    )
    references = {}
    for index, spec in enumerate(specifications):
        name = spec["case"]
        prefix = inventory[name]
        count = 8 if index < 13 else 1 if index == 13 else 0
        require(
            prefix == {"completed": count, "exists": index < 14},
            "Recovered prefix inventory differs",
        )
        frame = reply(recovered, 100 + index)
        if count:
            rows = articles(fields(frame)[321])
            require(
                {r["id"] for r in rows} == set(range(1, count + 1)),
                "Recovered public IDs differ",
            )
            for row in rows:
                require(
                    row["title"] == TITLES[row["id"]]
                    and row["parent"] == graph("unchanged")[1][row["id"]][2],
                    "Recovered prefix identity differs",
                )
        else:
            error(
                frame,
                b"Cannot get article list because the specified category could not be found.",
            )
        resumed = reports["resumed/" + name]
        require(all(f["error"] == 0 for f in resumed["frames"]), "Bounded seed failed")
        seeded = list_records(fields(reply(resumed, 20))[321], "unchanged")
        if count:
            require(
                fields(reply(resumed, 10)) == fields(frame),
                "Prefix changed between inspection and resume",
            )
            require(
                all(seeded[row["id"]] == row for row in rows),
                "Resume changed existing article metadata",
            )
        require(
            fields(reply(reports["deletions/" + name], 10))
            == fields(reply(resumed, 20)),
            "Deletion did not start from verified seed",
        )
        measured_wait(resumed, "pause")
        references[name] = deletion(reports["deletions/" + name], spec)
        require(
            fields(reply(reports["final"], 100 + index)) == {321: references[name]},
            "Independent final list differs",
        )
    denied_rows = list_records(references["denied"], "unchanged")
    for identifier in TITLES:
        body(
            reply(reports["final"], 500 + identifier),
            identifier,
            denied_rows,
            "unchanged",
        )
    baseline = listing(reply(reports["initial/preflight"], 11))
    require(len(baseline) == 41, "Files baseline inventory differs")
    for key in ["final", "cleanup", "publish", "remove-publisher"]:
        require(
            all(f["error"] == 0 for f in reports[key]["frames"]),
            "Finalization/cleanup failed",
        )
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            not categories(reply(reports[key], 90))
            and listing(reply(reports[key], 91))
            == (
                baseline
                if key != "publish"
                else {
                    **baseline,
                    b"m-nd24-publish": listing(reply(reports[key], 91))[
                        b"m-nd24-publish"
                    ],
                }
            ),
            "Owned cleanup listing differs",
        )
    catalogue(directory, references)
    addresses = {
        "100108a0",
        "10023830",
        "100249f0",
        "10025060",
        "10024620",
        "10025120",
        "10024280",
        "10024150",
        "10023180",
        "10056b90",
        "10008ad0",
        "10005ac0",
        "100233e0",
        "100248a0",
        "1000acf0",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == 15
        and {p.stem.removeprefix("ND-D-") for p in queries} == addresses,
        "Deletion oracle inventory differs",
    )
    for p in queries:
        query = json.loads(p.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"].get("isError", False)
            and query["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Deletion oracle identity/code differs",
        )
    require(
        len(reports) == 58
        and connections == manifest["paired_connections"] == 60
        and manifest["completed_reports"] == 56
        and manifest["failed_reports"] == 2
        and manifest["host_kernel_drops"] == 0,
        "Deletion aggregate counts differ",
    )
    return {
        "reports": 58,
        "completed": 56,
        "retained_failures": 2,
        "paired_connections": connections,
        "deletion_cases": 25,
        "positive_categories": 25,
        "oracle_queries": 15,
        "scope": "These native fixtures; no natural ban expiry, interrupted-storage atomicity, restart durability or historical-client claim",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
