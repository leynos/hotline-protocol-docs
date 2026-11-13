#!/usr/bin/env python3
"""Verify the native child append limit without hiding indexed orphan articles."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_news_boundary_cases as cases
from native_news_decode import articles, categories
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_article_deletion import measured_wait
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields, sha


def title(identifier: int) -> bytes:
    return b"parent" if identifier == 1 else f"child-{identifier - 1:03}".encode()


def traversal(value: bytes, children: int, dates: dict[int, bytes]) -> None:
    expected = list(range(1, children + 2))
    if children == 102:
        expected.remove(102)
    rows = articles(value)
    require([r["id"] for r in rows] == expected, "Sibling boundary traversal differs")
    for row in rows:
        identifier = row["id"]
        name = title(identifier)
        require(
            row["title"] == name
            and row["poster"] == b"framing-fixture"
            and row["parent"] == (0 if identifier == 1 else 1)
            and row["flags"] == 0
            and row["flavours"] == [(b"text/plain", 5 + len(name))],
            "Boundary article metadata differs",
        )
        require(
            row["date"][:4] == b"\x07p\0\0" and row["date"][4:] != bytes(4),
            "Boundary date representation differs",
        )
        if identifier in dates:
            require(
                row["date"] == dates[identifier],
                "Boundary append changed existing date",
            )
        dates[identifier] = row["date"]


def navigation(identifier: int) -> tuple[int, int, int, int]:
    if identifier == 1:
        return 0, 0, 0, 2
    previous = 0 if identifier == 2 else 101 if identifier == 103 else identifier - 1
    following = (
        103 if identifier == 101 else 0 if identifier in {102, 103} else identifier + 1
    )
    return previous, following, 1, 0


def body(frame: dict, identifier: int, dates: dict[int, bytes]) -> None:
    expected = {
        328: title(identifier),
        329: b"framing-fixture",
        327: b"text/plain",
        333: b"body-" + title(identifier),
        330: dates[identifier],
        **{
            k: v.to_bytes(2, "big")
            for k, v in zip([331, 332, 335, 336], navigation(identifier))
        },
    }
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Boundary direct body/navigation differs",
    )


def storage(directory: Path, wire: bytes, dates: dict[int, bytes]) -> None:
    final = directory / "native-final-positive"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(
        {r["path"] for r in rows}
        == {
            "/Hotline19/News/mothra-news25",
            "/Hotline19/News/mothra-news25/siblings",
            "/Hotline19/Files/m-nb25-flush",
        },
        "Boundary positive catalogue differs",
    )
    category = next(r for r in rows if r["path"].endswith("/siblings"))
    data = (final / (category["key"] + ".data")).read_bytes()

    def word(offset: int) -> int:
        return int.from_bytes(data[offset : offset + 4], "big")

    require(
        data[:8] == b"HLNZ\0\0\0\2" and word(32) == 256 and word(44) == 103,
        "Boundary stored article count/header differs",
    )
    offset = 512 + (word(36) - 1) * 256
    require(
        word(36) > 0
        and word(40) == len(wire)
        and data[offset : offset + len(wire)] == wire
        and len(articles(wire)) == 102,
        "Boundary cache must preserve count mismatch",
    )
    records = {}
    for start in range(512, len(data) - 255, 256):
        block = data[start : start + 256]
        if block[4:8] == b"\0\0\0\xc0":
            identifier = int.from_bytes(block[36:40], "big")
            require(identifier not in records, "Duplicate native article record")
            records[identifier] = (1 + (start - 512) // 256, block)
    require(set(records) == set(range(1, 104)), "Stored orphan article record missing")
    by_block = {block: identifier for identifier, (block, _) in records.items()}
    indexed = {}
    index_base = 512 + (word(72) - 1) * 256
    require(word(76) == 31, "Boundary native index mask differs")
    for bucket in range(32):
        start = index_base + bucket * 8
        first, count = word(start), word(start + 4)
        require(count <= 4, "Boundary index bucket cardinality differs")
        for i in range(count):
            entry = 512 + (first - 1) * 256 + i * 8
            identifier, native_block = word(entry), word(entry + 4)
            require(
                identifier not in indexed and identifier & 31 == bucket,
                "Boundary index entry differs",
            )
            indexed[identifier] = native_block
    require(
        indexed == {i: b for i, (b, _) in records.items()},
        "Native ID index does not preserve all 103 articles",
    )
    for identifier, (_, block) in records.items():
        links = tuple(int.from_bytes(block[n : n + 4], "big") for n in [40, 44, 48, 52])
        require(
            tuple(by_block[n] if n else 0 for n in links) == navigation(identifier),
            "Stored sibling/parent links differ",
        )
        length = block[68]
        require(
            block[69 : 69 + length] == title(identifier)
            and block[56:64] == dates[identifier],
            "Stored title/date differs",
        )
    # The two initial probes addressed catalogue IDs beyond the actual maximum.
    for name in ["native-final", "native-final-wide"]:
        require(
            json.loads((directory / name / "extraction.json").read_text())["records"]
            == [],
            "Out-of-range probe changed",
        )
    initial = json.loads((directory / "native-cleanup/extraction.json").read_text())[
        "records"
    ]
    require(
        len(initial) == 6
        and not ({r["catalog"] for r in initial} & {r["catalog"] for r in rows}),
        "Initial cleanup probe must remain inconclusive for owned objects",
    )
    published = directory / "native-published"
    after = {
        r["catalog"]: r
        for r in json.loads((published / "extraction.json").read_text())["records"]
    }
    require(
        len(after) == 10
        and set(after) == {r["catalog"] for r in rows + initial} | {11634},
        "Boundary published catalogue inventory differs",
    )
    require(
        after[11634]["path"] == "/Hotline19/Files/m-nb25-publish",
        "Separate boundary publisher differs",
    )
    for row in rows:
        moved = after[row["catalog"]]
        require(
            moved["path"]
            == row["path"]
            .replace("/Hotline19/News/", "/Trash/")
            .replace("/Hotline19/Files/", "/Trash/"),
            "Boundary Trash identity/path differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (final / (row["key"] + "." + fork)).read_bytes()
                    == (published / (moved["key"] + "." + fork)).read_bytes(),
                    "Boundary cleanup changed original fork/cache",
                )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == 1259319
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Boundary runtime identity differs",
    )
    ranges = [(n, min(n + 9, 99)) for n in range(1, 100, 10)] + [
        (100, 100),
        (101, 101),
        (102, 102),
    ]
    expected = {"preflight": cases.preflight(), "seed": cases.seed()}
    expected.update({f"append-{a:03}-{b:03}": cases.append(a, b) for a, b in ranges})
    expected.update(
        {
            "observe": cases.observe(),
            "final": cases.finalization(),
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
        "Boundary report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_packets"] == 927
        and manifest["host_kernel_drops"] == 0,
        "Boundary packet recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps
            and plan["expectation"] == expectation
            and plan["environment"] == runtime,
            "Boundary as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == manifest["reports"][key] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources
            and all(f["error"] == 0 for f in report["frames"]),
            "Boundary capture completion/provenance differs",
        )
        reference = (
            fields(reply(report, 80))[107].hex() if key in {"final", "publish"} else ""
        )
        for connection, recorded in report["streams"].items():
            sent = "".join(
                bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
                for s in steps
                if s["op"] == "send" and s["connection"] == connection
            )
            require(
                recorded["sent_hex"] == sent,
                "Boundary recorded request differs from plan",
            )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key == "seed" or key.startswith("append-"):
            measured_wait(report, "pause")
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(expected)
        ),
        "Boundary chronology differs",
    )
    require(
        not categories(reply(reports["preflight"], 10)),
        "Owned News root was not initially empty",
    )
    dates = {}
    previous = fields(reply(reports["seed"], 20))[321]
    traversal(previous, 0, dates)
    for first, last in ranges:
        report = reports[f"append-{first:03}-{last:03}"]
        require(
            fields(reply(report, 10)) == {321: previous},
            "Boundary before-list differs from preceding result",
        )
        for number in range(first, last + 1):
            require(
                fields(reply(report, 100 + number)) == {},
                "Post did not return empty ACK",
            )
        previous = fields(reply(report, 20))[321]
        require(
            fields(reply(report, 21)) == {321: previous},
            "Repeated boundary cache differs",
        )
        traversal(previous, last, dates)
    require(
        set(dates) == set(range(1, 104)),
        "Boundary did not observe all created article IDs",
    )
    for key in ["observe", "final"]:
        require(
            fields(reply(reports[key], 10)) == {321: previous},
            "Independent boundary list differs",
        )
        rows = categories(reply(reports[key], 20))
        require(
            len(rows) == 1 and rows[0]["name"] == b"siblings" and rows[0]["aux"] == 103,
            "Category count must retain indexed orphan",
        )
    for identifier in [1, 2, 100, 101, 102, 103]:
        body(reply(reports["observe"], 1000 + identifier), identifier, dates)
    measured_wait(reports["observe"], "expect_quiet")
    baseline = listing(reply(reports["preflight"], 11))
    require(len(baseline) == 41, "Boundary Files baseline differs")
    for key in ["cleanup", "publish", "remove-publisher"]:
        after = listing(reply(reports[key], 91))
        if key == "publish":
            require(b"m-nb25-publish" in after, "Boundary publisher missing")
            after.pop(b"m-nb25-publish")
        require(
            not categories(reply(reports[key], 90)) and after == baseline,
            "Boundary owned cleanup differs",
        )
    storage(directory, previous, dates)
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "10010470",
        "100229b0",
        "100247f0",
        "10024400",
        "10024280",
        "10023180",
        "10025900",
        "100233e0",
        "10005ac0",
        "10057de0",
    }
    require(
        len(queries) == 10
        and {p.stem.removeprefix("NB-D-") for p in queries} == addresses,
        "Boundary oracle inventory differs",
    )
    for p in queries:
        query = json.loads(p.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"].get("isError", False)
            and query["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Boundary oracle identity/code differs",
        )
    require(
        len(reports) == manifest["completed_reports"] == 20
        and connections == manifest["paired_connections"] == 22,
        "Boundary aggregate counts differ",
    )
    return {
        "completed_reports": 20,
        "paired_connections": connections,
        "posted_articles": 103,
        "stored_indexed_articles": 103,
        "reachable_list_articles": 102,
        "bypassed_but_readable_id": 102,
        "replacement_next_sibling": 103,
        "oracle_queries": 10,
        "scope": "Native child append boundary only; no all-category ceiling, root-sibling boundary, restart durability, interruption atomicity or historical-client claim",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
