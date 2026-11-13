#!/usr/bin/env python3
"""Verify native category layouts, threaded lists, body graphs and owned cleanup."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

from native_news_cases import (
    ROOT,
    VERSIONS,
    bodies,
    cleanup,
    files_preflight,
    finalization,
    listings,
    posts,
    preflight,
    publish_cleanup,
    remove_publisher,
    seed,
    structures,
    thread_children,
    thread_grandchild,
)
from native_news_decode import articles, categories
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing
from verify_native_shx import fields, sha

RECORDS = {
    1: (b"First root", 0, 0, b"first-body\r\n\0\xff"),
    2: (b"Second root", 0, 0x11223344, b"second-body"),
    3: (b"Missing body", 0, 0, None),
    4: (b"long-" + b"x" * 26, 1, 0, b"B" * 65535),
    5: (b"Second child", 1, 0, b"child-two"),
    6: (b"Grandchild", 4, 0, b"grandchild-body"),
}
GRAPH = {
    1: (0, 2, 0, 4),
    2: (1, 3, 0, 0),
    4: (0, 5, 1, 6),
    5: (4, 0, 1, 0),
    6: (0, 0, 4, 0),
}


def article_records(value: bytes, order: list[int]) -> list[dict]:
    rows = articles(value)
    require(
        [r["id"] for r in rows] == order, "Article traversal order/public IDs differ"
    )
    for row in rows:
        title, parent, flags, body = RECORDS[row["id"]]
        require(
            row["title"] == title
            and row["poster"] == b"framing-fixture"
            and row["parent"] == parent
            and row["flags"] == flags,
            "Article title/poster/parent/flags differ",
        )
        require(
            row["flavours"] == ([] if body is None else [(b"text/plain", len(body))]),
            "Article flavour cardinality/name/size differs",
        )
        require(
            row["date"][:4] == b"\x07p\0\0" and row["date"][4:] != bytes(4),
            "Article native date representation differs",
        )
    return rows


def category_view(
    frame: dict, version: int, expected: list[tuple[bytes, bool, int]]
) -> list[dict]:
    rows = categories(frame)
    require(
        [r["name"] for r in rows] == [e[0] for e in expected],
        "Category order/name bytes differ",
    )
    for row, (_, folder, count) in zip(rows, expected):
        require(
            row["field"] == (320 if version < 15 else 323),
            "Category version branch differs",
        )
        require(
            row["kind"]
            == ((1 if folder else 10) if version < 15 else (2 if folder else 3)),
            "Category target kind differs",
        )
        if version >= 15:
            require(row["aux"] == count, "Category count/valence differs")
    return rows


def body_reply(report: dict, expected: dict, by_id: dict) -> None:
    frame = reply(report, 10)
    identifier = expected["id"]
    if expected["case"] in {
        "no-flavour",
        "unknown-flavour",
        "flavour-case",
        "unknown-article",
    }:
        require(
            frame["error"] == 1
            and fields(frame)
            == {
                100: b"Cannot get article data because an invalid category was specified."
            },
            "Body error family differs",
        )
    else:
        title, _, _, body = RECORDS[identifier]
        value = fields(frame)
        previous, following, parent, child = GRAPH[identifier]
        expected_fields = {
            333: body,
            328: title,
            329: b"framing-fixture",
            327: b"text/plain",
            330: by_id[identifier]["date"],
            **{
                k: n.to_bytes(2, "big")
                for k, n in zip(
                    [331, 332, 335, 336], [previous, following, parent, child]
                )
            },
        }
        require(
            frame["error"] == 0 and value == expected_fields,
            "Body bytes/navigation/date graph differs",
        )
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Body error/success lost control liveness",
    )


def structure(report: dict, expected: dict) -> None:
    label = expected["case"]
    if "low-" in label or label.endswith("low-permission"):
        operation = "delete" if label.startswith("delete") else "create"
        noun = "bundles" if "folder" in label else "categories"
        message = f"You are not allowed to {operation} news {noun}.".encode()
    elif label.startswith("delete"):
        message = b"Cannot delete news item because it could not be found."
    else:
        noun = b"bundle" if label.startswith("folder") else b"category"
        name = (
            b"bundle"
            if label.endswith("conflict-folder")
            else b"category"
            if label.endswith("conflict-category")
            else b"new"
        )
        reason = (
            b"there is already an item or bundle with that name."
            if "conflict" in label
            else b"the enclosing bundle could not be found."
        )
        message = (
            b"Cannot create news " + noun + b" \xd2" + name + b"\xd3 because " + reason
        )
    require(
        reply(report, 11)["error"] == 1 and fields(reply(report, 11)) == {100: message},
        "Structure error outcome differs",
    )
    before, after = categories(reply(report, 10)), categories(reply(report, 12))
    require(
        [{k: v for k, v in r.items() if k != "tail"} for r in before]
        == [{k: v for k, v in r.items() if k != "tail"} for r in after],
        "Rejected structure operation changed semantic listing",
    )
    access = next(f for f in report["frames"] if f["type"] == 354)
    require(
        fields(access) == {110: bytes(8) if expected["role"] == "low" else ADMIN},
        "Structure privilege control differs",
    )
    require(reply(report, 90)["error"] == 0, "Structure failure lost control liveness")


def catalogue(
    directory: Path, reference: dict[int, bytes], listing_rows: dict[bytes, dict]
) -> dict:
    final = directory / "native-final"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(len(rows) == 10, "News positive final catalogue inventory differs")
    objects = {r["catalog"]: r for r in rows}
    for suffix, count, cache_id in [
        ("category", 6, 20),
        ("zero-articles", 0, 21),
        ("bundle/nested", 1, 22),
        ("bundle/child/deep", 0, None),
    ]:
        row = next(
            r
            for r in rows
            if r["path"] == "/Hotline19/News/" + ROOT.decode() + "/" + suffix
        )
        data = (final / (row["key"] + ".data")).read_bytes()
        stat = (final / (row["key"] + ".stat.txt")).read_text()
        require(
            not row["directory"]
            and "484c4e5a  HLNZ" in stat
            and "48544c53  HTLS" in stat
            and data[:8] == b"HLNZ\0\0\0\2",
            "Native category storage kind/header differs",
        )
        require(
            int.from_bytes(data[44:48], "big") == count, "HLNZ article count differs"
        )
        name = suffix.split("/")[-1].encode()
        wire = listing_rows[name]
        require(
            wire["metadata"] == data[8:24]
            and wire["aux"] == int.from_bytes(data[44:48], "big") & 65535
            and wire["word20"] == int.from_bytes(data[24:28], "big")
            and wire["word24"] == int.from_bytes(data[28:32], "big"),
            "Modern category metadata does not match native header",
        )
        if cache_id is not None:
            block, index, length = (
                int.from_bytes(data[n : n + 4], "big") for n in [32, 36, 40]
            )
            offset = 512 + (index - 1) * block
            require(
                block == 256
                and index > 0
                and length == len(reference[cache_id])
                and data[offset : offset + length] == reference[cache_id],
                "HLNZ cached list does not match wire/rebuilt list",
            )
    initial = json.loads((directory / "native-cleanup/extraction.json").read_text())
    require(initial["records"] == [], "Initial inconclusive cleanup probe differs")
    published = directory / "native-published"
    published_rows = json.loads((published / "extraction.json").read_text())["records"]
    require(len(published_rows) == 11, "Published cleanup inventory differs")
    moved = {r["catalog"]: r for r in published_rows}
    require(
        set(objects) < set(moved),
        "Published cleanup lost original catalogue identities",
    )
    publisher = moved[next(iter(set(moved) - set(objects)))]
    require(
        publisher["path"] == "/Hotline19/Files/m-news23-publish"
        and (published / (publisher["key"] + ".data")).read_bytes() == b"metadata-data",
        "Separate publisher object differs",
    )
    for identifier, row in objects.items():
        target = moved[identifier]
        expected_path = (
            row["path"]
            .replace("/Hotline19/News/", "/Trash/")
            .replace("/Hotline19/Files/", "/Trash/")
        )
        require(
            target["path"] == expected_path,
            "Published Trash path/subtree identity differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (final / (row["key"] + "." + fork)).read_bytes()
                    == (published / (target["key"] + "." + fork)).read_bytes(),
                    "News cleanup changed stored forks/cache",
                )
    return {
        "positive_before": 10,
        "initial_positive_cleanup": 0,
        "positive_original_objects_after_upload_flush": 10,
        "separate_publisher": 1,
        "scope": "Publisher removed by wire ACK/listing; no post-removal disk/restart durability claim",
    }


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime-check.json").read_text())
    require(
        runtime["emulator_pid"] == 881007
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "News runtime identity differs",
    )
    factories = {
        "preflight": preflight,
        "seed": seed,
        "posts": posts,
        "files-preflight": files_preflight,
        "files-after": files_preflight,
        "final": finalization,
        "cleanup": cleanup,
        "publish": publish_cleanup,
        "remove-publisher": remove_publisher,
    }
    expected = {k: next(iter(f().values())) for k, f in factories.items()}
    expected["children"] = next(iter(thread_children(1).values()))
    expected["grandchild"] = next(iter(thread_grandchild(4).values()))
    for group, cases in [
        ("listings", listings()),
        ("structures", structures()),
        ("bodies", bodies()),
    ]:
        expected.update({group + "/" + k: v for k, v in cases.items()})
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "News report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 1246
        and manifest["host_kernel_drops"] == 0,
        "News packet recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "News as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "News capture provenance/completion differs",
        )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith(("listings/", "structures/", "bodies/")) or key == "posts":
            creation_quiet(report, plan)
    require(
        not categories(reply(reports["preflight"], 10))
        and all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "News owned preflight/seed failed",
    )
    chronology = (
        ["preflight", "seed", "posts", "children", "grandchild"]
        + [f"listings/version-{v}" for v in VERSIONS]
        + ["structures/" + name for name in structures()]
        + ["bodies/" + name for name in bodies()]
        + [
            "files-preflight",
            "final",
            "cleanup",
            "files-after",
            "publish",
            "remove-publisher",
        ]
    )
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(chronology)
        ),
        "News fixture chronology differs",
    )
    require(
        fields(reply(reports["posts"], 11)) == {321: bytes(10)},
        "Initial empty article-list differs",
    )
    for identifier, order in [(40, [1]), (41, [1, 2]), (43, [1, 2, 3])]:
        article_records(fields(reply(reports["posts"], identifier))[321], order)
    require(
        all(
            reply(reports["posts"], i)["error"] == 0
            and fields(reply(reports["posts"], i)) == {}
            for i in [20, 21, 22]
        ),
        "Valid initial posts failed",
    )
    require(
        reply(reports["posts"], 23)["error"] == 1
        and fields(reply(reports["posts"], 23))
        == {100: b"Cannot post article because invalid data was specified."},
        "Missing-body post error differs",
    )
    article_records(fields(reply(reports["children"], 41))[321], [1, 4, 5, 2, 3])
    rebuilt = fields(reply(reports["grandchild"], 40))[321]
    rows = article_records(rebuilt, [1, 4, 6, 5, 2, 3])
    by_id = {r["id"]: r for r in rows}
    root_entries = [
        (b"bundle", True, 2),
        (b"category", False, 6),
        (b"empty", True, 0),
        (b"hi-\x9a", True, 0),
        (b"zero-articles", False, 0),
    ]
    all_modern = {}
    tails = set()
    references = {}
    for version in VERSIONS:
        report = reports[f"listings/version-{version}"]
        root_rows = category_view(reply(report, 10), version, root_entries)
        require(not categories(reply(report, 11)), "Empty bundle listing differs")
        nested_rows = category_view(
            reply(report, 12), version, [(b"child", True, 1), (b"nested", False, 1)]
        )
        deep_rows = category_view(reply(report, 13), version, [(b"deep", False, 0)])
        for identifier in [20, 21, 22]:
            value = fields(reply(report, identifier))[321]
            if identifier in references:
                require(
                    value == references[identifier],
                    "Cached/version article-list bytes differ",
                )
            references[identifier] = value
        require(
            references[20] == rebuilt and references[21] == bytes(10),
            "Rebuilt/cached/empty article list differs",
        )
        nested = articles(references[22])
        require(
            len(nested) == 1
            and nested[0]["id"] == 1
            and nested[0]["title"] == b"Nested root"
            and nested[0]["flavours"] == [(b"text/plain", 11)],
            "Nested-category list differs",
        )
        if version >= 15:
            for row in root_rows + nested_rows + deep_rows:
                tails.add(row["tail"].hex())
                if row["kind"] == 3:
                    all_modern[row["name"]] = row
    require(
        any(bytes.fromhex(v) != bytes(len(bytes.fromhex(v))) for v in tails),
        "Nonzero opaque category tails not retained",
    )
    for label, (_, expectation) in structures().items():
        structure(reports["structures/" + label], expectation)
    for label, (_, expectation) in bodies().items():
        body_reply(reports["bodies/" + label], expectation, by_id)
    for key in ["final", "cleanup", "publish", "remove-publisher"]:
        require(
            all(f["error"] == 0 for f in reports[key]["frames"]),
            "News final/cleanup operation failed",
        )
    baseline = listing(reply(reports["files-preflight"], 10))
    require(
        len(baseline) == 41
        and b"m-news23-flush" not in baseline
        and b"m-news23-publish" not in baseline
        and listing(reply(reports["files-after"], 10))
        == listing(reply(reports["remove-publisher"], 90))
        == baseline,
        "News helper cleanup did not restore Files",
    )
    require(
        not categories(reply(reports["cleanup"], 90))
        and not categories(reply(reports["publish"], 90))
        and not categories(reply(reports["remove-publisher"], 91)),
        "Owned News hierarchy remains after cleanup",
    )
    require(
        manifest["completed_reports"] == len(reports) == 43
        and manifest["paired_connections"] == connections == 45,
        "News aggregate counts differ",
    )
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "10011960",
        "100102c0",
        "10005710",
        "1002cb20",
        "1002ce00",
        "10022830",
        "1006f350",
        "10022670",
        "10010ee0",
        "10011110",
        "10010b70",
        "1002cac0",
        "10008ad0",
        "10011370",
        "100059e0",
        "10010470",
        "100229b0",
        "10022ea0",
        "10023180",
        "10025900",
        "10025a60",
        "10025c60",
        "10025d80",
        "100248a0",
        "1006f2e0",
        "10011580",
        "10005ac0",
        "100233e0",
        "10057de0",
    }
    require(
        len(queries) == 29
        and {p.stem.removeprefix("NW-D-") for p in queries} == addresses,
        "News oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "News oracle identity/code differs",
        )
    return {
        "completed_reports": 43,
        "paired_connections": connections,
        "controlled_versions": VERSIONS,
        "threaded_public_id_order": [r["id"] for r in rows],
        "structure_errors": 14,
        "body_successes": 5,
        "body_errors": 4,
        "opaque_tail_hex": sorted(tails),
        "oracle_queries": 29,
        "catalogue": catalogue(directory, references, all_modern),
        "scope": "Native category/list fixtures, not identified modern peer coverage; broader navigation/date/flavour/sibling limits, posting/deletion/partial storage failures and restart durability remain open",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
