"""Verify the sequence of cases, listings and oracle queries of the boundary corpus."""

import datetime as dt
import json
import typing as typ
from itertools import pairwise

import native_news_boundary_cases as cases
from native_news_decode import categories
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256
from verify_native_article_deletion import measured_wait
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_news_boundary_capture import Case, Corpus, Report, check_cases
from verify_native_news_boundary_checks import body, traversal
from verify_native_news_boundary_data import (
    ARTICLE_COUNT,
    BASELINE_ENTRY_COUNT,
    BYPASSED_ID,
    CATEGORY_AUX_COUNT,
    CONNECTION_COUNT,
    FIRST_CHILD_ID,
    HOST_PACKET_COUNT,
    LIST_FIELD,
    ORACLE_QUERY_COUNT,
    PARENT_ID,
    PRE_BYPASS_ID,
    REPLACEMENT_ID,
    REPORT_COUNT,
    RUNTIME_PID,
)
from verify_native_news_boundary_storage import storage
from verify_native_shx import fields, sha

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_runtime(runtime: Report) -> None:
    """Check that the corpus was recorded by the expected emulator.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The recorded runtime identity.
    """
    require(
        runtime["emulator_pid"] == RUNTIME_PID
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Boundary runtime identity differs",
    )


def append_ranges() -> list[tuple[int, int]]:
    """Return the inclusive ranges of identifiers that each append case posts.

    Returns
    -------
    list[tuple[int, int]]
        The first and last identifier of each append case, in order.
    """
    return [(n, min(n + 9, 99)) for n in range(1, 100, 10)] + [
        (100, 100),
        (101, 101),
        (102, 102),
    ]


def expected_cases(ranges: list[tuple[int, int]]) -> dict[str, Case]:
    """Return the planned steps and expectation of every case, by name.

    Parameters
    ----------
    ranges : list[tuple[int, int]]
        The identifier ranges of the append cases.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case, in the order it runs.
    """
    expected: dict[str, Case] = {"preflight": cases.preflight(), "seed": cases.seed()}
    expected.update({f"append-{a:03}-{b:03}": cases.append(a, b) for a, b in ranges})
    expected.update({
        "observe": cases.observe(),
        "final": cases.finalization(),
        "cleanup": cases.cleanup(),
        "publish": cases.publish_cleanup(),
        "remove-publisher": cases.remove_publisher(),
    })
    return expected


def read_corpus(directory: Path, manifest: Report, runtime: Report) -> Corpus:
    """Read the packets and the driver sources of the corpus.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    runtime : dict[str, typing.Any]
        The recorded runtime identity.

    Returns
    -------
    Corpus
        The corpus that the case checks read.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_packets"] == HOST_PACKET_COUNT
        and manifest["host_kernel_drops"] == 0,
        "Boundary packet recorder inventory differs",
    )
    return Corpus(
        directory,
        manifest,
        runtime,
        host,
        guest,
        {sha(p) for p in (directory / "sources").iterdir()},
    )


def check_appends(
    reports: dict[str, Report], ranges: list[tuple[int, int]]
) -> tuple[bytes, dict[int, bytes]]:
    """Check the sibling traversal before, during and after every append case.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each case, by name.
    ranges : list[tuple[int, int]]
        The identifier ranges of the append cases.

    Returns
    -------
    tuple[bytes, dict[int, bytes]]
        The last sibling list reply and the date of each article.
    """
    dates: dict[int, bytes] = {}
    previous = fields(reply(reports["seed"], 20))[LIST_FIELD]
    traversal(previous, 0, dates)
    for first, last in ranges:
        report = reports[f"append-{first:03}-{last:03}"]
        require(
            fields(reply(report, 10)) == {LIST_FIELD: previous},
            "Boundary before-list differs from preceding result",
        )
        for number in range(first, last + 1):
            require(
                fields(reply(report, 100 + number)) == {},
                "Post did not return empty ACK",
            )
        previous = fields(reply(report, 20))[LIST_FIELD]
        require(
            fields(reply(report, 21)) == {LIST_FIELD: previous},
            "Repeated boundary cache differs",
        )
        traversal(previous, last, dates)
    require(
        set(dates) == set(range(1, ARTICLE_COUNT + 1)),
        "Boundary did not observe all created article IDs",
    )
    return previous, dates


def check_observations(
    reports: dict[str, Report], previous: bytes, dates: dict[int, bytes]
) -> None:
    """Check the independent listings, the direct bodies and the quiet wait.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each case, by name.
    previous : bytes
        The last sibling list reply.
    dates : dict[int, bytes]
        The date that each article was first seen with.
    """
    for key in ["observe", "final"]:
        require(
            fields(reply(reports[key], 10)) == {LIST_FIELD: previous},
            "Independent boundary list differs",
        )
        rows = categories(reply(reports[key], 20))
        require(
            len(rows) == 1
            and rows[0]["name"] == b"siblings"
            and rows[0]["aux"] == CATEGORY_AUX_COUNT,
            "Category count must retain indexed orphan",
        )
    for identifier in [
        PARENT_ID,
        FIRST_CHILD_ID,
        100,
        PRE_BYPASS_ID,
        BYPASSED_ID,
        REPLACEMENT_ID,
    ]:
        body(reply(reports["observe"], 1000 + identifier), identifier, dates)
    measured_wait(reports["observe"], "expect_quiet")


def check_cleanup(reports: dict[str, Report]) -> None:
    """Check that each owned cleanup leaves the Files listing as it was.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each case, by name.
    """
    baseline = listing(reply(reports["preflight"], 11))
    require(len(baseline) == BASELINE_ENTRY_COUNT, "Boundary Files baseline differs")
    for key in ["cleanup", "publish", "remove-publisher"]:
        after = listing(reply(reports[key], 91))
        if key == "publish":
            require(b"m-nb25-publish" in after, "Boundary publisher missing")
            after.pop(b"m-nb25-publish")
        require(
            not categories(reply(reports[key], 90)) and after == baseline,
            "Boundary owned cleanup differs",
        )


def check_oracle_queries(directory: Path) -> None:
    """Check the inventory and the identity of the recorded oracle queries.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    """
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
        len(queries) == ORACLE_QUERY_COUNT
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


def verify(directory: Path) -> dict[str, object]:
    """Verify the native child append boundary corpus in ``directory``.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, object]
        The summary of the verified corpus.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    check_runtime(runtime)
    ranges = append_ranges()
    expected = expected_cases(ranges)
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Boundary report inventory differs",
    )
    corpus = read_corpus(directory, manifest, runtime)
    reports, connections = check_cases(corpus, expected)
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(expected)
        ),
        "Boundary chronology differs",
    )
    require(
        not categories(reply(reports["preflight"], 10)),
        "Owned News root was not initially empty",
    )
    previous, dates = check_appends(reports, ranges)
    check_observations(reports, previous, dates)
    check_cleanup(reports)
    storage(directory, previous, dates)
    check_oracle_queries(directory)
    require(
        len(reports) == manifest["completed_reports"] == REPORT_COUNT
        and connections == manifest["paired_connections"] == CONNECTION_COUNT,
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
        "scope": "Native child append boundary only; no all-category ceiling, "
        "root-sibling boundary, restart durability, interruption atomicity or "
        "historical-client claim",
    }
