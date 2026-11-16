#!/usr/bin/env python3
"""Verify native category layouts, threaded lists, body graphs and owned cleanup."""

import json
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
from pcap_tcp import read_packets
from script_cli import run
from verify_native_news_catalogue import catalogue
from verify_native_news_checks import check_results
from verify_native_news_data import GRAPH, RECORDS
from verify_native_news_records import article_records, category_view
from verify_native_news_replay import (
    check_inventory,
    check_packets,
    check_runtime,
    expected_cases,
    replay_cases,
)
from verify_native_news_replies import body_reply, structure
from verify_native_shx import sha

# The planner and decoder names are imported here as the original module imported
# them, so they remain importable from this module. The other re-exports are the
# names the original defined publicly.
__all__ = [
    "GRAPH",
    "RECORDS",
    "ROOT",
    "VERSIONS",
    "article_records",
    "articles",
    "bodies",
    "body_reply",
    "catalogue",
    "categories",
    "category_view",
    "cleanup",
    "files_preflight",
    "finalization",
    "listings",
    "posts",
    "preflight",
    "publish_cleanup",
    "remove_publisher",
    "seed",
    "structure",
    "structures",
    "thread_children",
    "thread_grandchild",
    "verify",
]


def verify(directory: Path) -> dict:
    """Verify the native news corpus in ``directory`` and summarise it.

    Returns
    -------
    dict
        The summary of the verified corpus.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_runtime(directory)
    expected = expected_cases()
    check_inventory(directory, manifest, expected)
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    check_packets(manifest, host)
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = replay_cases(directory, expected, sources, (host, guest))
    return check_results(directory, manifest, reports, connections)


def show(directory: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native news corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
