#!/usr/bin/env python3
"""Replay the frozen C39-C41 source and headless oracle findings offline."""

import hashlib
import json
import sys
import typing as typ
from pathlib import Path

from script_cli import run
from verify_native_download_send_path_checks import (
    check_queries,
    check_sources,
    code,
    includes,
    require,
)

# The source and decompiled-code checks live in
# verify_native_download_send_path_checks. require, code and includes are kept
# importable from this module because the original module defined them.
__all__ = [
    "C40",
    "C41",
    "FUNCTION_COUNT",
    "ORACLE_SHA",
    "QUERY_BUDGET",
    "check_queries",
    "check_sources",
    "code",
    "digest",
    "includes",
    "load",
    "require",
    "verify",
]

ORACLE_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
FUNCTION_COUNT = 1840  # the functions that the retained oracle binary holds
QUERY_BUDGET = 8  # the content queries that each of C40 and C41 may make
C40 = ["1006e040", "1006e1a0", "1006de10", "1006e0b0", "1006ddb0", "1002e300"]
C41 = [
    "10074930",
    "10071650",
    "10074b10",
    "10071950",
    "100742a0",
    "10070d20",
    "100749b0",
    "10071770",
]


def digest(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of a file.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, typ.Any]:
    """Parse a JSON file.

    Parameters
    ----------
    path : pathlib.Path
        The file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def check_manifest(manifest: dict[str, typ.Any]) -> None:
    """Check the schema, the binary identity and the query budget of the corpus.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed corpus manifest.
    """
    require(manifest["schema"] == "native-download-send-path-01", "Corpus schema")
    require(manifest["binary_sha256"] == ORACLE_SHA, "Binary identity")
    require(manifest["oracle_function_count"] == FUNCTION_COUNT, "Function count")
    require(
        manifest["c40_content_queries"] == QUERY_BUDGET
        and manifest["c41_content_queries"] == QUERY_BUDGET,
        "Query budget",
    )


def check_inventory(corpus: Path, files: dict[str, str]) -> None:
    """Check that the corpus holds exactly the listed files, with their digests.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    files : dict[str, str]
        The digest of each file, as the manifest lists it.
    """
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(actual == set(files), "Corpus inventory")
    for name, expected in files.items():
        require(digest(corpus / name) == expected, f"Corpus SHA: {name}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{value}  {name}" for name, value in sorted(files.items())],
        "SHA256SUMS list",
    )


def check_provenance(corpus: Path, files: dict[str, str]) -> None:
    """Check the source provenance record against the listed files.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    files : dict[str, str]
        The digest of each file, as the manifest lists it.
    """
    provenance = load(corpus / "source-provenance.json")
    require(
        provenance["schema"] == "native-download-send-path-source-provenance-01",
        "Source provenance schema",
    )
    require(
        set(provenance["sources"]) == set(files) - {"source-provenance.json"},
        "Source provenance inventory",
    )
    for name, entry in provenance["sources"].items():
        require(
            entry["sha256"] == files[name]
            and entry["bytes"] == (corpus / name).stat().st_size,
            f"Source provenance: {name}",
        )


def check_report(
    number: int,
    report: dict[str, typ.Any],
    addresses: list[str],
    extra_labels: list[str],
) -> None:
    """Check one oracle run, and the code of each function it queried.

    Parameters
    ----------
    number : int
        The number of the run, used in the error messages.
    report : dict[str, typing.Any]
        The parsed oracle report of the run.
    addresses : list[str]
        The functions that the run must have queried, in order.
    extra_labels : list[str]
        The labels that the run queried after the functions.
    """
    require(
        report["status"] == "complete" and report["project_unchanged"],
        f"C{number} run status",
    )
    require(
        report["project_before"] == report["project_after"],
        f"C{number} project mutation",
    )
    require(report["binary_sha256"] == ORACLE_SHA, f"C{number} binary hash")
    require(
        "--no-analyze" in report["args"]
        and "--discard" in report["args"]
        and "--save" not in report["args"],
        f"C{number} read-only invocation",
    )
    before = report["queries"][0]["result"]["structuredContent"]
    after = report["identity_after"]["structuredContent"]
    require(
        before == after
        and before["sha256"] == ORACLE_SHA
        and before["function_count"] == FUNCTION_COUNT,
        f"C{number} program identity",
    )
    expected_labels = ["identity-before", *addresses, *extra_labels]
    require(
        [q["label"] for q in report["queries"]] == expected_labels,
        f"C{number} query set",
    )
    for address in addresses:
        code(report, address)


def check_worker_caller(corpus: Path, c40: dict[str, typ.Any]) -> None:
    """Check the recorded call site of the download worker and its failed lookup.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    c40 : dict[str, typing.Any]
        The parsed oracle report of the C40 run.
    """
    caller = c40["queries"][-1]["result"]["structuredContent"]["callers"]
    require(
        caller["total"] == 1
        and caller["items"][0]["call_site"] == "100017e0"
        and caller["items"][0]["caller"] is None,
        "Worker call site",
    )
    failed_caller = load(corpus / "oracle/c40-caller.json")["result"]
    require(
        failed_caller["isError"]
        and "FUNCTION_NOT_FOUND" in failed_caller["content"][0]["text"],
        "Unannotated caller evidence",
    )


def verify(corpus: Path) -> None:
    """Verify the frozen send-path corpus in ``corpus``.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    manifest = load(corpus / "manifest.json")
    check_manifest(manifest)
    files = manifest["files"]
    check_inventory(corpus, files)
    check_provenance(corpus, files)
    c40, c41 = (load(corpus / f"oracle/c{n}-report.json") for n in (40, 41))
    check_report(40, c40, C40, ["worker-callers"])
    check_report(41, c41, C41, [])
    check_worker_caller(corpus, c40)
    check_sources(corpus)
    check_queries(c40, c41)


def show(corpus: str) -> None:
    """Verify the send-path corpus in ``corpus`` and report it as verified."""
    verify(Path(corpus))
    sys.stdout.write("native download send path: verified\n")


def main() -> None:
    """Verify a native download send-path corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
