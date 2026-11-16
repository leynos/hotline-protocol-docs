#!/usr/bin/env python3
"""Check captured queries, input identities, decompilation exports, and links."""

import hashlib
import json
import operator
import re
import typing as typ
from collections import Counter
from pathlib import Path

from pinned_source import pinned_bytes

type Json = dict[str, typ.Any]


def sha256(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def check_manifest(evidence: Path, manifest: Json) -> str:
    """Check the helper scripts and the saved input snapshots.

    Each helper script is compared as it was pinned (``pinned_source``), not as
    it is now, so the recorded hash keeps its meaning while the script is
    refactored.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed manifest.

    Returns
    -------
    str
        The SHA-256 of the program that every query must have run against.

    Raises
    ------
    ValueError
        If a helper script or an input snapshot has changed.
    """
    expected = manifest["program"]["sha256"]
    for helper in manifest["helper_scripts"]:
        if sha256(pinned_bytes(Path(helper["path"]).name)) != helper["sha256"]:
            message = f"Helper script changed: {helper['path']}"
            raise ValueError(message)
    for item in manifest["inputs"]:
        saved = evidence / item["snapshot"]
        if sha256(saved.read_bytes()) != item["sha256"]:
            message = f"Input snapshot changed: {saved}"
            raise ValueError(message)
    return expected


def check_record(saved: Path, query: Json, expected: str) -> Json:
    """Check one saved query record against its planned query.

    Parameters
    ----------
    saved : pathlib.Path
        The record file.
    query : dict[str, typing.Any]
        The query as planned.
    expected : str
        The program hash that the record must carry.

    Returns
    -------
    dict[str, typing.Any]
        The record's structured result.

    Raises
    ------
    ValueError
        If the record differs from its plan, names another program, reports an
        error, is missing or truncated, or has a changed decompiler export.
    """
    record = json.loads(saved.read_text())
    if record["query"] != query:
        message = f"Query plan mismatch: {saved}"
        raise ValueError(message)
    if record["program"]["sha256"] != expected:
        message = f"Wrong oracle: {saved}"
        raise ValueError(message)
    result = record["result"]
    if result["isError"]:
        message = f"Failed MCP query: {saved}"
        raise ValueError(message)
    data = result["structuredContent"]
    if data is None or data.get("truncated", False):
        message = f"Missing or truncated result: {saved}"
        raise ValueError(message)
    if "code" in data and saved.with_suffix(".c").read_text() != data["code"]:
        message = f"Decompiler export changed: {saved}"
        raise ValueError(message)
    return data


def check_queries(evidence: Path, expected: str) -> tuple[set[str], list[Json]]:
    """Check every planned query, in plan-file order.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    expected : str
        The program hash that every record must carry.

    Returns
    -------
    tuple[set[str], list[dict[str, typing.Any]]]
        The query identifiers, and the results of the data-item listings.

    Raises
    ------
    ValueError
        If an identifier repeats, a record fails :func:`check_record`, or a
        query other than a data-item listing has more pages.
    """
    identifiers: set[str] = set()
    data_pages: list[Json] = []
    for plan in sorted((evidence / "plans").glob("*.json")):
        for query in json.loads(plan.read_text()):
            identifier = query["id"]
            if identifier in identifiers:
                message = f"Duplicate query ID: {identifier}"
                raise ValueError(message)
            identifiers.add(identifier)
            saved = evidence / "queries" / (identifier + ".json")
            data = check_record(saved, query, expected)
            if query["tool"] == "list_data_items":
                data_pages.append(data)
            elif data.get("has_more", False):
                message = f"Incomplete query result: {saved}"
                raise ValueError(message)
    return identifiers, data_pages


def check_inventory(evidence: Path, identifiers: set[str], manifest: Json) -> None:
    """Check that the saved queries are exactly the planned ones.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    identifiers : set[str]
        The identifiers named by the plans.
    manifest : dict[str, typing.Any]
        The parsed manifest.

    Raises
    ------
    ValueError
        If a saved query is unplanned, or the count differs from the manifest.
    """
    saved_identifiers = {p.stem for p in (evidence / "queries").glob("*.json")}
    if (
        saved_identifiers != identifiers
        or len(identifiers) != manifest["capture_count"]
    ):
        message = "Capture inventory differs from the plans or manifest"
        raise ValueError(message)


def check_pages(data_pages: list[Json]) -> int:
    """Check that the data-item pages tile one inventory without a gap.

    Parameters
    ----------
    data_pages : list[dict[str, typing.Any]]
        The results of the data-item listings.

    Returns
    -------
    int
        The number of items collected.

    Raises
    ------
    ValueError
        If the pages have a gap or an overlap, report different totals, or stop
        short of the total.
    """
    offset = 0
    for page in sorted(data_pages, key=operator.itemgetter("offset")):
        if page["offset"] != offset:
            message = "Data inventory pages have a gap or overlap"
            raise ValueError(message)
        offset += len(page["items"])
        if page["total"] != data_pages[0]["total"]:
            message = "Data inventory total changed during capture"
            raise ValueError(message)
    if offset != data_pages[0]["total"]:
        message = "Incomplete data inventory"
        raise ValueError(message)
    return offset


def check_claims(ledger: Path, text: str, evidence: Path, manifest: Json) -> list[str]:
    """Check the ledger's claim identifiers against the claim index.

    Parameters
    ----------
    ledger : pathlib.Path
        The ledger file.
    text : str
        The ledger's text.
    evidence : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed manifest.

    Returns
    -------
    list[str]
        The claim identifiers, in ledger order.

    Raises
    ------
    ValueError
        If an identifier repeats, the index records another ledger hash or
        other identifiers, or the count differs from the manifest.
    """
    claims = re.findall(r"^\| ((?:V|M)\d{3}) \|", text, re.MULTILINE)
    if len(set(claims)) != len(claims):
        message = "Duplicate ledger claim ID"
        raise ValueError(message)
    index = json.loads((evidence / "claims.json").read_text())
    if sha256(ledger.read_bytes()) != index["ledger_sha256"]:
        message = "Ledger differs from the machine-readable claim index"
        raise ValueError(message)
    if [item["id"] for item in index["claims"]] != claims:
        message = "Claim IDs differ between the ledger and index"
        raise ValueError(message)
    if len(claims) != manifest["ledger_claim_count"]:
        message = "Ledger claim count differs from the manifest"
        raise ValueError(message)
    return claims


def check_links(ledger: Path, text: str) -> None:
    """Check that every evidence link in the ledger points at a file.

    Parameters
    ----------
    ledger : pathlib.Path
        The ledger file; links are relative to its directory.
    text : str
        The ledger's text.

    Raises
    ------
    ValueError
        If a reference link or a handler link is broken; reference links are
        checked first.
    """
    for target in re.findall(r"^\[[^\]]+\]: (\S+)", text, re.MULTILINE):
        if not (ledger.parent / target).exists():
            message = f"Broken evidence reference: {target}"
            raise ValueError(message)
    for target in re.findall(r"\]\((\.\./evidence/[^)]+)\)", text):
        if not (ledger.parent / target).exists():
            message = f"Broken handler reference: {target}"
            raise ValueError(message)


def verify(root: Path) -> None:
    """Verify the baseline evidence beneath ``root`` and print a summary.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    """
    evidence = root / "evidence/hotline-server-1.9"
    manifest = json.loads((evidence / "manifest.json").read_text())
    expected = check_manifest(evidence, manifest)
    identifiers, data_pages = check_queries(evidence, expected)
    check_inventory(evidence, identifiers, manifest)
    items = check_pages(data_pages)
    ledger = root / "docs/baseline-validity-ledger.md"
    text = ledger.read_text()
    claims = check_claims(ledger, text, evidence, manifest)
    check_links(ledger, text)
    statuses = Counter(
        re.findall(r"^\| (?:V|M)\d{3} \| .*? \| ([^|]+) \|", text, re.MULTILINE)
    )
    print(f"Verified {len(identifiers)} MCP queries and {len(claims)} ledger entries")
    print(f"Complete data inventory: {items} items")
    print(dict(statuses))


if __name__ == "__main__":
    verify(Path(__file__).resolve().parent.parent)
