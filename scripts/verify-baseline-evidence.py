#!/usr/bin/env python3
"""Check captured queries, input identities, decompilation exports, and links."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from pinned_source import pinned_bytes


def verify(root: Path) -> None:
    evidence = root / "evidence/hotline-server-1.9"
    manifest = json.loads((evidence / "manifest.json").read_text())
    expected = manifest["program"]["sha256"]
    for helper in manifest["helper_scripts"]:
        if (
            hashlib.sha256(pinned_bytes(Path(helper["path"]).name)).hexdigest()
            != helper["sha256"]
        ):
            raise ValueError(f"Helper script changed: {helper['path']}")
    for item in manifest["inputs"]:
        saved = evidence / item["snapshot"]
        if hashlib.sha256(saved.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Input snapshot changed: {saved}")

    identifiers = set()
    data_pages = []
    for plan in sorted((evidence / "plans").glob("*.json")):
        for query in json.loads(plan.read_text()):
            identifier = query["id"]
            if identifier in identifiers:
                raise ValueError(f"Duplicate query ID: {identifier}")
            identifiers.add(identifier)
            saved = evidence / "queries" / (identifier + ".json")
            record = json.loads(saved.read_text())
            if record["query"] != query:
                raise ValueError(f"Query plan mismatch: {saved}")
            if record["program"]["sha256"] != expected:
                raise ValueError(f"Wrong oracle: {saved}")
            result = record["result"]
            if result["isError"]:
                raise ValueError(f"Failed MCP query: {saved}")
            data = result["structuredContent"]
            if data is None or data.get("truncated", False):
                raise ValueError(f"Missing or truncated result: {saved}")
            if "code" in data and saved.with_suffix(".c").read_text() != data["code"]:
                raise ValueError(f"Decompiler export changed: {saved}")
            if query["tool"] == "list_data_items":
                data_pages.append(data)
            elif data.get("has_more", False):
                raise ValueError(f"Incomplete query result: {saved}")

    saved_identifiers = {p.stem for p in (evidence / "queries").glob("*.json")}
    if (
        saved_identifiers != identifiers
        or len(identifiers) != manifest["capture_count"]
    ):
        raise ValueError("Capture inventory differs from the plans or manifest")

    offset = 0
    for page in sorted(data_pages, key=lambda item: item["offset"]):
        if page["offset"] != offset:
            raise ValueError("Data inventory pages have a gap or overlap")
        offset += len(page["items"])
        if page["total"] != data_pages[0]["total"]:
            raise ValueError("Data inventory total changed during capture")
    if offset != data_pages[0]["total"]:
        raise ValueError("Incomplete data inventory")

    ledger = root / "docs/baseline-validity-ledger.md"
    text = ledger.read_text()
    claims = re.findall(r"^\| ((?:V|M)\d{3}) \|", text, re.MULTILINE)
    if len(set(claims)) != len(claims):
        raise ValueError("Duplicate ledger claim ID")
    index = json.loads((evidence / "claims.json").read_text())
    if hashlib.sha256(ledger.read_bytes()).hexdigest() != index["ledger_sha256"]:
        raise ValueError("Ledger differs from the machine-readable claim index")
    if [item["id"] for item in index["claims"]] != claims:
        raise ValueError("Claim IDs differ between the ledger and index")
    if len(claims) != manifest["ledger_claim_count"]:
        raise ValueError("Ledger claim count differs from the manifest")
    for target in re.findall(r"^\[[^\]]+\]: (\S+)", text, re.MULTILINE):
        if not (ledger.parent / target).exists():
            raise ValueError(f"Broken evidence reference: {target}")
    for target in re.findall(r"\]\((\.\./evidence/[^)]+)\)", text):
        if not (ledger.parent / target).exists():
            raise ValueError(f"Broken handler reference: {target}")
    statuses = Counter(
        re.findall(r"^\| (?:V|M)\d{3} \| .*? \| ([^|]+) \|", text, re.MULTILINE)
    )
    print(f"Verified {len(identifiers)} MCP queries and {len(claims)} ledger entries")
    print(f"Complete data inventory: {offset} items")
    print(dict(statuses))


if __name__ == "__main__":
    verify(Path(__file__).resolve().parent.parent)
