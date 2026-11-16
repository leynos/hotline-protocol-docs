"""Check the oracle queries that the batch corpus retained."""

import json
import typing as typ

from protocol_capture import ORACLE_SHA256
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

QUERY_COUNT = 12
ASSEMBLY_FILE = "BA-A-10015500.json"
ASSEMBLY_ITEMS = 555
ADDRESSES = {
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


def check_query(path: Path) -> None:
    """Check one query's identity, and its code or its assembly listing."""
    q = json.loads(path.read_text())
    require(
        q["program"]["sha256"] == ORACLE_SHA256
        and not q["result"].get("isError", False),
        "Batch oracle identity/result differs",
    )
    if path.name.startswith("BA-D-"):
        require(
            q["result"]["structuredContent"]["code"]
            == path.with_suffix(".c").read_text(),
            "Batch oracle code differs",
        )
    else:
        assembly = q["result"]["structuredContent"]
        require(
            path.name == ASSEMBLY_FILE
            and len(assembly["items"]) == assembly["total"] == ASSEMBLY_ITEMS
            and not assembly["has_more"],
            "Batch complete assembly inventory differs",
        )


def check_oracle_queries(directory: Path) -> None:
    """Check the inventory of the oracle queries and each query in turn."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == QUERY_COUNT
        and {
            p.stem.removeprefix("BA-D-") for p in queries if p.name.startswith("BA-D-")
        }
        == ADDRESSES,
        "Batch oracle inventory differs",
    )
    for path in queries:
        check_query(path)
