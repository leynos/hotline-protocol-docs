"""Check the oracle queries that retained the ID-allocation functions."""

import json
import typing as typ

from protocol_capture import ORACLE_SHA256
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

QUERY_COUNT = 25
EXPLORATORY_ERROR = "ID-D-10058960"  # the one function query that is an error
LIFECYCLE_ADDRESSES = [
    "10058090",
    "10058880",
    "100589b0",
    "10058df0",
    "10058ca0",
    "10058d70",
    "100590e0",
    "10058fd0",
    "10014640",
    "10079e30",
]
INCREMENT_QUERY = "ID-A-10058d70"
INCREMENT_BYTES = "8083000c340400019003000c4082000c380000019003000c8063000c4e800020"


def check_queries(directory: Path, root: Path) -> None:
    """Check the inventory, identity and retained code of every oracle query."""
    queries = [
        q for p in directory.glob("oracle-*.json") for q in json.loads(p.read_text())
    ]
    require(
        len(queries) == QUERY_COUNT and len({q["id"] for q in queries}) == QUERY_COUNT,
        "ID oracle query inventory differs",
    )
    for query in queries:
        record = json.loads((root / (query["id"] + ".json")).read_text())
        require(
            record["query"] == query and record["program"]["sha256"] == ORACLE_SHA256,
            "ID oracle identity differs",
        )
        require(
            record["result"]["isError"] == (query["id"] == EXPLORATORY_ERROR),
            "Exploratory function-query outcome differs",
        )
        data = record["result"].get("structuredContent") or {}
        if "code" in data:
            require(
                data["code"] == (root / (query["id"] + ".c")).read_text(),
                "ID oracle code differs",
            )


def verify_oracle(directory: Path) -> None:
    """Verify the ID oracle queries and the increment instructions."""
    root = directory / "oracle-queries"
    check_queries(directory, root)
    for address in LIFECYCLE_ADDRESSES:
        code = (root / ("ID-D-" + address + ".c")).read_text()
        require("FUN_" + address + "(" in code, "Lifecycle function identity differs")
    instructions = json.loads((root / (INCREMENT_QUERY + ".json")).read_text())[
        "result"
    ]["structuredContent"]
    require(
        not instructions["has_more"]
        and "".join(i["bytes"] for i in instructions["items"]) == INCREMENT_BYTES,
        "32-bit increment/zero-skip instructions differ",
    )
