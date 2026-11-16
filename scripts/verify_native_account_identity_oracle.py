"""Check the oracle queries that the identity corpus retained."""

import json
import typing as typ

from protocol_capture import ORACLE_SHA256
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

ADDRESSES = [
    "100146f0",
    "100149e0",
    "10014df0",
    "10007340",
    "10005f90",
    "10015e70",
    "100541e0",
    "100071a0",
    "1002af80",
    "1002ba20",
]
QUERY_PREFIX = "ID-D-"
DECOMPILE_TOOL = "decompile_function_by_address"


def check_query(path: Path) -> None:
    """Check one query's identity, tool, arguments and retained code."""
    query = json.loads(path.read_text())
    require(
        query["program"]["sha256"] == ORACLE_SHA256
        and not query["result"].get("isError", False)
        and query["query"]["tool"] == DECOMPILE_TOOL
        and query["query"]["arguments"] == {"address": path.stem[len(QUERY_PREFIX) :]}
        and query["result"]["structuredContent"]["code"]
        == path.with_suffix(".c").read_text(),
        "Identity oracle query failed",
    )


def check_oracle_queries(directory: Path) -> list[Path]:
    """Check the inventory of the oracle queries and each query in turn.

    Returns
    -------
    list[pathlib.Path]
        The query files.
    """
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        {p.stem for p in queries} == {QUERY_PREFIX + address for address in ADDRESSES},
        "Identity oracle query inventory differs",
    )
    for path in queries:
        check_query(path)
    return queries
