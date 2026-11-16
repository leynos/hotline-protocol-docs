#!/usr/bin/env python3
"""Offline semantic checks for the bounded Classic account-constructor trace."""

import json
import re
import typing as typ
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/client-account-constructors-01"
CLIENT_SHA = "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
JAR_SHA = "201d18ffde71a83a678eae607de265861f37e5a00b989d91958c1197664d2b43"
INITIAL_CONTENT_CALLS = 11  # the content queries that the first B37 report records
PROGRAM_INFO_QUERIES = 2  # the two program-identity queries of a run
B38_CONTENT_CALLS = 8  # the content queries of the B38 batch
B39_CONTENT_CALLS = 3  # the content queries of the B39 batch


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    message: str,
) -> None:
    """Raise a ValueError with the message when a retained fact does not hold.

    Raises
    ------
    ValueError
        With ``message``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def load_evidence(base: Path = CORPUS) -> dict[str, typ.Any]:
    """Read the five retained reports of the account-constructor corpus.

    Returns
    -------
    dict[str, typing.Any]
        The parsed reports, keyed by their names.
    """
    names = (
        "b36-preparation",
        "b37-report",
        "b37-followup",
        "b38-report",
        "b39-report",
    )
    return {name: json.loads((base / f"{name}.json").read_text()) for name in names}


def result(query: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Return the structured content of one retained tool query.

    Returns
    -------
    dict[str, typing.Any]
        The structured content of the query's result.
    """
    payload = query.get("result", {})
    require(not payload.get("isError", False), "retained tool error")
    content = payload.get("structuredContent")
    require(isinstance(content, dict), "missing structured tool result")
    return content


def code(queries: list[dict[str, typ.Any]], address: str) -> str:
    """Return the decompiled code of the one query made for an address.

    Returns
    -------
    str
        The decompiled source.
    """
    found = [
        result(query).get("code")
        for query in queries
        if query.get("tool") == "decompile_function_by_address"
        and query.get("arguments", {}).get("address") == address
    ]
    require(
        len(found) == 1 and isinstance(found[0], str), f"missing decompile {address}"
    )
    return typ.cast("str", found[0])


def program_pair(queries: list[dict[str, typ.Any]]) -> dict[str, typ.Any]:
    """Check that the program identity is the pinned client, and unchanged.

    Returns
    -------
    dict[str, typing.Any]
        The program information.
    """
    info = [
        result(query) for query in queries if query.get("tool") == "get_program_info"
    ]
    require(
        len(info) == PROGRAM_INFO_QUERIES and info[0] == info[1],
        "program identity changed",
    )
    expected = {
        "sha256": CLIENT_SHA,
        "language_id": "PowerPC:BE:32:default",
        "executable_format": "Preferred Executable Format (PEF)",
        "endian": "big",
        "pointer_size": 4,
        "function_count": 3564,
    }
    for key, value in expected.items():
        require(info[0].get(key) == value, f"program {key} changed")
    return info[0]


def nested_ids(source: str, object_name: str) -> list[int]:
    """Return the field identifiers that are appended to a named object.

    Returns
    -------
    list[int]
        The field identifiers, in source order.
    """
    pattern = rf"FUN_100b05d0\({re.escape(object_name)},0x([0-9a-f]+),"
    return [int(value, 16) for value in re.findall(pattern, source)]


def direct_ids(source: str) -> list[int]:
    """Return the field identifiers that are appended directly to the object.

    Returns
    -------
    list[int]
        The field identifiers, in source order.
    """
    pattern = r"FUN_100b(?:0800|05d0)\(param_1\[2\],0x([0-9a-f]+),"
    return [int(value, 16) for value in re.findall(pattern, source)]


def check_preparation(prep: dict[str, typ.Any]) -> None:
    """Check the prepared client DATA and resource hashes."""
    require(prep.get("data_sha256") == CLIENT_SHA, "prepared DATA hash changed")
    require(
        prep.get("resource_sha256")
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b",
        "resource hash changed",
    )


def check_initial(initial: dict[str, typ.Any]) -> None:
    """Check the first constructor report and its retained error paths."""
    require(
        initial.get("binary_sha256") == CLIENT_SHA
        and initial.get("jar_sha256") == JAR_SHA,
        "initial tool/input hash changed",
    )
    require(initial.get("code_base") == "10000000", "code base changed")
    require(
        initial.get("content_calls") == INITIAL_CONTENT_CALLS,
        "initial content-query count changed",
    )
    program_pair(initial["records"])
    witness = result(
        next(q for q in initial["records"] if q["label"] == "code-mapping-witness")
    )
    require(
        witness.get("hex", "").replace(" ", "").lower() == "3880006f",
        "mapping bytes changed",
    )
    errors = {"100b2294": 8, "100b28a0": 8, "100cf2bc": 10, "100efa10": 8}
    for address, kind in errors.items():
        source = code(initial["records"], address)
        require(
            f"FUN_1007d7e0({kind},0x6f)" in source,
            f"{address} is not the retained error path",
        )
        require("FUN_100b05d0(" not in source, f"{address} gained a TLV append")


def check_followup(follow: dict[str, typ.Any]) -> None:
    """Check the 350 creation path in the follow-up report."""
    program_pair(follow["queries"])
    create = code(follow["queries"], "1000c210")
    require(direct_ids(create) == [105, 106, 102, 110], "350 direct field list changed")
    require(
        "FUN_100b2410(*(undefined4 *)(*piVar2 + 0x4f4),0x15e)" in create,
        "350 dispatch changed",
    )


def check_batches(
    batch38: dict[str, typ.Any], batch39: dict[str, typ.Any]
) -> tuple[list[dict[str, typ.Any]], list[dict[str, typ.Any]]]:
    """Check the B38 and B39 batches and count their content queries.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The queries of the B38 batch and the queries of the B39 batch.
    """
    require(
        batch38.get("binary_sha256") == CLIENT_SHA
        and batch39.get("binary_sha256") == CLIENT_SHA,
        "later DATA hash changed",
    )
    require(
        batch38.get("jar_sha256") == JAR_SHA and batch39.get("jar_sha256") == JAR_SHA,
        "later tool hash changed",
    )
    for batch in (batch38, batch39):
        for run in batch["runs"]:
            require(run.get("status") == "complete", "headless query run incomplete")
            program_pair(run["queries"])
    q38 = [q for run in batch38["runs"] for q in run["queries"]]
    q39 = [q for run in batch39["runs"] for q in run["queries"]]
    require(
        sum(q["tool"] != "get_program_info" for q in q38) == B38_CONTENT_CALLS,
        "B38 content count changed",
    )
    require(
        sum(q["tool"] != "get_program_info" for q in q39) == B39_CONTENT_CALLS,
        "B39 content count changed",
    )
    return q38, q39


def check_updates(q38: list[dict[str, typ.Any]]) -> None:
    """Check the 353 update path and the 349 object handoff in the B38 queries."""
    update = code(q38, "1000c800")
    require(direct_ids(update) == [105, 106, 102, 110], "353 direct field list changed")
    require(
        "FUN_100b2410(*(undefined4 *)(*piVar2 + 0x4f4),0x161)" in update,
        "353 dispatch changed",
    )
    batch = code(q38, "1000bfa0")
    require(
        "FUN_100b0a20(param_2)" in batch
        and "FUN_100b0ad0(param_1[2],uVar2,0)" in batch,
        "349 object handoff changed",
    )
    require(
        "FUN_100b2410(*(undefined4 *)(*piVar1 + 0x4f4),0x15d)" in batch,
        "349 dispatch changed",
    )


def check_serializer(q39: list[dict[str, typ.Any]]) -> None:
    """Check the 349 serializer and the old-login removal in the B39 queries."""
    serializer = code(q39, "1005b5b0")
    require(
        "cVar6 = FUN_1005e650(local_118);" in serializer
        and "if (cVar6 == '\\0')" in serializer,
        "conditional old-login changed",
    )
    require(
        nested_ids(serializer, "local_114") == [101, 105, 106, 102, 110],
        "349 nested field list changed",
    )
    require(nested_ids(serializer, "local_120") == [101], "349 outer field changed")
    removal = code(q39, "1005ce30")
    require(
        nested_ids(removal, "uVar3") == [101]
        and nested_ids(removal, "*param_2") == [101],
        "349 old-login-only list changed",
    )


def check_server_deletion(server_source: str) -> None:
    """Check the server's 349 deletion branch in its decompiled source."""
    for token in (
        "local_ae0 = FUN_10056b60(uVar7,0x65",
        "local_3e0 = FUN_10056b60(uVar7,0x66",
        "local_358 = FUN_10056b60(uVar7,0x69",
        "if ((local_3e0 == 0) && (local_358 == 0))",
        "if (local_ae0 == 0)",
        "FUN_10007340(param_1,&local_ae0)",
    ):
        require(token in server_source, f"server 349 deletion branch changed: {token}")


def check_append(q39: list[dict[str, typ.Any]]) -> None:
    """Check the counted BE16 TLV append in the B39 queries."""
    append = code(q39, "100b05d0")
    for token in (
        "if (param_4 != 0)",
        "*puVar2 = 1",
        "puVar2[1] = param_2",
        "puVar2[2] = (short)param_4",
        "*psVar4 = param_2",
        "psVar4[1] = (short)param_4",
        "FUN_100ad220(psVar4 + 2,param_3,param_4)",
    ):
        require(token in append, f"counted BE16 TLV append changed: {token}")


def verify(
    bundle: dict[str, typ.Any], server_source: str | None = None
) -> dict[str, typ.Any]:
    """Verify the bounded constructor trace against the retained client and server.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the content-query counts and the client hash.
    """
    prep = bundle["b36-preparation"]
    check_preparation(prep)
    initial = bundle["b37-report"]
    follow = bundle["b37-followup"]
    check_initial(initial)
    check_followup(follow)
    batch38 = bundle["b38-report"]
    batch39 = bundle["b39-report"]
    q38, q39 = check_batches(batch38, batch39)
    check_updates(q38)
    check_serializer(q39)
    if server_source is None:
        server_source = (
            ROOT / "evidence/hotline-server-1.9/queries/D-10015500.c"
        ).read_text()
    check_server_deletion(server_source)
    check_append(q39)
    return {
        "status": "verified-bounded-constructor-trace",
        "content_queries": {"B37": 12, "B38": 8, "B39": 3},
        "client_sha256": CLIENT_SHA,
    }


def main() -> None:
    """Verify the retained account-constructor trace from the command line."""
    print(json.dumps(verify(load_evidence()), sort_keys=True))


if __name__ == "__main__":
    main()
