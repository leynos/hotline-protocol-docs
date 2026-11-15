#!/usr/bin/env python3
"""Offline semantic checks for the bounded Classic account-constructor trace."""

import json
import re
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/client-account-constructors-01"
CLIENT_SHA = "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
JAR_SHA = "201d18ffde71a83a678eae607de265861f37e5a00b989d91958c1197664d2b43"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_evidence(base: Path = CORPUS) -> dict:
    names = (
        "b36-preparation",
        "b37-report",
        "b37-followup",
        "b38-report",
        "b39-report",
    )
    return {name: json.loads((base / f"{name}.json").read_text()) for name in names}


def result(query: dict) -> dict:
    payload = query.get("result", {})
    require(not payload.get("isError", False), "retained tool error")
    content = payload.get("structuredContent")
    require(isinstance(content, dict), "missing structured tool result")
    return content


def code(queries: list[dict], address: str) -> str:
    found = [
        result(query).get("code")
        for query in queries
        if query.get("tool") == "decompile_function_by_address"
        and query.get("arguments", {}).get("address") == address
    ]
    require(
        len(found) == 1 and isinstance(found[0], str), f"missing decompile {address}"
    )
    return cast(str, found[0])


def program_pair(queries: list[dict]) -> dict:
    info = [
        result(query) for query in queries if query.get("tool") == "get_program_info"
    ]
    require(len(info) == 2 and info[0] == info[1], "program identity changed")
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
    pattern = rf"FUN_100b05d0\({re.escape(object_name)},0x([0-9a-f]+),"
    return [int(value, 16) for value in re.findall(pattern, source)]


def direct_ids(source: str) -> list[int]:
    pattern = r"FUN_100b(?:0800|05d0)\(param_1\[2\],0x([0-9a-f]+),"
    return [int(value, 16) for value in re.findall(pattern, source)]


def verify(bundle: dict, server_source: str | None = None) -> dict:
    prep = bundle["b36-preparation"]
    require(prep.get("data_sha256") == CLIENT_SHA, "prepared DATA hash changed")
    require(
        prep.get("resource_sha256")
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b",
        "resource hash changed",
    )

    initial = bundle["b37-report"]
    follow = bundle["b37-followup"]
    require(
        initial.get("binary_sha256") == CLIENT_SHA
        and initial.get("jar_sha256") == JAR_SHA,
        "initial tool/input hash changed",
    )
    require(initial.get("code_base") == "10000000", "code base changed")
    require(initial.get("content_calls") == 11, "initial content-query count changed")
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

    program_pair(follow["queries"])
    create = code(follow["queries"], "1000c210")
    require(direct_ids(create) == [105, 106, 102, 110], "350 direct field list changed")
    require(
        "FUN_100b2410(*(undefined4 *)(*piVar2 + 0x4f4),0x15e)" in create,
        "350 dispatch changed",
    )

    batch38 = bundle["b38-report"]
    batch39 = bundle["b39-report"]
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
        sum(q["tool"] != "get_program_info" for q in q38) == 8,
        "B38 content count changed",
    )
    require(
        sum(q["tool"] != "get_program_info" for q in q39) == 3,
        "B39 content count changed",
    )
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
    if server_source is None:
        server_source = (
            ROOT / "evidence/hotline-server-1.9/queries/D-10015500.c"
        ).read_text()
    for token in (
        "local_ae0 = FUN_10056b60(uVar7,0x65",
        "local_3e0 = FUN_10056b60(uVar7,0x66",
        "local_358 = FUN_10056b60(uVar7,0x69",
        "if ((local_3e0 == 0) && (local_358 == 0))",
        "if (local_ae0 == 0)",
        "FUN_10007340(param_1,&local_ae0)",
    ):
        require(token in server_source, f"server 349 deletion branch changed: {token}")
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
    return {
        "status": "verified-bounded-constructor-trace",
        "content_queries": {"B37": 12, "B38": 8, "B39": 3},
        "client_sha256": CLIENT_SHA,
    }


def main() -> None:
    print(json.dumps(verify(load_evidence()), sort_keys=True))


if __name__ == "__main__":
    main()
