"""Check retained banner exception and allocation evidence at the native oracle."""

import json
from pathlib import Path

from protocol_capture import ORACLE_SHA256
from verify_native_core import require


def verify(directory: Path) -> dict:
    records = {}
    for query in (directory / "oracle-queries").glob("*.json"):
        record = json.loads(query.read_text())
        require(
            record["program"]["sha256"] == ORACLE_SHA256
            and not record["result"]["isError"],
            "Format oracle query identity differs",
        )
        result = record["result"]["structuredContent"]
        if "code" in result:
            require(
                result["code"] == query.with_suffix(".c").read_text(),
                "Format oracle code differs",
            )
        records[query.stem] = result
    require(len(records) == 12, "Banner oracle query inventory differs")
    checks = {
        "1000d5e0": {
            "1000d62c": "lwz r3,0xc(r26)",
            "1000d630": "bl 0x10052f80",
            "1000d638": "or r29,r3,r3",
            "1000d71c": "or r3,r29,r29",
            "1000d720": "bl 0x1006ddb0",
        },
        "1006ddb0": {"1006ddbc": "bl 0x10070c30"},
        "10070c30": {
            "10070c44": "or. r30,r3,r3",
            "10070c48": "bne 0x10070c5c",
            "10070c4c": "li r3,0x1",
            "10070c50": "li r4,0x2",
            "10070c54": "bl 0x10027c30",
        },
    }
    for function, expected in checks.items():
        instructions = {
            i["address"]: i["instruction"] for i in records["BF-A-" + function]["items"]
        }
        require(
            all(
                instructions.get(address) == text for address, text in expected.items()
            ),
            "Zero-byte allocator ABI differs",
        )
    require(
        "FUN_10027c30(1,2)" in records["BF-D-10052f80"]["code"],
        "Missing null-size exception",
    )
    require(
        "NewHandle(param_1 + 4)" in records["BF-D-10052c50"]["code"],
        "Present empty buffer construction differs",
    )
    return {
        "queries": len(records),
        "worker_size_forwarding_checked": True,
        "zero_allocator_internal_domain": 1,
        "zero_allocator_internal_code": 2,
        "scope": "Native null/zero exception and ABI paths; no general reset threshold or wire-status mapping",
    }
