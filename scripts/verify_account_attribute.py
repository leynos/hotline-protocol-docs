#!/usr/bin/env python3
"""Verify bounded field-111 oracle trace and native stored-record controls."""

import argparse
import hashlib
import json
from pathlib import Path

from verify_native_core import require

ORACLE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
EVIDENCE_PREFIX = Path("evidence/gap-remediation/2026-11-13/account-attribute-01")
READER_CALLERS = {
    "10007fa0",
    "10007780",
    "100197e0",
    "10003170",
    "10011960",
    "10014bc0",
    "10011ee0",
    "10014df0",
    "10015160",
    "10015500",
}
WRITER_CALLERS = {"10014df0", "10015500"}
CREATOR_CALLERS = {"10007780", "100146f0", "10015500"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_record(data: bytes) -> bytes:
    """Extract the 64-byte bounded opaque attribute from a 734-byte record."""
    require(len(data) == 734, "account record size differs")
    require(data[:2] == b"\0\1", "account record version differs")
    length = int.from_bytes(data[0x254:0x256], "big")
    require(length <= 64, "attribute length exceeds its 64-byte slot")
    return data[0x256 : 0x256 + length]


def callers(record: dict, expected: set[str], label: str) -> int:
    content = record["result"]["structuredContent"]
    listing = content["callers"]
    actual = {item["caller"]["address"] for item in listing["items"]}
    require(
        actual == expected
        and listing["total"] == len(expected)
        and len(listing["items"]) == len(expected)
        and listing["has_more"] is False,
        label + " caller set differs",
    )
    require(
        all(item["direct"] is True for item in listing["items"]),
        label + " unexpectedly contains an indirect call",
    )
    return len(actual)


def verify(directory: Path, root: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["schema_version"] == 1
        and manifest["oracle_sha256"] == ORACLE_SHA256
        and manifest["query_count"] == 28
        and manifest["capture_exit_codes"] == [0, 0, 0]
        and manifest["oracle_identity_scope"]
        == "read-only Ghidra PEF; no native runtime",
        "oracle manifest identity or run result differs",
    )
    capture_source = directory / "sources/capture-ghidra-evidence.py"
    require(
        sha(capture_source) == manifest["capture_script_sha256"]
        and b"after.structuredContent != identity" in capture_source.read_bytes(),
        "oracle capture source lacks its after-identity guard",
    )
    plans = []
    for index in range(1, 4):
        plans.extend(json.loads((directory / f"plan-0{index}.json").read_text()))
    require(
        len(plans) == 28
        and len({plan["id"] for plan in plans}) == 28
        and {p.stem for p in (directory / "queries").glob("*.json")}
        == {plan["id"] for plan in plans},
        "oracle query inventory differs",
    )
    records = {}
    identities = []
    for plan in plans:
        path = directory / "queries" / (plan["id"] + ".json")
        record = json.loads(path.read_text())
        require(record["query"] == plan, "oracle tool name or arguments differ")
        program = record["program"]
        require(
            program["sha256"] == ORACLE_SHA256
            and program["name"] == "HLserver19"
            and program["language_id"] == "PowerPC:BE:32:default"
            and program["endian"] == "big",
            "oracle identity differs",
        )
        require(
            record["result"]["isError"] is False
            and record["result"]["structuredContent"] is not None,
            "oracle query failed or lacks structured content",
        )
        content = record["result"]["structuredContent"]
        if plan["tool"] == "decompile_function_by_address":
            require(
                content["truncated"] is False
                and content["function"]["address"] == plan["arguments"]["address"]
                and content["code"],
                "decompilation is truncated or addresses another function",
            )
            snapshot = path.with_suffix(".c")
            require(
                snapshot.is_file() and snapshot.read_text() == content["code"],
                "decompiler source snapshot differs",
            )
        identities.append(program)
        records[plan["id"]] = record
    require(all(item == identities[0] for item in identities), "oracle identity drift")
    reader_count = callers(records["AA-C-100073c0"], READER_CALLERS, "reader")
    writer_count = callers(records["AA-C-100075e0"], WRITER_CALLERS, "writer")
    creator_count = callers(records["AA-C-100071a0"], CREATOR_CALLERS, "creator")
    admin_update = records["AA-D-10007780"]["result"]["structuredContent"]["code"]
    require(
        "FUN_100073c0(param_1,param_2,local_300);" in admin_update
        and "FUN_1002c440(uVar2,0,local_300,0x2de,0);" in admin_update,
        "admin password update no longer copies the whole account record",
    )
    stored = {
        "absent": ("2026-11-12/native-core-01/account111-absent/UserData.bin", b""),
        "empty": ("2026-11-12/native-core-01/account111-empty/UserData.bin", b""),
        "value": (
            "2026-11-12/native-core-01/account111-value/UserData.bin",
            b"opaque-c",
        ),
        "sparse-clear": (
            "2026-11-13/native-account-update-01/native-final/catalog-11649.data",
            b"",
        ),
        "cap64": (
            "2026-11-13/native-account-update-01/native-final/catalog-11651.data",
            b"X" * 64,
        ),
    }
    observations = {}
    for label, (relative, expected) in stored.items():
        path = root / "evidence/gap-remediation" / relative
        actual = decode_record(path.read_bytes())
        require(actual == expected, label + " stored field-111 value differs")
        observations[label] = {"length": len(actual), "source_sha256": sha(path)}
    sums = (directory / "SHA256SUMS").read_text().splitlines()
    expected_sums = {
        f"{sha(path)}  {EVIDENCE_PREFIX / path.relative_to(directory)}"
        for path in directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    require(set(sums) == expected_sums, "trace evidence checksums differ")
    return {
        "status": "verified",
        "query_count": len(plans),
        "reader_direct_callers": reader_count,
        "writer_direct_callers": writer_count,
        "creator_direct_callers": creator_count,
        "stored": observations,
        "meaning": "unresolved",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.root), indent=2))


if __name__ == "__main__":
    main()
