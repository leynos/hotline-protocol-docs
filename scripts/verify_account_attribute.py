#!/usr/bin/env python3
"""Verify bounded field-111 oracle trace and native stored-record controls."""

import hashlib
import json
import typing as typ
from pathlib import Path

from native_wire_names import ACCOUNT_RECORD_BYTES
from script_cli import run
from verify_native_core import require

type Report = dict[str, typ.Any]

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
QUERY_COUNT = 28  # the oracle trace's queries, across its three plan files
PLAN_FILES = 3
ATTRIBUTE_SLOT_BYTES = 64  # the bounded opaque attribute's slot in the record


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of ``path``.

    Returns
    -------
    str
        The lower-case hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_record(data: bytes) -> bytes:
    """Extract the 64-byte bounded opaque attribute from a 734-byte record.

    Parameters
    ----------
    data : bytes
        The whole stored account record.

    Returns
    -------
    bytes
        The attribute bytes that the record's length word declares.
    """
    require(len(data) == ACCOUNT_RECORD_BYTES, "account record size differs")
    require(data[:2] == b"\0\1", "account record version differs")
    length = int.from_bytes(data[0x254:0x256], "big")
    require(
        length <= ATTRIBUTE_SLOT_BYTES,
        "attribute length exceeds its 64-byte slot",
    )
    return data[0x256 : 0x256 + length]


def callers(record: Report, expected: set[str], label: str) -> int:
    """Check the direct caller set of one oracle query.

    Parameters
    ----------
    record : dict[str, typing.Any]
        The recorded oracle query.
    expected : set[str]
        The caller addresses that the trace must list.
    label : str
        The name of the function, used in the error message.

    Returns
    -------
    int
        The number of distinct callers.
    """
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


def check_manifest(manifest: Report) -> None:
    """Require the oracle manifest to name the pinned identity and run.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    require(
        manifest["schema_version"] == 1
        and manifest["oracle_sha256"] == ORACLE_SHA256
        and manifest["query_count"] == QUERY_COUNT
        and manifest["capture_exit_codes"] == [0, 0, 0]
        and manifest["oracle_identity_scope"]
        == "read-only Ghidra PEF; no native runtime",
        "oracle manifest identity or run result differs",
    )


def check_capture_source(directory: Path, manifest: Report) -> None:
    """Require the capture script to keep its after-identity guard.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    capture_source = directory / "sources/capture-ghidra-evidence.py"
    require(
        sha(capture_source) == manifest["capture_script_sha256"]
        and b"after.structuredContent != identity" in capture_source.read_bytes(),
        "oracle capture source lacks its after-identity guard",
    )


def load_plans(directory: Path) -> list[Report]:
    """Load the query plans and require the recorded query inventory.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.

    Returns
    -------
    list[dict[str, typing.Any]]
        Every planned query, in plan-file order.
    """
    plans: list[Report] = []
    for index in range(1, PLAN_FILES + 1):
        plans.extend(json.loads((directory / f"plan-0{index}.json").read_text()))
    require(
        len(plans) == QUERY_COUNT
        and len({plan["id"] for plan in plans}) == QUERY_COUNT
        and {p.stem for p in (directory / "queries").glob("*.json")}
        == {plan["id"] for plan in plans},
        "oracle query inventory differs",
    )
    return plans


def check_query(directory: Path, plan: Report) -> Report:
    """Check one recorded oracle query against its plan.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.
    plan : dict[str, typing.Any]
        The plan that the query must have run.

    Returns
    -------
    dict[str, typing.Any]
        The parsed query record.
    """
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
    return record


def load_records(
    directory: Path, plans: list[Report]
) -> tuple[dict[str, Report], list[Report]]:
    """Check every recorded oracle query, keyed by its plan identifier.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.
    plans : list[dict[str, typing.Any]]
        The planned queries.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The records by plan identifier, and the program identity of each.
    """
    records: dict[str, Report] = {}
    identities: list[Report] = []
    for plan in plans:
        record = check_query(directory, plan)
        identities.append(record["program"])
        records[plan["id"]] = record
    return records, identities


def check_callers(records: dict[str, Report]) -> tuple[int, int, int]:
    """Check the reader, writer and creator caller sets of the field-111 functions.

    Parameters
    ----------
    records : dict[str, dict[str, typing.Any]]
        The recorded oracle queries, by plan identifier.

    Returns
    -------
    tuple[int, int, int]
        The reader, writer and creator direct-caller counts.
    """
    reader_count = callers(records["AA-C-100073c0"], READER_CALLERS, "reader")
    writer_count = callers(records["AA-C-100075e0"], WRITER_CALLERS, "writer")
    creator_count = callers(records["AA-C-100071a0"], CREATOR_CALLERS, "creator")
    return reader_count, writer_count, creator_count


def check_admin_update(records: dict[str, Report]) -> None:
    """Require the admin password update to copy the whole account record.

    Parameters
    ----------
    records : dict[str, dict[str, typing.Any]]
        The recorded oracle queries, by plan identifier.
    """
    admin_update = records["AA-D-10007780"]["result"]["structuredContent"]["code"]
    require(
        "FUN_100073c0(param_1,param_2,local_300);" in admin_update
        and "FUN_1002c440(uVar2,0,local_300,0x2de,0);" in admin_update,
        "admin password update no longer copies the whole account record",
    )


def read_stored(root: Path) -> dict[str, Report]:
    """Decode the retained stored records and require their field-111 values.

    Parameters
    ----------
    root : pathlib.Path
        The repository root that holds ``evidence/``.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The decoded length and source digest of each stored record.
    """
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
    observations: dict[str, Report] = {}
    for label, (relative, expected) in stored.items():
        path = root / "evidence/gap-remediation" / relative
        actual = decode_record(path.read_bytes())
        require(actual == expected, label + " stored field-111 value differs")
        observations[label] = {"length": len(actual), "source_sha256": sha(path)}
    return observations


def check_sums(directory: Path) -> None:
    """Require the checksum file to list exactly the trace's other files.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.
    """
    sums = (directory / "SHA256SUMS").read_text().splitlines()
    expected_sums = {
        f"{sha(path)}  {EVIDENCE_PREFIX / path.relative_to(directory)}"
        for path in directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    require(set(sums) == expected_sums, "trace evidence checksums differ")


def verify(directory: Path, root: Path) -> Report:
    """Verify the oracle trace in ``directory`` and the stored field-111 records.

    Parameters
    ----------
    directory : pathlib.Path
        The account-attribute evidence directory.
    root : pathlib.Path
        The repository root that holds ``evidence/``.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the counts and the stored observations.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_manifest(manifest)
    check_capture_source(directory, manifest)
    plans = load_plans(directory)
    records, identities = load_records(directory, plans)
    require(all(item == identities[0] for item in identities), "oracle identity drift")
    reader_count, writer_count, creator_count = check_callers(records)
    check_admin_update(records)
    stored = read_stored(root)
    check_sums(directory)
    return {
        "status": "verified",
        "query_count": len(plans),
        "reader_direct_callers": reader_count,
        "writer_direct_callers": writer_count,
        "creator_direct_callers": creator_count,
        "stored": stored,
        "meaning": "unresolved",
    }


def show(directory: str, *, root: str) -> None:
    """Print the verification of an oracle trace and its stored records as JSON.

    Parameters
    ----------
    directory : str
        The account-attribute evidence directory.
    root : str
        The repository root that holds ``evidence/``.
    """
    print(json.dumps(verify(Path(directory), Path(root)), indent=2))


def main() -> None:
    """Verify the field-111 oracle trace and native stored-record controls."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
