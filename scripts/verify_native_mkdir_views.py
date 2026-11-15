"""Check the auxiliary operations, final views and oracle queries of a mkdir corpus."""

import json
import typing as typ

from native_folder_cases import path
from native_mkdir_cases import BASE, ROOT, specs
from protocol_capture import ORACLE_SHA256
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir_checks import FAILURES, created_name, listing, uploaded
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Listing = dict[bytes, bytes]

INFO_DATE_BYTES = 8  # the length that the file-info check requires of fields 208, 209
ORACLE_QUERY_COUNT = 10  # one retained oracle query for each decompiled address
# The final views, by the identifier of their listing reply and the folder path.
FINAL_VIEWS = [
    (20, ()),
    (21, (ROOT,)),
    (22, (ROOT, b"nest")),
    (23, (ROOT, b"nest", b"leaf")),
    (24, (ROOT, b".")),
    (25, (ROOT, b"..")),
    (26, (ROOT, b"co-lon")),
    (27, (ROOT, b"hi-\x9a")),
    (28, (ROOT, b"\0nul")),
]
# The file-info replies that the final state must show, with their kind fields.
FILE_INFO_VIEWS = [
    (30, {205: b"Folder", 206: b"n/a", 213: b"fldr", 201: ROOT}),
    (
        31,
        {
            213: b"TEXT",
            205: b"Text File",
            206: b"MOTH",
            207: b"\0\r",
            201: b"ordinary",
            210: b"fixture-comment",
        },
    ),
]
ORACLE_ADDRESSES = {
    "100143f0",
    "1002c070",
    "1002f080",
    "1002b0e0",
    "1002b670",
    "1002e8b0",
    "1002e3d0",
    "1002f800",
    "1002f0c0",
    "1002a9f0",
}


def check_auxiliary(reports: dict[str, Report]) -> Listing:
    """Check the seed, final and cleanup operations, and the setup uploads.

    Returns
    -------
    dict[bytes, bytes]
        The Files listing before the owned creations.
    """
    seeded, final, cleaned = (reports[k] for k in ["seed", "final", "cleanup"])
    require(
        all(f["error"] == 0 for r in [seeded, final, cleaned] for f in r["frames"]),
        "Native auxiliary operation failed",
    )
    initial = listing(reply(seeded, 9))
    require(
        ROOT not in initial
        and not any(name.startswith(b"m-fs19-") for name in initial),
        "Owned preflight was not empty",
    )
    require(
        set(listing(reply(seeded, 15))) == {b"exists", b"nest", b"ordinary"},
        "Seed fixture differs",
    )
    uploaded(seeded, b"mkdir-fixture")
    uploaded(final, b"")
    return initial


def build_views(initial: Listing) -> dict[bytes, set[bytes]]:
    """Derive the exact expected listing of every folder after the creations.

    Returns
    -------
    dict[bytes, set[bytes]]
        The names that each folder path must list in the final state.
    """
    expected_views = {
        path(()): set(initial) | {ROOT, b"m-fs19-flush"},
        BASE: {b"exists", b"nest", b"ordinary"},
        path((ROOT, b"nest")): {b"leaf"},
    }
    for c in specs():
        if c["case"] not in FAILURES:
            expected_views.setdefault(bytes.fromhex(c["view_hex"]), set()).add(
                created_name(c)
            )
    return expected_views


def check_file_info(final: Report) -> None:
    """Check the kind matrix of the file-info replies in the final state."""
    for identifier, expected_info in FILE_INFO_VIEWS:
        info = fields(reply(final, identifier))
        require(
            set(info) == set(expected_info) | {208, 209}
            and all(info[key] == value for key, value in expected_info.items())
            and all(
                len(info[key]) == INFO_DATE_BYTES and info[key] != bytes(8)
                for key in [208, 209]
            ),
            "Final native file-info kind matrix differs",
        )


def check_final_views(final: Report, cleaned: Report, initial: Listing) -> None:
    """Check the final folder views, file-info kinds and the owned cleanup."""
    expected_views = build_views(initial)
    for identifier, parts in FINAL_VIEWS:
        require(
            set(listing(reply(final, identifier))) == expected_views[path(parts)],
            "Final native view differs from exact creation effects",
        )
    check_file_info(final)
    require(
        listing(reply(cleaned, 10)) == listing(reply(final, 20))
        and listing(reply(cleaned, 90)) == initial,
        "Owned cleanup did not restore the initial Files listing",
    )


def check_oracle_queries(directory: Path) -> None:
    """Check the retained oracle queries and the code that each one returned."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        {p.stem.removeprefix("FS-D-") for p in queries} == ORACLE_ADDRESSES
        and len(queries) == ORACLE_QUERY_COUNT,
        "Missing native creation oracle queries",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["query"]["tool"] == "decompile_function_by_address"
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Oracle query identity/code differs",
        )
