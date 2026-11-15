"""Check how the alias reports relate: resolution, repeats, comments and the oracle."""

import json
import typing as typ

from native_alias_cases import ROOT
from protocol_capture import ORACLE_SHA256
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

REPEAT_MESSAGE = (
    b"Cannot make alias of \xd2file\xd3 because there is already a file/folder in "
    b"the destination folder with the same name."
)
UNATTACHED_MESSAGE = b"Cannot download because there is no file named \xd2self\xd3."
BASELINE_ENTRIES = 41
ORACLE_QUERIES = 14
EMULATOR_PID = 881007
EMULATOR_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
ORACLE_ADDRESSES = {
    "10017c10",
    "1002fb00",
    "1002b6f0",
    "10016ba0",
    "1002f600",
    "1002f5a0",
    "1002cf90",
    "1002b0e0",
    "1002e3d0",
    "100121a0",
    "100055a0",
    "1002cb20",
    "1002ce00",
    "1002f310",
}


def check_resolutions(reports: dict[str, Report]) -> None:
    """Check that each alias reports the size, dates and comment of its target."""
    for original, aliases in [
        ("ordinary-file", ["file-alias", "file-chain", "derived-alias"]),
        ("ordinary-directory", ["directory-alias", "directory-chain"]),
    ]:
        target = fields(reply(reports["info/" + original], 10))
        for alias in aliases:
            resolved = fields(reply(reports["info/" + alias], 10))
            require(
                all(resolved.get(k) == target.get(k) for k in [207, 208, 209, 210]),
                "Alias size/date/comment does not match resolved target",
            )


def check_repeat(reports: dict[str, Report]) -> None:
    """Check that repeating an existing alias is refused and damages nothing."""
    repeated = reports["damage/repeat-existing-alias"]
    require(
        reply(repeated, 12)["error"] == 1
        and fields(reply(repeated, 12)) == {100: REPEAT_MESSAGE},
        "Repeat-existing-alias rejection differs",
    )
    require(
        listing(reply(repeated, 10)) == listing(reply(repeated, 14))
        and fields(reply(repeated, 15))[207] == (333).to_bytes(2, "big"),
        "Repeated alias damaged a resolved chain",
    )


def check_unattached(reports: dict[str, Report]) -> None:
    """Check that an unattached alias cannot be downloaded."""
    rejected = reply(reports["supplementary/unattached-download-rejected"], 10)
    require(
        rejected["error"] == 1 and fields(rejected) == {100: UNATTACHED_MESSAGE},
        "Unattached alias download failure differs",
    )


def check_comments(reports: dict[str, Report]) -> None:
    """Check that a directory comment set through an alias reaches its target."""
    comment = reports["supplementary/directory-comment-through-alias"]
    for identifier in [20, 30, 40, 50]:
        require(
            reply(comment, identifier)["error"] == 0, "Directory comment update failed"
        )
        source, alias = (
            fields(reply(comment, identifier + 1)),
            fields(reply(comment, identifier + 2)),
        )
        require(
            source.get(210)
            == alias.get(210)
            == (b"directory-comment" if identifier in {20, 40} else None),
            "Resolved directory comment differs",
        )


def check_baseline(reports: dict[str, Report]) -> None:
    """Check the baseline listing, its restoration by cleanup and the cleanup ACKs."""
    initial = listing(reply(reports["baseline"], 10))
    require(
        len(initial) == BASELINE_ENTRIES and ROOT not in initial,
        "Alias baseline directory differs",
    )
    require(
        listing(reply(reports["seed"], 9)) == initial
        and listing(reply(reports["cleanup"], 90)) == initial,
        "Owned alias cleanup did not restore Files wire listing",
    )
    require(
        all(f["error"] == 0 for f in reports["cleanup"]["frames"]),
        "Owned alias cleanup ACK failed",
    )


def check_runtime(directory: Path) -> None:
    """Check the identity of the emulator that produced the corpus."""
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == EMULATOR_PID
        and runtime["running_executable_sha256"] == EMULATOR_SHA256,
        "Alias runtime identity differs",
    )


def check_oracle(directory: Path) -> None:
    """Check the oracle queries: their inventory, identity and retained code."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERIES
        and {p.stem.removeprefix("AL-D-") for p in queries} == ORACLE_ADDRESSES,
        "Alias oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Alias oracle code/identity differs",
        )
