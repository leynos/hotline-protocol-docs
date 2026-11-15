"""Check the owned catalogue snapshots of a mkdir corpus and their Trash moves."""

import json
import typing as typ

from native_mkdir_cases import ROOT, specs
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Records = dict[int, Report]

# The owned catalogue inventory that the retained corpus records before and
# after the cleanup, and the catalogue controls that the corpus must contain.
BEFORE_RECORDS = 36
AFTER_RECORDS = 44
REQUIRED_CONTROLS = {
    "",
    "/exists",
    "/nest",
    "/nest/leaf",
    "/nest/leaf/nested-child",
    "/ordinary",
    "/plain",
}
SCOPE = (
    "TSK paths render control/high bytes; raw filename claims use native listing "
    "bytes. Positive catalogue IDs and payload survive parent move; no recursive "
    "erase or universal durability inferred."
)


def check_controls(before: Records, prefix: str) -> None:
    """Check that the positive directory and file controls were catalogued."""
    require(
        {prefix + tail for tail in REQUIRED_CONTROLS}
        <= {r["path"] for r in before.values()},
        "Missing positive native directory/file controls",
    )


def check_record(
    roots: tuple[Path, Path], record: Report, moved: Report, ordinary: str
) -> None:
    """Check that one owned record moved intact from Files to Trash."""
    before_dir, after_dir = roots
    require(
        moved["path"] == record["path"].replace("/Hotline19/Files/", "/Trash/", 1)
        and moved["directory"] == record["directory"],
        "Owned catalogue identity did not move intact to Trash",
    )
    for root, selected in [(before_dir, record), (after_dir, moved)]:
        text = (root / (selected["key"] + ".stat.txt")).read_text()
        require(
            "File Path: " + selected["path"] in text,
            "Positive native path evidence differs",
        )
    if record["path"] == ordinary:
        for root, selected in [(before_dir, record), (after_dir, moved)]:
            require(
                selected["attributes"]["data"]["exit_code"] == 0
                and (root / (selected["key"] + ".data")).read_bytes()
                == b"mkdir-fixture",
                "Trash move lost ordinary file bytes",
            )


def check_cleanup_targets(before: Records, after: Records) -> None:
    """Check that the new catalogue entries are exactly the owned cleanup targets."""
    extra_names = [
        bytes.fromhex(c["name_hex"]).decode()
        for c in specs()
        if c["view_hex"] == "0000"
    ] + ["m-fs19-flush"]
    require(
        {r["path"] for k, r in after.items() if k not in before}
        == {"/Trash/" + n for n in extra_names},
        "Owned root cleanup targets differ",
    )


def catalogue(directory: Path) -> Report:
    """Check the before-cleanup and after-cleanup catalogue snapshots.

    Returns
    -------
    dict[str, typing.Any]
        The record counts of both snapshots and the scope they support.
    """
    before_dir, after_dir = (
        directory / "native-before-cleanup",
        directory / "native-after-cleanup",
    )
    before_report = json.loads((before_dir / "extraction.json").read_text())
    after_report = json.loads((after_dir / "extraction.json").read_text())
    before = {r["catalog"]: r for r in before_report["records"]}
    after = {r["catalog"]: r for r in after_report["records"]}
    prefix = "/Hotline19/Files/" + ROOT.decode()
    check_controls(before, prefix)
    require(
        len(before) == BEFORE_RECORDS
        and len(after) == AFTER_RECORDS
        and set(before) <= set(after),
        "Owned catalogue inventory differs",
    )
    for catalog, record in before.items():
        check_record(
            (before_dir, after_dir), record, after[catalog], prefix + "/ordinary"
        )
    check_cleanup_targets(before, after)
    return {
        "positive_before": len(before),
        "positive_after": len(after),
        "scope": SCOPE,
    }
