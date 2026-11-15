"""Check positive direct-catalogue observations without inferring path absence."""

import dataclasses as dc
import json
import typing as typ

from native_folder_cases import FILES
from native_transfer_cases import resource_fork
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Forks = tuple[bytes, bytes]


@dc.dataclass(frozen=True, slots=True)
class Stage:
    """The extracted native tree of one stage and its positive records.

    Attributes
    ----------
    root : pathlib.Path
        The directory with the extraction and the per-record files.
    name : str
        The stage, ``before`` or ``after``.
    records : dict[str, dict[str, typing.Any]]
        The positive records, by path below the files directory.
    """

    root: Path
    name: str
    records: dict[str, Report]


def check_directory(stage: Stage, name: str) -> None:
    """Check that a positive record is a folder in the direct catalogue."""
    record = stage.records[name]
    stat = (stage.root / (record["key"] + ".stat.txt")).read_text()
    require(
        record["directory"] and "Type:\tFolder" in stat,
        "Native directory type differs",
    )
    require(
        "File Path: /Hotline19/Files/" + name in stat,
        "Direct catalogue path differs",
    )


def check_file(stage: Stage, name: str, forks: Forks) -> None:
    """Check that a positive record is a file whose forks are the expected bytes."""
    data, resource = forks
    record = stage.records[name]
    key = record["key"]
    stat = (stage.root / (key + ".stat.txt")).read_text()
    require(
        not record["directory"] and "File Path: /Hotline19/Files/" + name in stat,
        "Native file identity differs",
    )
    require(
        record["attributes"]["data"]["exit_code"] == 0
        and (stage.root / (key + ".data")).read_bytes() == data,
        "Native folder DATA differs",
    )
    require(
        f"Resource fork size:\t{len(resource)}" in stat,
        "Native folder resource length differs",
    )
    attribute = record["attributes"]["rsrc"]
    if attribute["exit_code"] == 0:
        require(
            (stage.root / (key + ".rsrc")).read_bytes() == resource,
            "Native folder MACR differs",
        )
    else:
        require(
            not resource and "Attribute 4353-1 not found" in attribute["stderr"],
            "Failed fork read is not verified empty-resource absence",
        )
    partial = stage.name == "before" and name == "mothra-folder-partial/part"
    require(
        ("HTft" if partial else "TEXT") in stat
        and ("HTLC" if partial else "MOTH") in stat,
        "Native folder type/creator differs",
    )


def check_stage(
    root: Path, stage_name: str, base_dirs: set[str], expected: dict[str, Forks]
) -> Report:
    """Check the positive records of one extraction stage.

    Returns
    -------
    dict[str, typing.Any]
        The count of positive records and the partial resource length.
    """
    report = json.loads((root / "extraction.json").read_text())
    records = {
        r["path"].removeprefix("/Hotline19/Files/"): r for r in report["records"]
    }
    dirs = base_dirs | (
        {"mothra-folder-partial/finish"} if stage_name == "after" else set()
    )
    files = {
        **expected,
        "mothra-folder-partial/part": (
            FILES[b"alpha",][0],
            resource_fork() if stage_name == "after" else resource_fork()[:5],
        ),
    }
    require(
        set(records) == dirs | set(files),
        "Positive native folder inventory differs",
    )
    stage = Stage(root, stage_name, records)
    for name in dirs:
        check_directory(stage, name)
    for name, forks in files.items():
        check_file(stage, name, forks)
    return {
        "positive_records": len(records),
        "partial_resource_bytes": len(files["mothra-folder-partial/part"][1]),
    }


def check_failed_attempts(directory: Path) -> None:
    """Check that the two failed catalogue attempts were reported as failures."""
    for failed in ["before-failed-catalogue", "before-failed-after-flush"]:
        report = json.loads(
            (directory / "native-files" / failed / "attempt.json").read_text()
        )
        require(
            report["exit_code"] != 0
            and "nodesize value out of bounds" in report["stderr"],
            "Failed catalogue attempt was misreported",
        )


def check_timing(root: Path) -> Report:
    """Check the directories that were observed while their timers ran.

    Returns
    -------
    dict[str, typing.Any]
        The count of positive timed records.
    """
    timing = json.loads((root / "extraction.json").read_text())
    expected_timing = {
        "/Hotline19/Files/mothra-folder-late",
        "/Hotline19/Files/mothra-folder-descriptor-delay",
        "/Hotline19/Files/mothra-folder-descriptor-delay/wait",
    }
    require(
        {r["path"] for r in timing["records"]} == expected_timing,
        "Timed directory positive observations differ",
    )
    for record in timing["records"]:
        stat = (root / (record["key"] + ".stat.txt")).read_text()
        require(
            record["directory"]
            and "Type:\tFolder" in stat
            and "File Path: " + record["path"] in stat,
            "Timed native directory identity differs",
        )
    return {"positive_records": len(timing["records"])}


def verify_files(directory: Path) -> Report:
    """Verify the positive direct-catalogue records of both stages and of timing.

    Returns
    -------
    dict[str, typing.Any]
        The positive record counts of each stage and of the timing directory.
    """
    base_dirs = {
        "mothra-folder-source",
        "mothra-folder-source/empty",
        "mothra-folder-source/inner",
        "mothra-folder-empty",
        "mothra-folder-dirlast",
        "mothra-folder-dirlast/only",
        "mothra-folder-partial",
    }
    expected: dict[str, Forks] = {
        "mothra-folder-source/" + b"/".join(parts).decode(): forks
        for parts, forks in FILES.items()
    }
    expected["mothra-folder-partial/alpha"] = FILES[b"alpha",]
    summary: Report = {}
    for stage in ["before", "after"]:
        summary[stage] = check_stage(
            directory / "native-files" / stage, stage, base_dirs, expected
        )
    check_failed_attempts(directory)
    summary["timing"] = check_timing(directory / "native-files/timing")
    return summary
