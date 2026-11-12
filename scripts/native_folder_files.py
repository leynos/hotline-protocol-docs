"""Check positive direct-catalogue observations without inferring path absence."""

import json
from pathlib import Path

from native_folder_cases import FILES
from native_transfer_cases import resource_fork
from verify_native_core import require


def verify_files(directory: Path) -> dict:
    base_dirs = {
        "mothra-folder-source",
        "mothra-folder-source/empty",
        "mothra-folder-source/inner",
        "mothra-folder-empty",
        "mothra-folder-dirlast",
        "mothra-folder-dirlast/only",
        "mothra-folder-partial",
    }
    expected = {
        "mothra-folder-source/" + b"/".join(parts).decode(): forks
        for parts, forks in FILES.items()
    }
    expected["mothra-folder-partial/alpha"] = FILES[(b"alpha",)]
    summary = {}
    for stage in ["before", "after"]:
        root = directory / "native-files" / stage
        report = json.loads((root / "extraction.json").read_text())
        records = {
            r["path"].removeprefix("/Hotline19/Files/"): r for r in report["records"]
        }
        dirs = base_dirs | (
            {"mothra-folder-partial/finish"} if stage == "after" else set()
        )
        files = {
            **expected,
            "mothra-folder-partial/part": (
                FILES[(b"alpha",)][0],
                resource_fork() if stage == "after" else resource_fork()[:5],
            ),
        }
        require(
            set(records) == dirs | set(files),
            "Positive native folder inventory differs",
        )
        for name in dirs:
            record = records[name]
            stat = (root / (record["key"] + ".stat.txt")).read_text()
            require(
                record["directory"] and "Type:\tFolder" in stat,
                "Native directory type differs",
            )
            require(
                "File Path: /Hotline19/Files/" + name in stat,
                "Direct catalogue path differs",
            )
        for name, (data, resource) in files.items():
            record = records[name]
            key = record["key"]
            stat = (root / (key + ".stat.txt")).read_text()
            require(
                not record["directory"]
                and "File Path: /Hotline19/Files/" + name in stat,
                "Native file identity differs",
            )
            require(
                record["attributes"]["data"]["exit_code"] == 0
                and (root / (key + ".data")).read_bytes() == data,
                "Native folder DATA differs",
            )
            require(
                f"Resource fork size:\t{len(resource)}" in stat,
                "Native folder resource length differs",
            )
            attribute = record["attributes"]["rsrc"]
            if attribute["exit_code"] == 0:
                require(
                    (root / (key + ".rsrc")).read_bytes() == resource,
                    "Native folder MACR differs",
                )
            else:
                require(
                    not resource
                    and "Attribute 4353-1 not found" in attribute["stderr"],
                    "Failed fork read is not verified empty-resource absence",
                )
            partial = stage == "before" and name == "mothra-folder-partial/part"
            require(
                ("HTft" if partial else "TEXT") in stat
                and ("HTLC" if partial else "MOTH") in stat,
                "Native folder type/creator differs",
            )
        summary[stage] = {
            "positive_records": len(records),
            "partial_resource_bytes": len(files["mothra-folder-partial/part"][1]),
        }
    for failed in ["before-failed-catalogue", "before-failed-after-flush"]:
        report = json.loads(
            (directory / "native-files" / failed / "attempt.json").read_text()
        )
        require(
            report["exit_code"] != 0
            and "nodesize value out of bounds" in report["stderr"],
            "Failed catalogue attempt was misreported",
        )
    timing_root = directory / "native-files/timing"
    timing = json.loads((timing_root / "extraction.json").read_text())
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
        stat = (timing_root / (record["key"] + ".stat.txt")).read_text()
        require(
            record["directory"]
            and "Type:\tFolder" in stat
            and "File Path: " + record["path"] in stat,
            "Timed native directory identity differs",
        )
    summary["timing"] = {"positive_records": len(timing["records"])}
    return summary
