#!/usr/bin/env python3
"""Replay the frozen C39-C41 source and headless oracle findings offline."""

import argparse
import hashlib
import json
from pathlib import Path

ORACLE_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
C40 = ["1006e040", "1006e1a0", "1006de10", "1006e0b0", "1006ddb0", "1002e300"]
C41 = [
    "10074930",
    "10071650",
    "10074b10",
    "10071950",
    "100742a0",
    "10070d20",
    "100749b0",
    "10071770",
]


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def code(report: dict, address: str) -> str:
    query = next(q for q in report["queries"] if q["label"] == address)
    result = query["result"]
    require(not result["isError"], f"Oracle error at {address}")
    content = result["structuredContent"]
    require(
        content["function"]["address"] == address and not content["truncated"],
        f"Oracle mapping or truncation at {address}",
    )
    return content["code"]


def includes(haystack: str, needles: tuple[str, ...], label: str) -> None:
    for needle in needles:
        require(needle in haystack, f"{label}: missing {needle}")


def verify(corpus: Path) -> None:
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-download-send-path-01", "Corpus schema")
    require(manifest["binary_sha256"] == ORACLE_SHA, "Binary identity")
    require(manifest["oracle_function_count"] == 1840, "Function count")
    require(
        manifest["c40_content_queries"] == 8 and manifest["c41_content_queries"] == 8,
        "Query budget",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(actual == set(files), "Corpus inventory")
    for name, expected in files.items():
        require(digest(corpus / name) == expected, f"Corpus SHA: {name}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{value}  {name}" for name, value in sorted(files.items())],
        "SHA256SUMS list",
    )
    provenance = load(corpus / "source-provenance.json")
    require(
        provenance["schema"] == "native-download-send-path-source-provenance-01",
        "Source provenance schema",
    )
    require(
        set(provenance["sources"]) == set(files) - {"source-provenance.json"},
        "Source provenance inventory",
    )
    for name, entry in provenance["sources"].items():
        require(
            entry["sha256"] == files[name]
            and entry["bytes"] == (corpus / name).stat().st_size,
            f"Source provenance: {name}",
        )

    c40, c41 = (load(corpus / f"oracle/c{n}-report.json") for n in (40, 41))
    for number, report, addresses in ((40, c40, C40), (41, c41, C41)):
        require(
            report["status"] == "complete" and report["project_unchanged"],
            f"C{number} run status",
        )
        require(
            report["project_before"] == report["project_after"],
            f"C{number} project mutation",
        )
        require(report["binary_sha256"] == ORACLE_SHA, f"C{number} binary hash")
        require(
            "--no-analyze" in report["args"]
            and "--discard" in report["args"]
            and "--save" not in report["args"],
            f"C{number} read-only invocation",
        )
        before = report["queries"][0]["result"]["structuredContent"]
        after = report["identity_after"]["structuredContent"]
        require(
            before == after
            and before["sha256"] == ORACLE_SHA
            and before["function_count"] == 1840,
            f"C{number} program identity",
        )
        expected_labels = ["identity-before", *addresses]
        if number == 40:
            expected_labels.append("worker-callers")
        require(
            [q["label"] for q in report["queries"]] == expected_labels,
            f"C{number} query set",
        )
        for address in addresses:
            code(report, address)
    caller = c40["queries"][-1]["result"]["structuredContent"]["callers"]
    require(
        caller["total"] == 1
        and caller["items"][0]["call_site"] == "100017e0"
        and caller["items"][0]["caller"] is None,
        "Worker call site",
    )
    failed_caller = load(corpus / "oracle/c40-caller.json")["result"]
    require(
        failed_caller["isError"]
        and "FUNCTION_NOT_FOUND" in failed_caller["content"][0]["text"],
        "Unannotated caller evidence",
    )

    source = lambda name: (corpus / "sources" / name).read_text()
    includes(source("D-1000acf0.c"), ("uVar6 == 0xca", "FUN_100121a0"), "202 dispatch")
    includes(
        source("D-100121a0.c"),
        ("FUN_1002d470", "FUN_1002d7b0", "iVar10 + 0x1c) = 0x19000", "param_1 + 0x38"),
        "202 entry",
    )
    includes(source("D-1000bd20.c"), ("FUN_1000e600", "*puVar4 = uVar2"), "HTXF attach")
    includes(
        source("B04-D-1000c200.c"),
        (
            "FUN_1006e040(iVar8)",
            "FUN_1006e1a0(iVar8)",
            "piVar1[7] = piVar1[7] + 0x19000",
            "piVar1[7] = 0x200000",
            "FUN_1006de10(iVar8,uVar4)",
            "FUN_1006e0b0(iVar8)",
            "piVar1[6] = piVar1[6] + uVar3",
        ),
        "Download worker",
    )
    includes(source("B04-D-1002d830.c"), ("FUN_1002e300",), "FILP serializer")

    includes(
        code(c41, "10071650"),
        (
            "OTEnterNotifier",
            "param_1 + 0x3c",
            "puVar3[3] - puVar3[2]",
            "puVar3 = (undefined4 *)*puVar3",
        ),
        "Pending byte count",
    )
    includes(
        code(c41, "10071950"),
        ("param_1 + 0x3c) == 0", "**(int **)(param_1 + 0x3c) == 0", "uVar2 = 1"),
        "Queue readiness",
    )
    includes(
        code(c41, "10070d20"),
        (
            ".glue::OTSnd",
            "if ((int)uVar2 < 0)",
            "uVar2 = 0",
            "if (uVar2 < *(uint *)(param_2 + -4))",
            "*(uint *)(param_2 + -8) = uVar2",
            "*(int *)(param_1 + 0x3c) = param_2 + -0x10",
        ),
        "Partial send queue",
    )
    includes(
        code(c41, "10071770"),
        ("if (bVar1)", "OTAtomicClearBit", "OTAtomicSetBit", "FUN_10028dc0(0x66"),
        "Callback condition",
    )
    includes(
        code(c40, "1002e300"),
        (".glue::PBReadSync", "(short)uVar1 != -0x27", "return local_28"),
        "Fork read",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    verify(args.corpus)
    print("native download send path: verified")


if __name__ == "__main__":
    main()
