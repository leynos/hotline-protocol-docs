"""Check the file inventory, the frozen sources and the A7 replay of the witness."""

import typing as typ

from verify_classic_native_baseline import verify_a7
from verify_classic_roster_subject_115_common import (
    AGREEMENT_SHA,
    CAPTURE_GATE_SHA,
    FILP_SHA,
    PARSER_SHA,
    PROXY_SHA,
    load,
    need,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

AGREEMENT_ACTION = 6  # the frame action that carries the agreement in an A7 report
AGREEMENT_BYTES = 242  # the length of the agreement text


def inventory(base: Path) -> int:
    """Check every corpus file against its ``SHA256SUMS`` entry.

    Returns
    -------
    int
        The number of inventory entries.
    """
    root = base.resolve().parents[3]
    found: set[str] = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, rel = line.split("  ", 1)
        path = root / rel
        need(path.is_file() and path.resolve().is_relative_to(base), "inventory path")
        need(sha(path.read_bytes()) == expected, "SHA inventory mismatch")
        need(rel not in found, "duplicate inventory entry")
        found.add(rel)
    actual = {
        str(p.relative_to(root))
        for p in base.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    need(found == actual, "SHA inventory file set")
    return len(found)


def source_check(base: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the frozen source snapshots, client identity and oracle identity."""
    source = manifest["source"]
    for name, revision, expected, key in (
        (
            "classic_login_proxy.py",
            "73681b1b06d58ede021a7440c1173595e8e78a0d",
            PROXY_SHA,
            "proxy",
        ),
        (
            "pcap_tcp.py",
            "31fd33efaa778eabcaed4195cccad4e2d7e89094",
            PARSER_SHA,
            "parser",
        ),
    ):
        need(
            source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}",
            "source path",
        )
        need(
            source[f"{key}_revision"] == revision
            and source[f"{key}_sha256"] == expected,
            "source revision/hash",
        )
        need(
            source[f"{key}_snapshot_path"] == f"as-run/{name}.txt",
            "source snapshot path",
        )
        need(
            sha((base / source[f"{key}_snapshot_path"]).read_bytes()) == expected,
            "frozen source changed",
        )
    need(
        source["client_data_sha256"]
        == "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315",
        "client DATA",
    )
    need(
        source["client_resource_sha256"]
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b",
        "client RSRC",
    )
    need(
        source["client_vers_short"] == "1.9.1.0"
        and source["vendor_authenticity"] == "unproved",
        "client identity limits",
    )
    need(
        source["native_oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "oracle identity",
    )
    need(manifest["capture_gate_sha256"] == CAPTURE_GATE_SHA, "capture gate source")


def a7_check(base: Path) -> dict[str, typ.Any]:
    """Check the full A7 replay and the agreement text of both A7 reports.

    Returns
    -------
    dict[str, typing.Any]
        The summary that ``verify_a7`` returns for the run.
    """
    result = verify_a7(base / "run")
    need(
        result
        == {"actions_each": 29, "accounts": 2, "files": 41, "filp_sha256": FILP_SHA},
        "full A7",
    )
    for phase in ("a7-preflight", "a7-postflight"):
        report = load(base / "run" / phase / "report.json")
        agreement = next(f for f in report["frames"] if f["action"] == AGREEMENT_ACTION)
        text = bytes.fromhex(agreement["fields"][0]["hex"])
        need(
            len(text) == AGREEMENT_BYTES and sha(text) == AGREEMENT_SHA,
            "known agreement",
        )
    return result
