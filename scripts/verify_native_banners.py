#!/usr/bin/env python3
"""Verify bounded native banner metadata, payload and reload observations."""

import json
import typing as typ
from pathlib import Path

from native_banner_cases import GIF_A, GIF_B, URL, image, metadata
from native_packet_evidence import reconcile
from native_wire_names import (
    BANNER_MIN_VERSION,
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_VERSION,
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from script_cli import run
from verify_native_banner_transfers import (
    HANDSHAKE_BYTES,
    LIVENESS_REQUEST,
    OWNER_REQUEST,
    Case,
    check_transfer,
    fields,
    read_transfer,
)
from verify_native_core import require

type Report = dict[str, typ.Any]

# verify_native_auth, verify_native_banner_formats, verify_native_correlation,
# verify_native_agreements, verify_native_htxf and verify_native_login_extras
# import fields from this module, and test_native_banners imports check_case.
__all__ = ["check_case", "fields", "main", "verify"]

INITIAL_CASES = 42
CATALOGS = [(11240, GIF_A, "a"), (11241, GIF_B, "b")]
FILENAME_HELPERS = ["1002af80", "1002e8b0", "1002f080", "1002f0c0"]
SCOPE = (
    "Bounded GIF/URL/absent banner observations, not all formats, arbitrary "
    "reference lifetimes or historical client acceptance"
)


def parse_requests(name: str, report: Report) -> list[Report]:
    """Decode the requests that the main connection sent.

    Returns
    -------
    list[dict[str, typing.Any]]
        One decoded frame for each request, in order.
    """
    incoming = bytes.fromhex(report["streams"]["main"]["sent_hex"])[HANDSHAKE_BYTES:]
    requests = []
    while incoming:
        require(len(incoming) >= FRAME_HEADER_BYTES, name + ": truncated request")
        size = FRAME_HEADER_BYTES + int.from_bytes(
            incoming[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        require(len(incoming) >= size, name + ": truncated request body")
        requests.append(decode_frame(incoming[:size]))
        incoming = incoming[size:]
    return requests


def check_metadata(
    name: str, report: Report, expectation: Report, banners: list[Report]
) -> None:
    """Check that a delayed login emits the 122 notification only when it should."""
    requests = parse_requests(name, report)
    login_request = next(r for r in requests if r["type"] == TYPE_LOGIN)
    require(
        fields(login_request)[FIELD_VERSION]
        == expectation["version"].to_bytes(2, "big"),
        name + ": reported version differs",
    )
    require(
        FIELD_NAME not in fields(login_request)
        and FIELD_ICON not in fields(login_request)
        and any(r["type"] == TYPE_ACCEPT_AGREEMENT for r in requests),
        name + ": delayed completion input differs",
    )
    tag = expectation["type_hex"]
    emitted = tag is not None and expectation["version"] >= BANNER_MIN_VERSION
    require(len(banners) == int(emitted), name + ":122 eligibility differs")
    if not emitted:
        return
    expected = {FIELD_BANNER_TYPE: bytes.fromhex(tag)}
    if expectation["link_hex"] is not None:
        expected[FIELD_BANNER_LINK] = bytes.fromhex(expectation["link_hex"])
    require(fields(banners[0]) == expected, name + ":122 fields differ")
    earlier = [f for f in report["frames"] if f["action"] < banners[0]["action"]]
    require(
        any(f["type"] == TYPE_PRIVILEGES_NOTIFICATION for f in earlier),
        name + ":122 ordering differs",
    )


def check_silent(name: str, kind: str, report: Report) -> None:
    """Check that an early login, or a 212 before completion, gets no notification."""
    if kind != "no-reply-212":
        return
    require(
        not any(f["is_reply"] and f["id"] == OWNER_REQUEST for f in report["frames"]),
        name + ": unexpected212 reply",
    )
    require(
        any(e["event"] == "quiet" for e in report["events"]),
        name + ": missing bounded silence",
    )
    require(
        any(
            f["is_reply"] and f["id"] == LIVENESS_REQUEST and f["error"] == 0
            for f in report["frames"]
        ),
        name + ": missing subsequent liveness ACK",
    )


def check_case(name: str, report: Report, plan: Report, packets: Report) -> Report:
    """Check actual frames/streams; plan labels alone cannot establish semantics.

    Returns
    -------
    dict[str, typing.Any]
        The case, its kind and what the capture showed.
    """
    require(report["status"] == "completed", name + ": incomplete observation")
    expectation = plan["expectation"]
    kind = expectation["kind"]
    banners = [
        f
        for f in report["frames"]
        if f["type"] == TYPE_BANNER_METADATA and not f["is_reply"]
    ]
    result = {"case": name, "kind": kind, "packet_reconciliation": packets}
    if kind == "metadata":
        check_metadata(name, report, expectation, banners)
        result["banner_notifications"] = len(banners)
        return result
    parse_requests(name, report)
    if kind in {"early", "no-reply-212"}:
        require(not banners, name + ": unexpected122")
        check_silent(name, kind, report)
        return result
    transfer = read_transfer(Case(name, report, packets, expectation, banners))
    check_transfer(transfer, kind)
    result.update(
        advertised_bytes=transfer.advertised, delivered_bytes=len(transfer.raw)
    )
    return result


def check_oracle_files(directory: Path) -> None:
    """Check the retained queries for the banner filename helpers."""
    for address in FILENAME_HELPERS:
        prefix = directory / "path-queries" / ("BN-D-" + address)
        record = json.loads(prefix.with_suffix(".json").read_text())
        require(
            record["program"]["sha256"] == ORACLE_SHA256
            and not record["result"]["isError"],
            "Filename helper oracle differs",
        )
        require(
            record["query"]["arguments"]["address"] == address
            and record["result"]["structuredContent"]["code"]
            == prefix.with_suffix(".c").read_text(),
            "Filename helper query differs",
        )


def check_native_files(directory: Path) -> None:
    """Check the native banner forks and their catalogue entries."""
    for catalog, expected, letter in CATALOGS:
        prefix = directory / "native-files" / f"catalog-{catalog}"
        require(
            prefix.with_suffix(".data").read_bytes() == expected,
            "Native banner fork differs",
        )
        stat = prefix.with_suffix(".stat.txt").read_text()
        require(
            f"File Path: /Hotline19/mothra-banner-{letter}.gif" in stat
            and "GIFf" in stat
            and "MOTH" in stat,
            "Native banner identity differs",
        )


def unread(manifest: Report, key: str) -> dict[str, bytes]:
    """Read the retained unread output of a case.

    Returns
    -------
    dict[str, bytes]
        The unread bytes of each connection.
    """
    return {
        k: bytes.fromhex(v)
        for k, v in manifest.get("unread_output", {}).get(key, {}).items()
    }


def check_initial(
    directory: Path, manifest: Report, host: list, guest: list
) -> list[Report]:
    """Replay the exploratory cases that preceded the final ones.

    Returns
    -------
    list[dict[str, typing.Any]]
        The status, error and packet reconciliation of each case.
    """
    require(
        set(manifest["initial_cases"])
        == {p.name for p in (directory / "initial").iterdir()}
        and len(manifest["initial_cases"]) == INITIAL_CASES,
        "Exploratory banner inventory differs",
    )
    initial = []
    for path in sorted((directory / "initial").iterdir()):
        report = verify_capture(path)
        packets = reconcile(
            report, host, guest, unread(manifest, "initial/" + path.name)
        )
        initial.append({
            "case": path.name,
            "status": report["status"],
            "error": report["error"],
            "packet_reconciliation": packets,
        })
    return initial


def verify(directory: Path) -> Report:
    """Verify every case of a retained banner corpus.

    Returns
    -------
    dict[str, typing.Any]
        The final and exploratory observations and the scope they support.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = (
        set(metadata("none", None, None))
        | set(metadata("url", b"URL ", URL))
        | set(image())
        | {"changed-buffer", "missing-metadata-190", "expired-reference"}
    )
    require(
        set(manifest["final_cases"]) == expected
        and len(manifest["final_cases"]) == len(expected),
        "Banner case inventory differs",
    )
    require(
        manifest["oracle_sha256"] == ORACLE_SHA256, "Banner oracle identity differs"
    )
    check_oracle_files(directory)
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    observations = []
    for name in manifest["final_cases"]:
        path = directory / "transcripts" / name
        report = verify_capture(path)
        plan = json.loads((path / "plan.json").read_text())
        packets = reconcile(report, host, guest, unread(manifest, name))
        observations.append(check_case(name, report, plan, packets))
    check_native_files(directory)
    initial = check_initial(directory, manifest, host, guest)
    return {"cases": observations, "initial": initial, "scope": SCOPE}


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a banner corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
