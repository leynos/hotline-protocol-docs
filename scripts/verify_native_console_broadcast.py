#!/usr/bin/env python3
"""Verify a retained native console broadcast: frames, captures and postflight."""

import hashlib
import json
import sys
import typing as typ
from pathlib import Path
from tempfile import TemporaryDirectory

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from script_cli import run
from verify_mac_peer_first_session import field_map, parse_frames, require
from verify_native_account_updates import enumeration
from verify_native_console_broadcast_capture import (
    GUEST_PORT,
    NAMES,
    check_capture,
    check_tail,
    complete_syns,
    connection,
    delta,
    packets_for,
    partial,
)
from verify_native_console_broadcast_frames import (
    TEXT_AFTER,
    TEXT_BEFORE,
    TEXT_CONSOLE,
    check_frames,
)
from verify_native_mkdir import listing
from verify_native_resume import reply

# The helper modules hold the checks. The names below stay importable from this
# module because the original defined them publicly or imported them at module
# level. The corpus test imports verify.
__all__ = [
    "NAMES",
    "TEXT_AFTER",
    "TEXT_BEFORE",
    "TEXT_CONSOLE",
    "check_capture",
    "check_frames",
    "check_inventory",
    "check_postflight",
    "check_tail",
    "connection",
    "delta",
    "enumeration",
    "field_map",
    "lifetime",
    "listing",
    "main",
    "packets_for",
    "parse_frames",
    "partial",
    "read_packets",
    "reply",
    "require",
    "show",
    "stream",
    "verify",
    "verify_capture",
]


type Report = dict[str, typ.Any]
type Packet = dict[str, typ.Any]

POSTFLIGHT_ACTIONS = 29  # the completed actions of the postflight run
POSTFLIGHT_CONNECTIONS = 2  # the guest connections of the postflight capture
POSTFLIGHT_DOWNLOAD_PORT = 5501  # the guest port of the postflight download
ACCOUNT_COUNT = 2  # the accounts that the postflight enumeration holds
FILES_ROOT_ENTRIES = 41  # the entries of the postflight Files root


def check_inventory(root: Path) -> None:
    """Check the manifest status and the SHA-256 of every file it lists.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.
    """
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["status"] == "bounded-native-console-broadcast", "Bad manifest")
    for name, expected in manifest["files"].items():
        require(
            hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
            f"File SHA differs: {name}",
        )


def verify(root: Path) -> dict[str, typ.Any]:
    """Verify the native console broadcast corpus in ``root``.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory: the manifest, the captures, the operator actions and
        the postflight and baseline runs.

    Returns
    -------
    dict[str, typing.Any]
        The status of the corpus and the results of its frame, capture and postflight
        checks.
    """
    check_inventory(root)
    report = verify_capture(root / "capture")
    require(
        report["oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "Oracle identity differs",
    )
    require(
        json.loads((root / "operator-actions.json").read_text())["result"].startswith(
            "Exactly one console send"
        ),
        "Operator scope differs",
    )
    return {
        "status": "verified-finite-native-console-broadcast",
        "frames": check_frames(report),
        "capture": check_capture(root, report),
        "postflight": check_postflight(root),
    }


def _check_postflight_state(root: Path, post: Report, base: Report) -> None:
    """Check the postflight status, the A7 baseline and the restored counts.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.
    post : dict[str, typing.Any]
        The verified report of the postflight capture.
    base : dict[str, typing.Any]
        The verified report of the baseline capture.
    """
    require(
        post["status"] == "completed"
        and post["completed_actions"] == POSTFLIGHT_ACTIONS,
        "Postflight incomplete",
    )
    require(
        json.loads((root / "postflight/plan.json").read_text())["expectation"]
        == json.loads((root / "baseline/plan.json").read_text())["expectation"],
        "Postflight expectation differs",
    )
    for identifier in (10, 11, 12, 14, 16, 17):
        require(
            reply(post, identifier)["fields"] == reply(base, identifier)["fields"],
            f"A7 baseline changed: {identifier}",
        )
    require(len(enumeration(reply(post, 10))) == ACCOUNT_COUNT, "Account count differs")
    require(
        len(listing(reply(post, 11))) == FILES_ROOT_ENTRIES,
        "Files root count differs",
    )
    require(
        post["streams"]["download"]["received_hex"]
        == base["streams"]["download"]["received_hex"],
        "Full fixture stream changed",
    )


def _postflight_packets(root: Path) -> list[Packet]:
    """Read the guest capture of the postflight run, with its appended packets.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets of the postflight guest capture.
    """
    with TemporaryDirectory() as temporary:
        return read_packets(
            delta(
                root / "guest-after.pcap",
                root / "guest-postflight.pcap",
                Path(temporary),
            )
        )


def _check_postflight_flows(post: Report, guest: list[Packet]) -> None:
    """Check the postflight guest bytes of each client against its report.

    Parameters
    ----------
    post : dict[str, typing.Any]
        The verified report of the postflight capture.
    guest : list[dict[str, typing.Any]]
        The packets of the postflight guest capture.
    """
    for name, destination in (
        ("a", GUEST_PORT),
        ("download", POSTFLIGHT_DOWNLOAD_PORT),
    ):
        port, sent, received = connection(post, name)
        _, out, inbound = packets_for(
            guest, ("10.0.2.2", port), ("10.0.2.15", destination)
        )
        require(
            (out, inbound) == (sent, received),
            f"Postflight guest/report bytes differ: {name}",
        )


def check_postflight(root: Path) -> dict[str, typ.Any]:
    """Check the postflight run, the restored baseline and its guest bytes.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The restored status and the retained counts of the postflight run.
    """
    post = verify_capture(root / "postflight")
    base = verify_capture(root / "baseline")
    _check_postflight_state(root, post, base)
    guest = _postflight_packets(root)
    require(
        len(complete_syns(guest)) == POSTFLIGHT_CONNECTIONS,
        "Postflight guest connection count differs",
    )
    _check_postflight_flows(post, guest)
    return {
        "status": "restored-a7-baseline",
        "accounts": 2,
        "files_root": 41,
        "download_bytes": 1_049_073,
    }


def show(directory: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``directory``.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(directory)), indent=2) + "\n")


def main() -> None:
    """Verify a native console broadcast corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
