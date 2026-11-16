#!/usr/bin/env python3
"""Replay A29 PM semantics, full A7 readbacks and both saved TCP packet views."""

import json
import typing as typ
from pathlib import Path

from protocol_capture import digest, verify_capture
from script_cli import UsageError, run
from verify_native_core import require
from verify_native_pm_checks import check_pm
from verify_native_pm_readback import full_readback
from verify_native_pm_views import packet_views

type Report = dict[str, typ.Any]

# The checks live in their own modules and stay importable from here.
__all__ = [
    "check_pm",
    "digest",
    "full_readback",
    "inventory",
    "main",
    "packet_views",
    "verify",
]

STATUS = "bounded-native-pm-a29"
CAPTURES = ("preflight", "observe", "postflight")


def inventory(root: Path) -> None:
    """Check the manifest, the recorded file hashes and the checksum list.

    The checks run in a fixed order: the manifest status, each file's hash in
    manifest order, the checksum list's names, then each line's hash.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.
    """
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["status"] == STATUS, "PM manifest status differs")
    for path, expected in manifest["files"].items():
        require(
            digest((root / path).read_bytes()) == expected,
            f"PM file hash differs: {path}",
        )
    checks = (root / "SHA256SUMS").read_text().splitlines()
    require(
        {line.split("  ", 1)[1] for line in checks}
        == set(manifest["files"]) | {"manifest.json"},
        "PM SHA inventory differs",
    )
    for line in checks:
        expected, path = line.split("  ", 1)
        require(
            digest((root / path).read_bytes()) == expected,
            f"PM SHA line differs: {path}",
        )


def verify(root: Path) -> Report:
    """Verify the corpus: inventory, readbacks, messages, then packet views.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.

    Returns
    -------
    dict[str, typing.Any]
        The status, both readback summaries, the message result and the
        connections of each capture.
    """
    inventory(root)
    source = json.loads((root / "a7-report.json").read_text())
    pre = full_readback(root, "preflight", source)
    post = full_readback(root, "postflight", source)
    _, pm = check_pm(root)
    reports = {name: verify_capture(root / name) for name in CAPTURES}
    packets = packet_views(root, reports, bytes.fromhex(pm["peer_uid_hex"]))
    return {
        "status": "verified-bounded-native-pm",
        "preflight": pre,
        "postflight": post,
        "pm": pm,
        "packet_connections": {k: list(v["connections"]) for k, v in packets.items()},
    }


def command(batch: str, *, output: str | None = None) -> None:
    """Verify a corpus and print its status.

    Parameters
    ----------
    batch
        The corpus directory.
    output
        A new file that receives the result as JSON.

    Raises
    ------
    UsageError
        If the output file exists; the corpus is verified first.
    """
    result = verify(Path(batch))
    if output is not None:
        target = Path(output)
        if target.exists():
            message = "Refusing existing output"
            raise UsageError(message)
        target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(result["status"])


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(command, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
