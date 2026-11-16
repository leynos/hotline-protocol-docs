"""Check the stopped forks, the account set and the unit terminal state."""

import typing as typ

from verify_native_rate304_partial_core import FORKS, need, read, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

ORIGINAL_ACCOUNTS = 2  # the admin and fixture-low accounts of the stopped image
INACTIVE_UNITS = 3  # the units that are inactive at the terminal state
IMAGE_SHA256 = "1909b4ed299f032f95d5fbac2f4b6446c49e860e57bf9018ec7a96dec24e8f74"


def check_forks(raw: Path, forks: dict) -> None:
    """Check the stopped fork hashes and the bytes of the four named forks."""
    need(
        {name: row["sha256"] for name, row in forks.items()} == FORKS,
        "Stopped fork hashes differ",
    )
    for name in ("admin", "fixture-low", "Prefs", "board"):
        need(
            sha(raw / "stopped" / f"{name}.bin") == FORKS[name],
            f"Stopped {name} bytes differ",
        )


def check_catalog(raw: Path, forks: dict) -> None:
    """Check the allocated account set, the absence of a ban and the empty board."""
    catalog = (raw / "stopped/catalog-allocated.txt").read_text()
    users = [
        line
        for line in catalog.splitlines()
        if "/Users/" in line and line.endswith("/UserData")
    ]
    need(
        len(users) == ORIGINAL_ACCOUNTS
        and any("/Users/admin/UserData" in x for x in users)
        and any("/Users/fixture-low/UserData" in x for x in users),
        "Original account set differs",
    )
    need(
        "/Banned" not in catalog and forks["board"]["size"] == 0,
        "Stopped ban or board state differs",
    )


def check_units(raw: Path) -> None:
    """Check the unit terminal state, the released image and the retired user units."""
    units = (raw / "units-terminal.txt").read_text()
    need(
        units.count("ActiveState=inactive") == INACTIVE_UNITS
        and "ActiveState=failed" in units
        and "ExecMainStatus=1" in units,
        "Unit terminal state differs",
    )
    need(
        (raw / "fuser-terminal.exit").read_text().strip() == "1",
        "Working image still held",
    )
    need(
        "Result=success" in (raw / "user-units-terminal.txt").read_text(),
        "Owned user-unit retirement missing",
    )
    need(
        IMAGE_SHA256 in (raw / "stopped/image-sha256.txt").read_text(),
        "Stopped image hash differs",
    )


def stopped(raw: Path) -> None:
    """Check the stopped state of the corpus in the order of the case."""
    forks = read(raw / "stopped/forks.json")
    check_forks(raw, forks)
    check_catalog(raw, forks)
    check_units(raw)
