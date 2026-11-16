"""Check the preboot state of the persisted-ban reload witness before its probe."""

import typing as typ

from verify_native_ban_reload_core import (
    BAN,
    BASE,
    DATA,
    EMULATOR,
    IMAGE_BEFORE,
    ROM,
    read,
    require,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

# The SHA-256 digests of the stored user records that the preboot HFS listing holds.
ADMIN_USER_SHA = "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3"
LOW_USER_SHA = "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5"
BAN52_USER_SHA = "0df7dd5ad9c2c992ddefa4aa30af069c27d1e0d793ea19d112d0520e9fcc3e86"


def preflight(corpus: Path) -> None:
    """Check the preboot source, the HFS paths and the stored ban bytes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    root = corpus / "c61"
    p = read(root / "preflight.json")
    require(
        p["source_sha256"]
        == {
            "working": IMAGE_BEFORE,
            "base": BASE,
            "rom": ROM,
            "emulator": EMULATOR,
            "server_data": DATA,
        }
        and p["working_fd_holders"] == []
        and p["ports_15750_15753_free"] is True
        and p["full_file_baseline"] == "not_exercised"
        and p["existing_ban_state_preserved"] is True,
        "Preboot source or scope differs",
    )
    require(
        sha(root / "preboot-fls.txt") == p["fls_sha256"]
        and all(
            item in (root / "preboot-fls.txt").read_text()
            for item in (
                "Hotline19/Banned",
                "Hotline19/Users/admin/UserData",
                "Hotline19/Users/fixture-low/UserData",
                "Hotline19/Users/m-ban52-only/UserData",
            )
        ),
        "Preboot HFS paths differ",
    )
    users = p["hfs_user_data_and_ban"]
    require(
        users
        == {
            "admin": {"bytes": 734, "sha256": ADMIN_USER_SHA},
            "fixture-low": {"bytes": 734, "sha256": LOW_USER_SHA},
            "m-ban52-only": {"bytes": 734, "sha256": BAN52_USER_SHA},
            "Banned": {"bytes": 49, "sha256": BAN},
        }
        and sha(corpus / "c56-reference/Banned.data.bin") == BAN
        and sha(root / "Banned-postprobe.data.bin") == BAN
        and (root / "Banned-postprobe.data.bin").read_bytes()
        == (corpus / "c56-reference/Banned.data.bin").read_bytes(),
        "Stored ban or account bytes differ",
    )
    c56 = read(corpus / "c56-reference/terminal.json")
    require(
        c56["stopped_image_sha256"] == IMAGE_BEFORE
        and c56["ban_file"]["data_sha256"] == BAN,
        "C56 stopped-image origin differs",
    )
