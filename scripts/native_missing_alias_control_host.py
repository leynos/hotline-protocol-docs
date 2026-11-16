"""Read the owned target and its Finder sidecar on the host, and compare them.

Part of the missing-alias runner (``native_missing_alias_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import os
import stat
from pathlib import Path

import native_missing_alias_cases as cases
from native_missing_alias_control_frames import Report, digest, need

RUNTIME_NAME = "native-alias-live-05"
OWNER_UID = 1000
OWNER_MODE = 0o600
TYPE_CREATOR_BYTES = 8
FINDER_RECORD = b"U54TM54X" + bytes(24)
TARGET_KEYS = (
    "path",
    "dev",
    "inode",
    "uid",
    "mode",
    "nlink",
    "size",
    "sha256",
    "type_creator_hex",
)
FINDER_KEYS = (
    "path",
    "dev",
    "inode",
    "uid",
    "mode",
    "nlink",
    "size",
    "type_creator_hex",
)


def _parents(shared: Path) -> Report:
    """Describe the owned shared directory and its sidecar directory.

    Returns
    -------
    dict[str, typing.Any]
        The path, device, inode and owner of each directory.
    """
    result: Report = {}
    for name, parent in (("shared", shared), ("finf", shared / ".finf")):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode), f"Owned {name} parent is not a directory")
        result[name] = {
            "path": str(parent),
            "dev": info.st_dev,
            "inode": info.st_ino,
            "uid": info.st_uid,
        }
    return result


def _read_owned(name: str, path: Path, wanted: bytes) -> tuple[os.stat_result, bytes]:
    """Read one owned file without following links, checking it as it opens.

    Returns
    -------
    tuple[os.stat_result, bytes]
        The status of the file and its bytes.
    """
    info = path.lstat()
    need(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == OWNER_UID
        and stat.S_IMODE(info.st_mode) == OWNER_MODE
        and info.st_nlink == 1,
        f"Owned {name} mode/owner/link differs",
    )
    need(info.st_size == len(wanted), f"Owned {name} length differs")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        opened = os.fstat(handle.fileno())
        need(
            (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
            f"Owned {name} changed before read",
        )
        raw = handle.read(len(wanted) + 1)
    need(len(raw) == len(wanted), f"Owned {name} read length differs")
    return info, raw


def host_state(plan: Report) -> Report:
    """Read the owned runtime's directories, target and Finder sidecar.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.

    Returns
    -------
    dict[str, typing.Any]
        The parents, the target and the Finder sidecar, each with its identity.
    """
    runtime = Path(plan["environment"]["owned_runtime"])
    need(
        runtime.is_absolute() and runtime.name == RUNTIME_NAME,
        "Unexpected owned runtime root",
    )
    need(
        Path(plan["environment"]["owned_working_image"]).parent == runtime,
        "Owned shared path is not the captured image runtime",
    )
    shared = runtime / "shared"
    target = shared / cases.TARGET.decode("ascii")
    finf = shared / ".finf" / cases.TARGET.decode("ascii")
    need(not runtime.is_symlink(), "Owned runtime path is a symlink")
    result: Report = {"parents": _parents(shared)}
    for name, path, wanted in (
        ("target", target, cases.TARGET_DATA),
        ("finder", finf, FINDER_RECORD),
    ):
        info, raw = _read_owned(name, path, wanted)
        if name == "target":
            need(raw == wanted, "Owned target DATA differs")
        else:
            need(
                raw[:TYPE_CREATOR_BYTES] == wanted[:TYPE_CREATOR_BYTES],
                "Owned Finder type/creator differs",
            )
        result[name] = {
            "path": str(path),
            "dev": info.st_dev,
            "inode": info.st_ino,
            "mtime_ns": info.st_mtime_ns,
            "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode),
            "nlink": info.st_nlink,
            "size": info.st_size,
            "sha256": digest(raw),
            "type_creator_hex": (
                raw[:TYPE_CREATOR_BYTES].hex() if name == "finder" else None
            ),
        }
    return result


def same_data_target(before: Report, after: Report) -> None:
    """Require the owned target to keep its identity and content."""
    for key in TARGET_KEYS:
        need(
            before["target"][key] == after["target"][key],
            "Owned target identity/content changed",
        )


def same_target(before: Report, after: Report) -> None:
    """Require the owned target and the Finder sidecar to keep their identity.

    The Finder may change flags or positions, so the sidecar's content is not
    compared; both full hashes are retained.
    """
    need(before["parents"] == after["parents"], "Owned parent changed across UI")
    same_data_target(before, after)
    for key in FINDER_KEYS:
        need(
            before["finder"][key] == after["finder"][key],
            "Owned Finder identity/type changed across UI",
        )
