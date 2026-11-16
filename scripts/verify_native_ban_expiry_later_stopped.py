"""Check the stopped image, its terminal units and the owned Trash footprint."""

from pathlib import Path

from verify_native_ban_expiry_first_common import need, read, sha, when
from verify_native_ban_expiry_later_wire import (
    BASE,
    DEADLINE,
    HOST_PCAP_HEADER,
    INODE,
    ORIGINAL_USERS,
    OWNED_SIZE,
    ROM,
    START,
    WORKING,
)

# The original forks of the stopped image: the file name, its catalogue
# identifier, and its byte size.
STOPPED_FILES = {
    "admin": (11193, 734),
    "fixture-low": (11201, 734),
    "Prefs": (11202, 175),
    "server-data": ("11183-4352-0", 616821),
    "server-rsrc": ("11183-4353-1", 38460),
}

# The owned Trash folders: the folder name, the suffix of its image, the
# directory and data identifiers, and the digest of its data fork.
OWNED_FOLDERS = (
    (
        "m-expiry-zero",
        "zero",
        11754,
        11755,
        "d7c4f728b21c6f1c060cc94ff2d0151f5ee6e29929774a4e026bf59b1ef04ae6",
    ),
    (
        "m-expiry-protected",
        "protected",
        11756,
        11757,
        "ea68398dd65a2bd0d955f155a3265dcc64fc9f0a7607ef02e61d2641a4d956a8",
    ),
)

# The terminal units that each owned unit must report as inactive and
# successful, by the name of the file that holds them.
TERMINAL_UNITS = {
    "c81-terminal-units.txt": 3,
    "lab-terminal-units.txt": 2,
    "bridge-terminal-units.txt": 2,
}


def boundary_gate(post: Path) -> dict:
    """Check the stopped boundary and the final capture bytes.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.

    Returns
    -------
    dict
        The terminal record of the stopped image.
    """
    gate = read(post / "stopped-read-gate.json")
    terminal = read(post / "terminal.json")
    need(
        gate["image_inode"] == INODE
        and gate["image_fd_owners"] == []
        and gate["emulator_pid_absent"] is True
        and gate["source_start_ticks"] == int(START)
        and terminal["emulator_absent"] is True
        and terminal["sheep_wrapper_absent"] is True
        and terminal["bridge_pids_absent"] is True
        and terminal["stopped_image_inode"] == INODE
        and "not orderly OS shutdown" in terminal["retirement"]
        and when(terminal["utc"]) < when(DEADLINE),
        "Stopped and FD-free extraction boundary differs",
    )
    for key, name in (
        ("guest_pcap", "lab-guest-final.pcap"),
        ("namespace_pcap", "lab-namespace.pcap"),
        ("primary_pcap", "primary-syn.pcap"),
    ):
        path = post / name
        need(
            terminal[key] == {"bytes": path.stat().st_size, "sha256": sha(path)},
            f"Final {key} bytes differ",
        )
    return terminal


def units_gate(post: Path) -> None:
    """Check the terminal units, the capture drops and the primary SYN silence.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.
    """
    for name, expected in TERMINAL_UNITS.items():
        data = (post / name).read_text()
        need(
            data.count("ActiveState=inactive") == expected
            and data.count("MainPID=0") == expected
            and data.count("Result=success") == expected,
            f"Owned terminal units differ: {name}",
        )
    for label in ("host", "namespace"):
        data = (post / f"{label}-terminal-journal.log").read_text()
        need("0 packets dropped by kernel" in data, f"{label} capture drops differ")
    need(
        "0 packets captured" in (post / "host-terminal-journal.log").read_text()
        and (post / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER,
        "Primary SYN isolation differs",
    )


def assets_gate(post: Path) -> None:
    """Check the recorded hashes of the working image, base image and ROM.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.
    """
    hashes = {}
    for line in (post / "stopped-assets.sha256").read_text().splitlines():
        digest, path = line.split("  ", 1)
        hashes[Path(path).name] = digest
    need(
        hashes == {"working.dsk": WORKING, "base.dsk": BASE, "rom": ROM},
        "Stopped working/base/ROM hash receipt differs",
    )


def preparation_gate(first: Path) -> dict:
    """Check the original immutable preparation baseline of the first epoch.

    Parameters
    ----------
    first : Path
        The first-epoch corpus directory.

    Returns
    -------
    dict
        The preflight record of the preparation.
    """
    prep = read(first / "preparation/preflight.json")
    need(
        prep["working.dsk"]["inode"] == INODE
        and prep["working.dsk"]["sha256"] == BASE
        and prep["base.dsk"]["sha256"] == BASE
        and prep["rom"]["sha256"] == ROM
        and prep["banned_absent"] is True
        and prep["original_user_count"] == ORIGINAL_USERS,
        "Original immutable preparation baseline differs",
    )
    return prep


def forks_gate(post: Path, prep: dict) -> None:
    """Check that the original forks are unchanged and that no ban file appeared.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.
    prep : dict
        The preflight record of the preparation.
    """
    catalog = (post / "stopped-catalog.txt").read_text()
    need("Banned" not in catalog, "Banned file appeared after temporary expiry")
    for name, (identifier, size) in STOPPED_FILES.items():
        path = post / "stopped-hfs" / f"{name}.bin"
        need(
            path.stat().st_size == size
            and sha(path) == prep["files"][name]["sha256"]
            and prep["files"][name]["catalog"] == str(identifier),
            f"Original stopped fork changed: {name}",
        )


def owned_gate(post: Path) -> None:
    """Check the owned Trash folders, their catalogue entries and their forks.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.
    """
    allocated = (post / "stopped-allocated-catalog.txt").read_text()
    deleted = (post / "stopped-deleted-catalog.txt").read_text()
    for name, suffix, directory, data_id, digest in OWNED_FOLDERS:
        path = post / "stopped-hfs" / f"owned-{suffix}.bin"
        need(
            f"d/d {directory}:\tTrash/{name}" in allocated
            and f"-/r {data_id}:\tTrash/{name}/UserData" in allocated
            and name not in deleted
            and sha(path) == digest
            and path.stat().st_size == OWNED_SIZE
            and all(
                "Allocated" in (post / "stopped-hfs" / f"istat-{i}.txt").read_text()
                and f"File Path: /Trash/{name}"
                in (post / "stopped-hfs" / f"istat-{i}.txt").read_text()
                for i in (directory, data_id)
            ),
            f"Owned {name} allocated Trash footprint differs",
        )


def stopped_gate(corpus: Path, first: Path, manifest: dict) -> dict:
    """Check the stopped image from its boundary to its owned Trash footprint.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    manifest : dict
        The manifest of the later corpus, which the checks do not read.

    Returns
    -------
    dict
        The working image hash and the number of owned folders in the Trash.
    """
    post = corpus / "raw/post"
    boundary_gate(post)
    units_gate(post)
    assets_gate(post)
    prep = preparation_gate(first)
    forks_gate(post, prep)
    owned_gate(post)
    return {"working_sha256": WORKING, "owned_folders_allocated_in_trash": 2}
