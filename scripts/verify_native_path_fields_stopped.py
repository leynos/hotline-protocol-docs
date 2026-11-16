"""Gates on the stopped Hotline image: owners, catalogues, cleanup and captures."""

import datetime as dt
import typing as typ

from verify_native_path_fields_constants import (
    CATEGORY_IDENTIFIER,
    DEADLINE,
    FILE_CELLS,
    FORKS,
    INODE,
    MARKER_ENTRIES,
    MIN_CATALOGUE_LINES,
    OWNED_UNITS,
    PID,
    RECORDERS,
    SKIPPED_IDENTIFIER,
    START,
    SUPPLEMENT_COMMANDS,
)
from verify_native_path_fields_core import need, read, sha

if typ.TYPE_CHECKING:
    from pathlib import Path


def _owner(epoch: Path, hfs: dict, retire: dict) -> None:
    """Check the retired owner, the deadline and that the image is no longer held."""
    need(
        hfs["pid_gone"] is True
        and hfs["root_fuser_exit"] == 1
        and hfs["working_inode"] == INODE
        and hfs["original_ticks"] == {"1099659": "767842", "1012834": "2357813"}
        and retire["pid"] == PID
        and retire["start_ticks"] == int(START)
        and retire["gone_final"] is True
        and "forced emulator TERM" in retire["reason"],
        "Stopped owner/retirement differs",
    )
    need(
        dt.datetime.fromisoformat(retire["utc"]) < dt.datetime.fromisoformat(DEADLINE)
        and dt.datetime.fromisoformat((epoch / "units-stopped.utc").read_text().strip())
        < dt.datetime.fromisoformat(DEADLINE),
        "Retirement missed fixed deadline",
    )
    need(
        (epoch / "working-fuser-after.exit").read_text().strip() == "1"
        and (epoch / "working-fuser-after.stdout").read_bytes() == b""
        and (epoch / "working-fuser-after.stderr").read_bytes() == b"",
        "Stopped image still held",
    )


def _catalogues(epoch: Path, hfs: dict) -> list[str]:
    """Check the two stopped catalogues against their recorded digests.

    Returns
    -------
    list[str]
        The lines of the allocated catalogue.
    """
    for key, filename in (
        ("fls-full", "stopped-fls-full.stdout"),
        ("fls-allocated", "stopped-fls-allocated.stdout"),
    ):
        result = hfs["results"][key]
        need(
            result["exit"] == 0 and result["sha256"] == sha(epoch / filename),
            "Stopped catalogue differs",
        )
    full = (epoch / "stopped-fls-full.stdout").read_text().splitlines()
    allocated = (epoch / "stopped-fls-allocated.stdout").read_text().splitlines()
    need(
        full == allocated and len(full) >= MIN_CATALOGUE_LINES,
        "Allocated/full HFS differs",
    )
    return allocated


def _marker(corpus: Path, allocated: list[str]) -> list[str]:
    """Check the derived marker catalogue against the allocated listing.

    Returns
    -------
    list[str]
        The catalogue lines of the owned marker entries.
    """
    marker = read(corpus / "derived/stopped-marker-catalogue.json")
    need(
        marker["catalogue"] == "raw/epoch/stopped-fls-allocated.stdout"
        and marker["entries"]
        == [
            {"line_number": i + 1, "line": line}
            for i, line in enumerate(allocated)
            if "m-path47" in line or "m-n47" in line or "m-cat47" in line
        ],
        "Stopped marker catalogue differs",
    )
    return [row["line"] for row in marker["entries"]]


def _baseline(prep: Path, hfs: dict) -> None:
    """Check that the original Files and News catalogues are unchanged."""
    baseline_catalogue = read(prep / "files-news-catalog.json")["entries"]
    need(
        all(
            [
                line
                for line in hfs["files_news"]
                if f"Hotline19/{kind}" in line
                and "m-path47" not in line
                and "m-n47" not in line
                and "m-cat47" not in line
            ]
            == baseline_catalogue[kind]
            for kind in ("Files", "News")
        ),
        "Original Files/News catalogue differs",
    )


def _cleanup(names: list[str], allocated: list[str]) -> None:
    """Check that the owned entries are the only ones moved to Trash."""
    need(
        len(names) == MARKER_ENTRIES
        and sum(
            "Trash/m-path47/H-" in line and line.endswith(f"/p{i}")
            for i in range(FILE_CELLS)
            for line in names
        )
        == FILE_CELLS
        and any("Trash/m-cat47" in line for line in names)
        and any("Trash/m-n47" in line for line in names)
        and not any(
            "Hotline19/Files/m-path47" in line or "Hotline19/News/m-n47" in line
            for line in allocated
        ),
        "Owned cleanup/Trash path differs",
    )


def _users(prep: Path, hfs: dict, allocated: list[str]) -> dict:
    """Check the original users and the banned list, then read the preflight.

    Returns
    -------
    dict
        The preflight record of the preparation.
    """
    prepared = read(prep / "preflight.json")
    need(
        hfs["active_users"]
        == [
            "-/r 11193:\tHotline19/Users/admin/UserData",
            "-/r 11201:\tHotline19/Users/fixture-low/UserData",
        ]
        and not hfs["banned_lines"]
        and all(line in allocated for line in hfs["active_users"]),
        "Original users/Banned state differs",
    )
    return prepared


def _forks(hfs: dict, prepared: dict) -> None:
    """Check each fork read from the stopped image."""
    # No copyrighted fork bytes are packaged; retained command receipt is
    # evidence of a stopped read, not an independently rehashed fork here.
    for name, digest in FORKS.items():
        item = hfs["results"][f"icat-{name}"]
        need(
            item["exit"] == 0
            and item["sha256"] == digest
            and (item["size"] == prepared["forks"][name]["size"]),
            f"Stopped {name} fork differs",
        )


def _board(epoch: Path, hfs: dict) -> None:
    """Check the stopped board stat against its retained output."""
    need(
        hfs["results"]["istat-board"]["exit"] == 0
        and hfs["results"]["istat-board"]["sha256"]
        == sha(epoch / "stopped-istat-board.stdout"),
        "Stopped board stat differs",
    )


def _commands(supplement: Path) -> None:
    """Check the marker commands and the bytes each one retained."""
    commands = read(supplement / "commands.json")
    need(
        len(commands) == SUPPLEMENT_COMMANDS, "Supplement marker command count differs"
    )
    for item in commands:
        path = supplement / item["stdout_file"]
        need(
            item["exit"] == 0
            and path.stat().st_size == item["size"]
            and sha(path) == item["sha256"],
            "Stopped marker command bytes differ",
        )


def _records(supplement: Path, names: list[str]) -> None:
    """Check the type and the catalogue record of each marker identifier."""
    for identifier in range(11747, 11759):
        if identifier == SKIPPED_IDENTIFIER:
            continue
        text = (supplement / f"istat-{identifier}.stdout").read_text()
        matching = [
            line for line in names if line.split(":", 1)[0].endswith(f" {identifier}")
        ]
        need(
            len(matching) == 1
            and f"File Path: /{matching[0].split(chr(9), 1)[1]}" in text
            and f"Catalog Record: {identifier}" in text
            and "File Path: /Trash/" in text
            and (
                "Type:\tFile" if identifier == CATEGORY_IDENTIFIER else "Type:\tFolder"
            )
            in text,
            "Stopped marker type/catalogue differs",
        )


def _category(supplement: Path) -> None:
    """Check the News category folder's fork and its type and creator."""
    category = (supplement / f"istat-{CATEGORY_IDENTIFIER}.stdout").read_text()
    need(
        "Resource fork size:\t0" in category
        and "File type:\t484c4e5a  HLNZ" in category
        and "File creator:\t48544c53  HTLS" in category
        and sha(supplement / "category-data.bin")
        == "7d82b5826175ca1971249907692fa51823998e11d77dbd577226ee2bde97cd1a",
        "Stopped News category fork differs",
    )


def _supplement(epoch: Path, names: list[str]) -> None:
    """Check the supplementary marker commands, records and category fork."""
    supplement = epoch / "stopped-marker-forks"
    fd_free = read(supplement / "fd-free-before-read.json")
    need(
        fd_free["pid"] == PID
        and fd_free["pid_gone"] is True
        and fd_free["working_inode"] == INODE
        and fd_free["root_fuser_exit"] == 1
        and fd_free["root_fuser_stdout"] == fd_free["root_fuser_stderr"] == "",
        "Supplement owner-free gate differs",
    )
    _commands(supplement)
    _records(supplement, names)
    _category(supplement)


def _journal_units(epoch: Path) -> None:
    """Check the managed recorder journal and the owned units after the stop."""
    journal = (epoch / "capture-journal-terminal.txt").read_text()
    need(
        "0 packets captured" in journal
        and "252 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == RECORDERS,
        "Managed recorder journal differs",
    )
    units = (epoch / "units-after-stop.txt").read_text()
    need(
        units.count("ActiveState=inactive") == OWNED_UNITS
        and units.count("MainPID=0") == OWNED_UNITS
        and units.count("Result=success") == OWNED_UNITS
        and "ActiveState=active" not in units
        and (epoch / "coordinator.exit").read_text().strip() == "0",
        "Owned unit/case terminal differs",
    )


def stopped(corpus: Path) -> None:
    """Gate the stopped image and its catalogues, cleanup, forks and captures."""
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    hfs, retire = (
        read(epoch / "stopped-hfs-summary.json"),
        read(epoch / "emulator-retire.json"),
    )
    _owner(epoch, hfs, retire)
    allocated = _catalogues(epoch, hfs)
    names = _marker(corpus, allocated)
    _baseline(prep, hfs)
    _cleanup(names, allocated)
    prepared = _users(prep, hfs, allocated)
    _forks(hfs, prepared)
    _board(epoch, hfs)
    _supplement(epoch, names)
    _journal_units(epoch)
