"""Check the terminal state of the board corpus: retired processes, the stopped image.

The terminal checks read the stopped image and the retired services, and then the
board's data, its metadata and its named forks, which must be unchanged.
"""

import typing as typ

from verify_native_board_checks import Report, need, read, sha, utc
from verify_native_board_pins import (
    BASE,
    BOARD,
    BOARD_BYTES,
    DEADLINE,
    FORKS,
    ROM,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

RECORDERS = 2  # the host and the namespace recorders, each with zero drops
BOARD_DATA_FILE = "MessageBoard.data"  # the stopped board's data fork


def check_proof(raw: Path) -> None:
    """Check the independent proof that the lab process retired without its image.

    Parameters
    ----------
    raw : pathlib.Path
        The raw directory of the corpus.
    """
    proof = read(raw / "parent-terminal-proof.json")
    need(
        proof["lab_pid_gone"]
        and proof["original_ticks_unchanged"]
        and proof["lock_free"]
        and proof["working_fd_hits"] == []
        and proof["no_working_image_bytes_read"]
        and utc(proof["recorded_at_utc"]) < utc(DEADLINE),
        "Independent retired-process or FD-free proof differs",
    )


def check_holder(raw: Path, stopped: Path) -> None:
    """Check that no process holds the stopped image, its lease or its ports.

    Parameters
    ----------
    raw : pathlib.Path
        The raw directory of the corpus.
    stopped : pathlib.Path
        The stopped image's directory.
    """
    need(
        (stopped / "fuser.exit").read_text().strip() == "1"
        and not (stopped / "fuser.stdout").read_bytes()
        and (raw / "lock-free.exit").read_text().strip() == "0"
        and "15860" not in (raw / "ports-terminal.txt").read_text()
        and "15861" not in (raw / "ports-terminal.txt").read_text()
        and "15862" not in (raw / "ports-terminal.txt").read_text()
        and "15863" not in (raw / "ports-terminal.txt").read_text(),
        "Stopped image holder, lease or ports differ",
    )


def check_units(raw: Path) -> None:
    """Check that every owned system and user service is retired.

    Parameters
    ----------
    raw : pathlib.Path
        The raw directory of the corpus.
    """
    system = (raw / "units-terminal.txt").read_text()
    user = (raw / "user-units-terminal.txt").read_text()
    need(
        all(
            f"Id={unit}\nActiveState=inactive" in system
            for unit in (
                "mothra-native-board02-c100-host.service",
                "mothra-native-board02-c100-namespace.service",
                "mothra-native-board02-c100-lease.service",
            )
        )
        and all(
            f"Id={unit}\nActiveState=inactive" in user
            for unit in (
                "mothra-sheep-8eca68cab7b1.service",
                "mothra-bridge-fd5e17ac00f6.service",
                "mothra-xbridge-fd5e17ac00f6.service",
                "mothra-display-364ae329a9c8.service",
            )
        ),
        "Owned service retirement differs",
    )


def check_journal(raw: Path) -> None:
    """Check the recorders' drop and packet counts and the managed results.

    Parameters
    ----------
    raw : pathlib.Path
        The raw directory of the corpus.
    """
    journal = (raw / "capture-journal.txt").read_text()
    need(
        journal.count("0 packets dropped by kernel") == RECORDERS
        and "0 packets captured" in journal
        and "830 packets captured" in journal,
        "Recorder zero-drop or primary quiet evidence differs",
    )
    need(
        "ExecMainStatus=0" in (raw / "units-terminal.txt").read_text()
        and "ActiveState=inactive" in (raw / "case-units-stopped.txt").read_text()
        and (raw / "postflight.exit").read_text().strip() == "0",
        "Managed case/postflight terminal result differs",
    )


def check_hashes(stopped: Path) -> None:
    """Check the hashes of the stopped base, the ROM and the quarantined image.

    Parameters
    ----------
    stopped : pathlib.Path
        The stopped image's directory.
    """
    hashes = dict(
        line.split(maxsplit=1)
        for line in (stopped / "image-sha256.txt").read_text().splitlines()
    )
    need(
        hashes[BASE] == "state/mac-runtime/native-board-02/base.dsk"
        and hashes[ROM] == "state/mac-runtime/native-board-02/rom"
        and hashes["a1b2f48093cc6dc622c5d4bcffb3c14409eedbd67af0f40f559e318b18d185b9"]
        == "state/mac-runtime/native-board-02/working.dsk",
        "Stopped base, ROM or quarantined working image hash differs",
    )


def check_board(stopped: Path, report: Report) -> None:
    """Check the stopped board's data against the segments that the case recorded.

    Parameters
    ----------
    stopped : pathlib.Path
        The stopped image's directory.
    report : dict[str, typing.Any]
        The finite board case's report, which records the segments.
    """
    board = (stopped / BOARD_DATA_FILE).read_bytes()
    expected = b"".join(
        bytes.fromhex(value) for value in reversed(report["segments_hex"])
    )
    need(
        len(board) == BOARD_BYTES
        and board == expected
        and sha(stopped / BOARD_DATA_FILE) == BOARD
        and (stopped / "MessageBoard.rsrc").stat().st_size == 0,
        "Stopped board DATA bytes or resource fork differ",
    )


def check_metadata(stopped: Path) -> None:
    """Check the stopped board's HFS path, its Finder metadata and its active users.

    Parameters
    ----------
    stopped : pathlib.Path
        The stopped image's directory.
    """
    meta = (stopped / "board-istat.txt").read_text()
    catalog = (stopped / "catalog-allocated.txt").read_text()
    need(
        "File Path: /Hotline19/MessageBoard.txt" in meta
        and "Size:\t65629" in meta
        and "Resource fork size:\t0" in meta
        and "File type:\t54455854  TEXT" in meta
        and "File creator:\t74747874  ttxt" in meta
        and "-/r 11191:\tHotline19/MessageBoard.txt" in catalog
        and catalog.count("/Users/admin/UserData") == 1
        and catalog.count("/Users/fixture-low/UserData") == 1,
        "Stopped board HFS path, Finder metadata or active users differ",
    )


def check_forks(corpus: Path, stopped: Path) -> None:
    """Check that each named fork of the stopped image is unchanged.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory, which holds the preflight record.
    stopped : pathlib.Path
        The stopped image's directory.
    """
    prep = read(corpus / "preparation/preflight.json")
    for name, digest in FORKS.items():
        need(
            prep["forks"][name]["sha256"] == digest
            and dict(
                line.split(maxsplit=1)
                for line in (stopped / "fork-sha256.txt").read_text().splitlines()
            )
            .get(digest, "")
            .endswith(f"/{name}.bin"),
            f"Unchanged stopped named fork differs: {name}",
        )


def terminal(corpus: Path, report: Report) -> None:
    """Check the terminal state of the corpus, in the order that it is recorded.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The finite board case's report.
    """
    raw = corpus / "raw"
    stopped = raw / "stopped"
    check_proof(raw)
    check_holder(raw, stopped)
    check_units(raw)
    check_journal(raw)
    check_hashes(stopped)
    check_board(stopped, report)
    check_metadata(stopped)
    check_forks(corpus, stopped)
