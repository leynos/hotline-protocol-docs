"""Characterize the HFS snapshot script against fake Sleuth Kit tools.

``snapshot_native_hfs`` shells out to ``istat`` and ``icat``. The cases give it a
disk image and tools that are plain files, and replace ``subprocess.run`` by a
function that answers each catalogue lookup from a table. They record which
requests are refused and in which order, what the snapshot returns and writes, and
what the command line prints. The endings were recorded on the script as it stood
before it was brought to the standard (commit 8a3f8cd), in
``data/characterize_snapshot_hfs.tsv``.
"""

import contextlib
import dataclasses as dc
import hashlib
import io
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # stand-in results for the tools
import sys
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import pytest
import snapshot_native_hfs as snapshot_script
from characterize_support import Cases, record, replay

TABLE = Path(__file__).with_name("data") / "characterize_snapshot_hfs.tsv"
ROOT_DIRECTORY = "/Files"
LOOKUPS = {
    10: (0, b"File Path: /Files/a.txt\nType:\tFile\n", b""),
    11: (0, b"File Path: /Files/dir\nType:\tFolder\n", b""),
    12: (1, b"", b"not found"),
    13: (0, b"File Path: /Elsewhere/b.txt\nType:\tFile\n", b""),
    14: (0, b"File Path: /Files/c.txt\nType:\tFile\n", b""),
    15: (0, b"File Path: /Filesystem/d.txt\nType:\tFile\n", b""),
}
FORKS = {
    "10-4352-0": (0, b"data-a", b""),
    "10-4353-1": (0, b"rsrc-a", b""),
    "14-4352-0": (0, b"data-c", b""),
    "14-4353-1": (1, b"", b"Attribute 4353-1 not found"),
}


@dc.dataclass(frozen=True, slots=True)
class Setup:
    """One snapshot request and the state of the files it reads."""

    start: int = 10
    end: int = 15
    roots: tuple[str, ...] = (ROOT_DIRECTORY,)
    image: bool = True
    tools: bool = True
    output_exists: bool = False


def fake_run(command: list[str], **_options: object) -> subprocess.CompletedProcess:
    """Answer one ``istat`` or ``icat`` call from the tables.

    Returns
    -------
    subprocess.CompletedProcess
        The recorded answer for the lookup.
    """
    tool = Path(command[0]).name
    key = command[-1]
    code, out, err = (
        LOOKUPS.get(int(key), (1, b"", b"not found"))
        if tool == "istat"
        else FORKS.get(key, (0, b"", b""))
    )
    return subprocess.CompletedProcess(command, code, out, err)


def prepare(base: Path, setup: Setup) -> tuple[Path, Path, Path]:
    """Lay out the image, the tools and the output directory for one case.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path, pathlib.Path]
        The image, the tool directory and the output directory.
    """
    image = base / "disk.img"
    tools = base / "bin"
    tools.mkdir()
    if setup.image:
        image.write_bytes(b"image")
    if setup.tools:
        (tools / "istat").write_bytes(b"istat")
        (tools / "icat").write_bytes(b"icat")
    output = base / "out"
    if setup.output_exists:
        output.mkdir()
    return image, tools, output


def described(output: Path, report: dict[str, typ.Any] | None) -> object:
    """Describe a finished snapshot: its report and the files that it wrote.

    Returns
    -------
    object
        The report without its timestamp, and a digest of each written file.
    """
    files = {
        str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()[
            :12
        ]
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "extraction.json"
    }
    written = json.loads((output / "extraction.json").read_text())
    for item in (report, written):
        if item is not None:
            item.pop("recorded_at_utc", None)
            item["image"] = Path(item["image"]).name
    return {"report": report, "written": written, "files": files}


def taken(setup: Setup) -> object:
    """Take a snapshot with fake tools and describe the outcome.

    Returns
    -------
    object
        What ``snapshot`` returned and wrote.
    """
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        image, tools, output = prepare(base, setup)
        with mock.patch.object(snapshot_script.subprocess, "run", fake_run):
            report = snapshot_script.snapshot(
                image, tools, setup.start, setup.end, list(setup.roots), output
            )
        return described(output, report)


def command_line() -> object:
    """Run the command line with two roots and a range, and show what it printed.

    Returns
    -------
    object
        The printed text and the extraction written.
    """
    with tempfile.TemporaryDirectory() as temporary:
        image, tools, output = prepare(Path(temporary), Setup())
        argv = [
            "snapshot_native_hfs.py",
            "--image",
            str(image),
            "--tsk-bin",
            str(tools),
            "--catalog-range",
            "10",
            "13",
            "--root",
            ROOT_DIRECTORY,
            "--root",
            "/Elsewhere",
            "--output",
            str(output),
        ]
        out = io.StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(snapshot_script.subprocess, "run", fake_run),
            contextlib.redirect_stdout(out),
            contextlib.suppress(SystemExit),
        ):
            snapshot_script.main()
        return {"printed": out.getvalue(), "seen": described(output, None)}


CASES: Cases = {
    "snapshot": lambda: taken(Setup()),
    "two-roots": lambda: taken(Setup(roots=(ROOT_DIRECTORY, "/Elsewhere"))),
    "single-catalogue": lambda: taken(Setup(start=10, end=10)),
    "unordered": lambda: taken(Setup(start=15, end=10)),
    "below-two": lambda: taken(Setup(start=1, end=5)),
    "too-wide": lambda: taken(Setup(start=2, end=2 + 4096)),
    "widest": lambda: taken(Setup(start=10, end=10 + 4095)),
    "no-roots": lambda: taken(Setup(roots=())),
    "no-image": lambda: taken(Setup(image=False)),
    "no-tools": lambda: taken(Setup(tools=False)),
    "output-exists": lambda: taken(Setup(output_exists=True)),
    "unordered-and-no-roots": lambda: taken(Setup(start=15, end=10, roots=())),
    "no-roots-and-no-image": lambda: taken(Setup(roots=(), image=False)),
    "no-image-and-no-tools": lambda: taken(Setup(image=False, tools=False)),
    "no-tools-and-output-exists": lambda: taken(Setup(tools=False, output_exists=True)),
    "unordered-and-output-exists": lambda: taken(
        Setup(start=15, end=10, output_exists=True)
    ),
    "no-image-and-output-exists": lambda: taken(Setup(image=False, output_exists=True)),
    "command-line": command_line,
}


class SnapshotCharacterizationTests:
    """Keep the snapshot script as it was recorded."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each case ends with the exception or result recorded earlier."""
        now, recorded = replay(CASES, TABLE, name)
        assert now == recorded, "ending differs"


def table() -> str:
    """Say how every case ends, for the table; run it only on the earlier scripts.

    Returns
    -------
    str
        The table text.
    """
    return record(CASES)
