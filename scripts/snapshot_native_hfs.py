#!/usr/bin/env python3
"""Retain bounded, read-only HFS catalogue/fork observations using SleuthKit."""

import dataclasses as dc
import datetime as dt
import hashlib
import json
import os
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the fixed argv runs SleuthKit with no shell
import typing as typ
from pathlib import Path

from script_cli import run

PROBE_TIMEOUT_SECONDS = 15  # the bound on each SleuthKit invocation
MIN_CATALOG = 2  # the lowest catalogue ID that a snapshot may look up
MAX_PROBES = 4096  # the most catalogue IDs that one snapshot may look up
# (suffix of the retained fork, SleuthKit attribute of that fork)
FORKS = [("data", "4352-0"), ("rsrc", "4353-1")]


@dc.dataclass(frozen=True, slots=True)
class _Session:
    """The image, tools and retained output of one snapshot."""

    image: Path
    roots: list[str]
    output: Path
    env: dict[str, str]
    istat: Path
    icat: Path
    identities: dict[str, str]


def _require(*, condition: bool, message: str) -> None:
    """Raise a ValueError with ``message`` unless ``condition`` holds.

    Raises
    ------
    ValueError
        When the condition does not hold.
    """
    if not condition:
        raise ValueError(message)


def _check_request(image: Path, start: int, end: int, roots: list[str]) -> None:
    """Refuse an unordered or unbounded request, or a missing image."""
    _require(
        condition=MIN_CATALOG <= start <= end and end - start < MAX_PROBES,
        message="Require roots and an ordered range of at most4096 catalogue IDs",
    )
    _require(
        condition=bool(roots),
        message="Require roots and an ordered range of at most4096 catalogue IDs",
    )
    _require(condition=image.is_file(), message="Image must exist")


def _begin(image: Path, tools: Path, roots: list[str], output: Path) -> _Session:
    """Hash the tools, create the output directory and collect the session.

    Returns
    -------
    _Session
        The state that every later step of the snapshot reads.
    """
    executables = {name: tools / name for name in ["istat", "icat"]}
    identities = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in executables.items()
    }
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, LD_LIBRARY_PATH=str(tools.resolve().parent / "lib64"))
    return _Session(
        image,
        roots,
        output,
        env,
        executables["istat"],
        executables["icat"],
        identities,
    )


def _run_tool(
    executable: Path, session: _Session, target: str
) -> subprocess.CompletedProcess[bytes]:
    """Run one SleuthKit lookup of the image in the HFS mode.

    Returns
    -------
    subprocess.CompletedProcess[bytes]
        The finished process, whatever its exit status.
    """
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        [str(executable), "-f", "hfs", str(session.image), target],
        env=session.env,
        check=False,
        capture_output=True,
        timeout=PROBE_TIMEOUT_SECONDS,
    )


def _file_path(stat: str) -> str:
    """Return the file path that an ``istat`` report names, or an empty string.

    Returns
    -------
    str
        The path after the ``File Path: `` prefix.
    """
    return next(
        (
            line.removeprefix("File Path: ")
            for line in stat.splitlines()
            if line.startswith("File Path: ")
        ),
        "",
    )


def _retained(name: str, roots: list[str]) -> bool:
    """Tell whether a path is one of the requested roots or lies beneath one.

    Returns
    -------
    bool
        True when the path is a root or lies beneath one.
    """
    return any(
        name == root or name.startswith(root.rstrip("/") + "/") for root in roots
    )


def _retain_forks(session: _Session, catalog: int, key: str) -> dict[str, typ.Any]:
    """Read and retain both forks of one file, recording each exit status.

    Returns
    -------
    dict[str, typing.Any]
        The fork records, keyed by fork suffix.
    """
    attributes: dict[str, typ.Any] = {}
    for suffix, attribute in FORKS:
        fork = _run_tool(session.icat, session, f"{catalog}-{attribute}")
        (session.output / (key + "." + suffix)).write_bytes(fork.stdout)
        if fork.stderr:
            (session.output / (key + "." + suffix + ".stderr")).write_bytes(fork.stderr)
        attributes[suffix] = {
            "attribute": attribute,
            "exit_code": fork.returncode,
            "bytes": len(fork.stdout),
            "stderr": fork.stderr.decode(errors="replace"),
        }
    return attributes


def _scan_catalog(
    session: _Session, catalog: int
) -> tuple[dict[str, typ.Any], dict[str, typ.Any] | None]:
    """Probe one catalogue ID and retain it when it lies under a root.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any] | None]
        The probe record, and the retained record when the lookup succeeded
        and the path lies under a root.
    """
    result = _run_tool(session.istat, session, str(catalog))
    probe = {
        "catalog": catalog,
        "exit_code": result.returncode,
        "stderr": result.stderr.decode(errors="replace"),
    }
    if result.returncode:
        return probe, None
    stat = result.stdout.decode(errors="replace")
    name = _file_path(stat)
    if not _retained(name, session.roots):
        return probe, None
    key = f"catalog-{catalog}"
    (session.output / (key + ".stat.txt")).write_bytes(result.stdout)
    directory = "Type:\tFolder" in stat
    record: dict[str, typ.Any] = {
        "path": name,
        "key": key,
        "catalog": catalog,
        "directory": directory,
        "attributes": {},
    }
    if not directory:
        record["attributes"] = _retain_forks(session, catalog, key)
    return probe, record


def _scan(
    session: _Session, start: int, end: int
) -> tuple[list[dict[str, typ.Any]], list[dict[str, typ.Any]]]:
    """Probe every catalogue ID in the ordered range.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The probe records and the retained records, in catalogue order.
    """
    probes: list[dict[str, typ.Any]] = []
    records: list[dict[str, typ.Any]] = []
    for catalog in range(start, end + 1):
        probe, record = _scan_catalog(session, catalog)
        probes.append(probe)
        if record is not None:
            records.append(record)
    return probes, records


def _report(
    session: _Session,
    catalog_range: tuple[int, int],
    probes: list[dict[str, typ.Any]],
    records: list[dict[str, typ.Any]],
) -> dict[str, typ.Any]:
    """Assemble the extraction report of one snapshot.

    Returns
    -------
    dict[str, typing.Any]
        The report that is written as ``extraction.json``.
    """
    return {
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "image": str(session.image),
        "tool_sha256": session.identities,
        "catalog_range": [catalog_range[0], catalog_range[1]],
        "roots": session.roots,
        "method": "Read-only direct catalogue observations. Positive paths verified "
        "by istat before fork reads. Not an exhaustive directory listing, "
        "path-absence proof, protocol certification or restart-durability result.",
        "probes": probes,
        "records": records,
    }


def snapshot(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the public signature takes six arguments
    image: Path, tools: Path, start: int, end: int, roots: list[str], output: Path
) -> dict[str, typ.Any]:
    """Record positive direct lookups; failed probes never prove path absence.

    Parameters
    ----------
    image : pathlib.Path
        The disk image to read.
    tools : pathlib.Path
        The directory that holds the ``istat`` and ``icat`` executables.
    start : int
        The first catalogue ID of the range.
    end : int
        The last catalogue ID of the range.
    roots : list[str]
        The retained path roots.
    output : pathlib.Path
        The new directory that receives the retained files.

    Returns
    -------
    dict[str, typing.Any]
        The extraction report, which is also written to ``extraction.json``.
    """
    _check_request(image, start, end, roots)
    session = _begin(image, tools, roots, output)
    probes, records = _scan(session, start, end)
    report = _report(session, (start, end), probes, records)
    (output / "extraction.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def show(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the command line takes five options
    *,
    image: str,
    tsk_bin: str,
    catalog_range: tuple[int, int],
    root: list[str],
    output: str,
) -> None:
    """Retain the positive catalogue records of the requested roots.

    Parameters
    ----------
    image : str
        The disk image to read.
    tsk_bin : str
        The directory that holds the ``istat`` and ``icat`` executables.
    catalog_range : tuple[int, int]
        The first and last catalogue IDs of the range.
    root : list[str]
        A retained path root; repeat the option for each root.
    output : str
        The new directory that receives the retained files.
    """
    report = snapshot(
        Path(image),
        Path(tsk_bin),
        catalog_range[0],
        catalog_range[1],
        root,
        Path(output),
    )
    print(
        f"Retained {len(report['records'])} positive catalogue records; "
        "inspect every probe/fork status"
    )


def main() -> None:
    """Retain bounded, read-only HFS observations from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
