"""Files, checks and the sandbox command for ``capture_shx_session``.

Part of the capture driver's module set (``capture_shx_session.CAPTURE_MODULES``).
Nothing here touches the process, the clock or the terminal, which the driver
keeps in its own module; ``capture_shx_session`` re-exports :func:`digest`.
"""

import dataclasses as dc
import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

MAX_COMMAND_LENGTH = 4096
TRACE_CALLS = "trace=network,read,write,close,execve,exit_group"
TRACE_STRING_SIZE = "131072"

type Report = dict[str, typ.Any]


def digest(path: Path) -> str:
    """Hash a file.

    Returns
    -------
    str
        The SHA-256 of its bytes in lower-case hexadecimal.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dc.dataclass(frozen=True, slots=True)
class Sandbox:
    """What the sandbox binds and runs.

    Attributes
    ----------
    bwrap : str
        The ``bwrap`` program.
    strace : str
        The ``strace`` program.
    root : pathlib.Path
        The checkout that is bound read-write.
    output : pathlib.Path
        The capture directory, which holds ``home``, ``tmp`` and ``work``.
    binary : pathlib.Path
        The compiled peer.
    """

    bwrap: str
    strace: str
    root: Path
    output: Path
    binary: Path


@dc.dataclass(frozen=True, slots=True)
class Inputs:
    """The checked inputs of a capture.

    Attributes
    ----------
    plan : dict[str, typing.Any]
        The parsed plan.
    profile : dict[str, typing.Any]
        The parsed peer profile.
    sandbox : Sandbox
        The programs and paths of the sandbox.
    """

    plan: Report
    profile: Report
    sandbox: Sandbox


def check_steps(plan: Report) -> None:
    """Require bounded single-line commands and a successful final exit.

    Raises
    ------
    ValueError
        If a command has a control character or is too long, or the last step
        does not expect exit status zero.
    """
    for step in plan["steps"]:
        command = step["command"]
        if any(c in command for c in "\0\r\n") or len(command) > MAX_COMMAND_LENGTH:
            message = "Require bounded single-line peer commands"
            raise ValueError(message)
    if not plan["steps"] or plan["steps"][-1].get("expect_exit") != 0:
        message = "Require an explicit successful peer exit as the final step"
        raise ValueError(message)


def sandbox_command(sandbox: Sandbox, home_target: str) -> list[str]:
    """Build the argument list that runs the peer under ``strace`` in ``bwrap``.

    Parameters
    ----------
    sandbox : Sandbox
        The programs and paths.
    home_target : str
        The path at which the private home is bound.

    Returns
    -------
    list[str]
        The command, in the order its options were always given.
    """
    output = sandbox.output
    return [
        sandbox.bwrap,
        "--unshare-user",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(sandbox.root),
        str(sandbox.root),
        "--bind",
        str(output / "home"),
        home_target,
        "--bind",
        str(output / "tmp"),
        "/tmp",  # ruff: ignore[hardcoded-temp-file]  # the sandbox's own /tmp
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        str(output / "work"),
        "--",
        sandbox.strace,
        "-f",
        "-ttt",
        "-xx",
        "-yy",
        "-s",
        TRACE_STRING_SIZE,
        "-e",
        TRACE_CALLS,
        "-o",
        str(output / "syscalls.log"),
        str(sandbox.binary),
        "-q",
        "-d",
    ]


def home_file_state(guarded: Path) -> Report:
    """Describe the file in the real home directory that the capture guards.

    Returns
    -------
    dict[str, typing.Any]
        ``{"exists": False}``, or its size, modification time and hash.
    """
    if not guarded.exists():
        return {"exists": False}
    stat = guarded.stat()
    return {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": digest(guarded),
    }


def write_results(output: Path, raw: bytes, report: Report) -> None:
    """Write the raw output, the report and the checksum list.

    Parameters
    ----------
    output : pathlib.Path
        The capture directory.
    raw : bytes
        Everything the terminal printed.
    report : dict[str, typing.Any]
        The report.
    """
    (output / "stdout.bin").write_bytes(raw)
    (output / "stdout.txt").write_text(
        raw.decode("utf8", errors="backslashreplace"), encoding="utf-8"
    )
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{digest(path)}  {path.name}\n"
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "SHA256SUMS"
        ),
        encoding="utf-8",
    )
