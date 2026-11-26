"""Fail closed unless a managed tcpdump still owns the expected capture file."""

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import stat
import subprocess
import time

PCAP_MAGIC = {
    bytes.fromhex(value) for value in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d")
}


def require(condition: bool, reason: str) -> None:
    """Raise a value error with the reason unless the condition holds."""
    if not condition:
        raise ValueError(reason)


def parse_show(output: str) -> dict[str, str]:
    """Parse the key=value lines of systemctl show output."""
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def duration_us(value: str) -> int:
    """Parse systemd's formatted RuntimeMaxUSec, rejecting unknown units."""
    if value.isdecimal():
        return int(value)
    match = re.fullmatch(r"(\d+)(us|ms|s|min|h)", value)
    if match is None:
        raise ValueError("invalid service runtime cap")
    scale = {
        "us": 1,
        "ms": 1_000,
        "s": 1_000_000,
        "min": 60_000_000,
        "h": 3_600_000_000,
    }
    return int(match.group(1)) * scale[match.group(2)]


def process_start(pid: int) -> int:
    # The comm field can contain spaces and parentheses; count after its last ')'.
    """Return a process's start time in clock ticks from its stat file."""
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])  # field 22, after state (field 3)


def namespace_inode(pid: int) -> int:
    """Return the inode number of a process's network namespace."""
    link = os.readlink(f"/proc/{pid}/ns/net")
    match = re.fullmatch(r"net:\[(\d+)\]", link)
    if match is None:
        raise ValueError("invalid network namespace link")
    return int(match.group(1))


def writable_capture_fd(pid: int, capture: pathlib.Path) -> int:
    """Return the descriptor on which a process holds the capture file open for writing."""
    expected = capture.stat()
    require(stat.S_ISREG(expected.st_mode), "capture is not a regular file")
    for entry in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            actual = entry.stat()
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                continue
            info = pathlib.Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text()
            flags = int(
                next(x.split()[1] for x in info.splitlines() if x.startswith("flags:")),
                8,
            )
            require(
                flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR),
                "capture FD is not writable",
            )
            return int(entry.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
    raise ValueError("tcpdump has no FD for exact capture inode")


def validate(
    show: dict[str, str],
    *,
    pid: int,
    argv: list[str],
    start_ticks: int,
    expected_argv: list[str],
    netns: int,
    expected_netns: int,
    fd: int,
    header: bytes,
    now_monotonic_us: int,
    now_utc: dt.datetime,
    deadline_utc: dt.datetime,
) -> None:
    """Require the capture unit, process, namespace, file and header to be as expected before the deadline."""
    require(show.get("ActiveState") == "active", "capture unit is not active")
    require(show.get("SubState") == "running", "capture unit is not running")
    require(int(show.get("MainPID", "0")) == pid and pid > 0, "dead or changed MainPID")
    require(argv == expected_argv, "tcpdump argv differs from pinned command")
    require(start_ticks > 0, "invalid process start tick")
    require(netns == expected_netns, "wrong network namespace")
    require(fd >= 0, "no writable capture FD")
    require(len(header) == 24 and header[:4] in PCAP_MAGIC, "invalid PCAP header")
    limit = duration_us(show.get("RuntimeMaxUSec", "0"))
    entered = int(show.get("ActiveEnterTimestampMonotonic", "0"))
    require(0 < limit <= 900_000_000, "missing or excessive service runtime cap")
    require(
        entered > 0 and entered + limit > now_monotonic_us + 10_000_000,
        "service deadline too close",
    )
    require(
        now_utc + dt.timedelta(seconds=10) < deadline_utc, "case deadline too close"
    )
    case_remaining_us = int((deadline_utc - now_utc).total_seconds() * 1_000_000)
    require(
        entered + limit - now_monotonic_us >= case_remaining_us + 5_000_000,
        "service expires before case deadline and shutdown margin",
    )


def check(
    unit: str,
    capture: pathlib.Path,
    expected_argv: list[str],
    expected_netns: int,
    deadline_utc: dt.datetime,
) -> dict[str, object]:
    """Inspect the capture unit and process and return the readiness record."""
    require(
        re.fullmatch(r"[a-zA-Z0-9_.@-]+\.service", unit) is not None,
        "invalid unit name",
    )
    require(not capture.is_symlink(), "capture path must not be a symlink")
    capture = capture.resolve(strict=True)
    command = [
        "systemctl",
        "show",
        unit,
        "--no-pager",
        "--property=ActiveState,SubState,MainPID,RuntimeMaxUSec,ActiveEnterTimestampMonotonic,KillMode",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    show = parse_show(result.stdout)
    require(
        show.get("KillMode") == "control-group", "unit does not own its process group"
    )
    pid = int(show.get("MainPID", "0"))
    require(pid > 0, "no MainPID")
    proc = pathlib.Path(f"/proc/{pid}")
    start = process_start(pid)
    argv = [
        arg.decode()
        for arg in (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    ]
    netns = namespace_inode(pid)
    fd = writable_capture_fd(pid, capture)
    header = capture.open("rb").read(24)
    now = dt.datetime.now(dt.timezone.utc)
    validate(
        show,
        pid=pid,
        argv=argv,
        start_ticks=start,
        expected_argv=expected_argv,
        netns=netns,
        expected_netns=expected_netns,
        fd=fd,
        header=header,
        now_monotonic_us=time.monotonic_ns() // 1000,
        now_utc=now,
        deadline_utc=deadline_utc,
    )
    # Recheck process identity and ownership after potentially racing reads.
    again = parse_show(
        subprocess.run(command, check=True, capture_output=True, text=True).stdout
    )
    require(
        again.get("ActiveState") == "active" and int(again.get("MainPID", "0")) == pid,
        "capture unit changed during check",
    )
    require(process_start(pid) == start, "capture PID was recycled during check")
    require(writable_capture_fd(pid, capture) == fd, "capture FD changed during check")
    return {
        "utc": now.isoformat(),
        "unit": unit,
        "pid": pid,
        "start_ticks": start,
        "netns_inode": netns,
        "fd": fd,
        "capture": str(capture),
        "dev": capture.stat().st_dev,
        "inode": capture.stat().st_ino,
        "header24": header.hex(),
        "deadline_utc": deadline_utc.isoformat(),
        "unit_properties": again,
    }


def main() -> None:
    """Parse the command line, check the capture is ready and print the record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--pcap", type=pathlib.Path, required=True)
    parser.add_argument("--netns-inode", type=int, required=True)
    parser.add_argument("--deadline-utc", required=True)
    parser.add_argument("--filter", required=True)
    args = parser.parse_args()
    deadline = dt.datetime.fromisoformat(args.deadline_utc.replace("Z", "+00:00"))
    require(deadline.tzinfo is not None, "deadline must include UTC offset")
    expected = [
        "/usr/sbin/tcpdump",
        "-i",
        "lo",
        "-U",
        "-n",
        "-s",
        "0",
        "-w",
        str(args.pcap.resolve()),
        args.filter,
    ]
    print(
        json.dumps(
            check(
                args.unit,
                args.pcap,
                expected,
                args.netns_inode,
                deadline.astimezone(dt.timezone.utc),
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
