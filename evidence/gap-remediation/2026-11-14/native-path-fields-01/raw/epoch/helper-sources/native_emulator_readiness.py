"""Gate emulator disk identity first, then guest Ethernet capture readiness."""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import time
from typing import cast

PCAP_BYTE_ORDER = {bytes.fromhex("d4c3b2a1"): "<", bytes.fromhex("a1b2c3d4"): ">"}


class NotReady(Exception):
    """Capture exists but its header has not been flushed yet."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def utc_deadline(value: str) -> dt.datetime:
    deadline = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(deadline.tzinfo is not None, "deadline needs a UTC offset")
    return deadline.astimezone(dt.timezone.utc)


def start_ticks(pid: int) -> int:
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])


def netns_inode(pid: int) -> int:
    match = re.fullmatch(r"net:\[(\d+)\]", os.readlink(f"/proc/{pid}/ns/net"))
    require(match is not None, "invalid network namespace")
    assert match is not None
    return int(match.group(1))


def exact_file(path: pathlib.Path) -> os.stat_result:
    require(
        path.is_absolute() and not path.is_symlink(),
        "path must be absolute and not symlink",
    )
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), "path must be regular file")
    return info


def fd_identity(pid: int, number: int, path: pathlib.Path) -> tuple[int, int]:
    fd = pathlib.Path(f"/proc/{pid}/fd/{number}")
    require(os.readlink(fd) == str(path), f"FD{number} path differs")
    actual, expected = fd.stat(), exact_file(path)
    require(
        (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
        f"FD{number} inode differs",
    )
    return actual.st_dev, actual.st_ino


def candidate_pids(working: pathlib.Path) -> list[int]:
    expected = exact_file(working)
    matches = []
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            fd = proc / "fd/6"
            info = fd.stat()
            if os.readlink(fd) == str(working) and (info.st_dev, info.st_ino) == (
                expected.st_dev,
                expected.st_ino,
            ):
                matches.append(int(proc.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return matches


def exe_hash(pid: int) -> str:
    digest = hashlib.sha256()
    with pathlib.Path(f"/proc/{pid}/exe").open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def disk_snapshot(
    pid: int, working: pathlib.Path, inode: int, expected_hash: str, uid: int
) -> dict[str, object]:
    dev, actual_inode = fd_identity(pid, 6, working)
    require(actual_inode == inode, "working image inode differs")
    proc_uid = pathlib.Path(f"/proc/{pid}").stat().st_uid
    require(proc_uid == uid, "emulator UID differs")
    actual_hash = exe_hash(pid)
    require(actual_hash == expected_hash, "emulator executable hash differs")
    netns = netns_inode(pid)
    require(netns != netns_inode(os.getpid()), "emulator is in host network namespace")
    start = start_ticks(pid)
    require(start > 0, "invalid process start tick")
    return {
        "pid": pid,
        "start_ticks": start,
        "exe_sha256": actual_hash,
        "uid": proc_uid,
        "netns_inode": netns,
        "working_image": str(working),
        "working_dev": dev,
        "working_inode": actual_inode,
    }


def capture_snapshot(pid: int, guest: pathlib.Path) -> dict[str, object]:
    dev, inode = fd_identity(pid, 16, guest)
    flags_line = next(
        x
        for x in pathlib.Path(f"/proc/{pid}/fdinfo/16").read_text().splitlines()
        if x.startswith("flags:")
    )
    flags = int(flags_line.split()[1], 8)
    require(
        flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR), "capture FD is not writable"
    )
    with guest.open("rb") as stream:
        header = stream.read(24)
    if len(header) < 24:
        raise NotReady("PCAP header not yet complete")
    require(header[:4] in PCAP_BYTE_ORDER, "invalid PCAP header")
    major, minor, zone, accuracy, snaplen, linktype = struct.unpack(
        PCAP_BYTE_ORDER[header[:4]] + "HHIIII", header[4:]
    )
    require((major, minor) == (2, 4), "unexpected PCAP version")
    require(
        (zone, accuracy, snaplen, linktype) == (0, 0, 65535, 1),
        "unexpected PCAP format",
    )
    return {
        "guest_pcap": str(guest),
        "guest_dev": dev,
        "guest_inode": inode,
        "guest_fd": 16,
        "header24": header.hex(),
    }


def check(
    phase: str,
    working: pathlib.Path,
    inode: int,
    expected_hash: str,
    uid: int,
    deadline: dt.datetime,
    receipt: dict[str, object] | None = None,
    guest: pathlib.Path | None = None,
    wait_seconds: float = 30,
) -> dict[str, object]:
    require(phase in ("disk", "capture"), "invalid phase")
    require(
        len(expected_hash) == 64
        and all(c in "0123456789abcdef" for c in expected_hash),
        "invalid executable hash",
    )
    require(inode > 0 and uid >= 0, "invalid image inode or UID")
    require(working.is_absolute(), "working image needs absolute path")
    if phase == "capture":
        require(
            receipt is not None and guest is not None,
            "capture phase needs disk receipt and guest path",
        )
        assert receipt is not None and guest is not None
        require(guest.is_absolute(), "guest capture needs absolute path")
    remaining = (deadline - dt.datetime.now(dt.timezone.utc)).total_seconds()
    require(remaining > 0, "fixed UTC deadline passed")
    stop = time.monotonic() + min(wait_seconds, remaining)
    while True:
        require(
            dt.datetime.now(dt.timezone.utc) < deadline, "fixed UTC deadline passed"
        )
        matches = candidate_pids(working)
        require(len(matches) <= 1, "duplicate working image owners")
        if matches:
            current = disk_snapshot(matches[0], working, inode, expected_hash, uid)
            if phase == "disk":
                result = current
                break
            assert receipt is not None and guest is not None
            for key, value in current.items():
                require(receipt.get(key) == value, f"disk receipt {key} differs")
            require(
                receipt.get("phase") == "disk"
                and receipt.get("deadline_utc") == deadline.isoformat(),
                "disk receipt phase/deadline differs",
            )
            try:
                captured = capture_snapshot(matches[0], guest)
            except (FileNotFoundError, StopIteration, NotReady):
                pass  # No first Ethernet packet yet; continue within the fixed wait.
            else:
                result = current | captured
                break
        elif phase == "capture":
            raise ValueError("disk receipt process has exited")
        if time.monotonic() >= stop:
            raise TimeoutError(f"{phase} readiness not observed within bounded wait")
        time.sleep(min(0.1, max(0, stop - time.monotonic())))
    result_pid = cast(int, result["pid"])
    require(
        candidate_pids(working) == [result_pid],
        "process changed during readiness check",
    )
    final_disk = disk_snapshot(result_pid, working, inode, expected_hash, uid)
    require(
        all(final_disk[key] == result[key] for key in final_disk),
        "process identity changed during readiness check",
    )
    if phase == "capture":
        assert guest is not None
        require(
            capture_snapshot(result_pid, guest) == captured,
            "capture changed during readiness check",
        )
    return result | {
        "phase": phase,
        "deadline_utc": deadline.isoformat(),
        "checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def write_exclusive(path: pathlib.Path, result: dict[str, object]) -> None:
    require(
        path.is_absolute() and not path.is_symlink(),
        "output needs absolute nonsymlink path",
    )
    data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("disk", "capture"), required=True)
    parser.add_argument("--working-image", type=pathlib.Path, required=True)
    parser.add_argument("--working-inode", type=int, required=True)
    parser.add_argument("--exe-sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--deadline-utc", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--disk-receipt", type=pathlib.Path)
    parser.add_argument("--guest-pcap", type=pathlib.Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "CLI requires root for complete /proc inspection")
    require(
        args.phase == "disk" or (args.disk_receipt and args.guest_pcap),
        "capture phase requires disk receipt and guest PCAP",
    )
    require(
        args.phase == "capture"
        or (args.disk_receipt is None and args.guest_pcap is None),
        "disk phase cannot inspect capture",
    )
    receipt = json.loads(args.disk_receipt.read_text()) if args.disk_receipt else None
    result = check(
        args.phase,
        args.working_image,
        args.working_inode,
        args.exe_sha256,
        args.uid,
        utc_deadline(args.deadline_utc),
        receipt,
        args.guest_pcap,
    )
    write_exclusive(args.output, result)


if __name__ == "__main__":
    main()
