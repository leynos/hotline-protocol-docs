#!/usr/bin/env python3
"""Build one validated native capture receipt from live managed-unit facts."""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time

import capture_readiness as capture

PROPERTIES = (
    "ActiveState",
    "SubState",
    "MainPID",
    "RuntimeMaxUSec",
    "ActiveEnterTimestampMonotonic",
    "KillMode",
)
READY_KEYS = {
    "utc",
    "unit",
    "pid",
    "start_ticks",
    "netns_inode",
    "fd",
    "capture",
    "dev",
    "inode",
    "header24",
    "deadline_utc",
    "unit_properties",
}


def require(ok: bool, reason: str) -> None:
    """Raise a value error with the reason unless the condition holds."""
    if not ok:
        raise ValueError(reason)


def utc(value: str) -> dt.datetime:
    """Parse an ISO timestamp that carries an offset and return it in UTC."""
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "UTC value lacks offset")
    return result.astimezone(dt.timezone.utc)


def command(args: list[str]) -> str:
    """Run a command and return its output, failing on a non-zero exit or a timeout."""
    return subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=5
    ).stdout


def show(unit: str) -> dict[str, str]:
    """Return the properties of a managed systemd unit."""
    require(
        re.fullmatch(r"mothra-[A-Za-z0-9_.@-]+\.service", unit) is not None,
        "Unexpected managed unit",
    )
    result = capture.parse_show(
        command(
            [
                "systemctl",
                "show",
                unit,
                "--no-pager",
                "--property=" + ",".join(PROPERTIES),
            ]
        )
    )
    require(set(result) == set(PROPERTIES), "Managed unit property set differs")
    return result


def coverage(
    props: dict[str, str],
    pid: int,
    deadline: dt.datetime,
    now: dt.datetime,
    mono_us: int,
) -> None:
    """Require the managed unit to be running now with the expected properties and a runtime cap that covers the deadline."""
    require(
        set(props) == set(PROPERTIES), "Managed unit properties incomplete or extra"
    )
    require(
        props["ActiveState"] == "active"
        and props["SubState"] == "running"
        and props["KillMode"] == "control-group",
        "Managed unit not running",
    )
    require(int(props["MainPID"]) == pid and pid > 0, "Managed MainPID differs")
    require(props["RuntimeMaxUSec"] == "15min", "Managed runtime cap differs")
    entered = int(props["ActiveEnterTimestampMonotonic"])
    require(
        entered > 0
        and entered + 900_000_000 - mono_us
        >= int((deadline - now).total_seconds() * 1_000_000) + 5_000_000,
        "Managed unit does not cover deadline plus5s",
    )


def construct(
    runtime: dict,
    host: dict,
    namespace: dict,
    lease: dict,
    *,
    epoch: dt.datetime,
    deadline: dt.datetime,
    now: dt.datetime,
    mono_us: int,
    lock: pathlib.Path,
    guest_pcap: pathlib.Path,
) -> dict:
    """Pure schema/identity/deadline gate; caller supplies independently read facts."""
    require(
        runtime["fixture_profile"] == "control-only"
        and runtime["full_file_baseline"] == "not_exercised",
        "Unexpected runtime profile",
    )
    require(
        epoch <= now < deadline
        and 0 < (deadline - epoch).total_seconds() <= 720
        and (deadline - now).total_seconds() > 10,
        "Epoch bounds differ",
    )
    require(
        runtime["emulator_pid"] > 0
        and runtime["emulator_starttime"]
        and runtime["owned_working_image_inode"] > 0,
        "Runtime identity incomplete",
    )
    require(
        runtime["emulator_netns"] == f"net:[{runtime['emulator_netns_inode']}]",
        "Runtime namespace identity differs",
    )
    require(
        lock.is_absolute() and guest_pcap.is_absolute(),
        "Capture or lock path not absolute",
    )
    require(
        lease["unit"].startswith("mothra-") and lease["unit"].endswith(".service"),
        "Lease unit name differs",
    )
    require(
        lease["busy_exit"] == 1
        and lease["lock_inode"] == lock.stat().st_ino
        and lease["fd"] >= 0
        and lease["start"] > 0,
        "Lease lock proof differs",
    )
    require(lease["uid"] == "Uid:\t1000\t1000\t1000\t1000", "Lease UID differs")
    coverage(lease["unit_properties"], lease["pid"], deadline, now, mono_us)
    for label, ready in (("host", host), ("namespace", namespace)):
        require(set(ready) == READY_KEYS, f"{label} readiness schema differs")
        require(
            ready["deadline_utc"] == deadline.isoformat(), f"{label} deadline differs"
        )
        require(
            ready["unit"].startswith("mothra-") and ready["unit"].endswith(".service"),
            f"{label} unit differs",
        )
        require(
            ready["pid"] > 0 and ready["start_ticks"] > 0 and ready["fd"] >= 0,
            f"{label} process/FD differs",
        )
        require(
            bytes.fromhex(ready["header24"])[:4] in capture.PCAP_MAGIC
            and len(bytes.fromhex(ready["header24"])) == 24,
            f"{label} PCAP header differs",
        )
        coverage(ready["unit_properties"], ready["pid"], deadline, now, mono_us)
    require(
        host["netns_inode"] != runtime["emulator_netns_inode"]
        and namespace["netns_inode"] == runtime["emulator_netns_inode"],
        "Recorder namespace differs",
    )
    require(
        host["capture"] != namespace["capture"]
        and len({host["pid"], namespace["pid"], lease["pid"]}) == 3,
        "Recorder identity collision",
    )
    return {
        **runtime,
        "utc": now.isoformat(),
        "epoch_started_utc": epoch.isoformat(),
        "deadline_utc": deadline.isoformat(),
        "oracle_lock": str(lock),
        "managed_lock": lease,
        "managed_capture": {"host": host, "namespace": namespace},
        "host_pcap": host["capture"],
        "namespace_pcap": namespace["capture"],
        "guest_pcap": str(guest_pcap),
        "host_recorder_pid": host["pid"],
        "host_recorder_starttime": host["start_ticks"],
        "namespace_recorder_pid": namespace["pid"],
        "namespace_recorder_starttime": namespace["start_ticks"],
        "primary_syn_count": 0,
        "ns_routes": [],
        "runtime_mode": "control-only capture receipt",
    }


def verify_capture(
    saved: dict, filter_text: str, expected_netns: int, deadline: dt.datetime
) -> dict:
    """Verify one saved capture's unit, command line, namespace and file."""
    path = pathlib.Path(saved["capture"])
    expected = [
        "/usr/sbin/tcpdump",
        "-i",
        "lo",
        "-U",
        "-n",
        "-s",
        "0",
        "-w",
        str(path.resolve(strict=True)),
        filter_text,
    ]
    actual = capture.check(saved["unit"], path, expected, expected_netns, deadline)
    require(
        {k: v for k, v in actual.items() if k != "utc"}
        == {k: v for k, v in saved.items() if k != "utc"},
        "Capture readiness changed since recorded proof",
    )
    return saved


def lease_probe(
    unit: str, lock: pathlib.Path, deadline: dt.datetime, now: dt.datetime, mono_us: int
) -> dict:
    """Check that the lease process holds the oracle lock and return its identity."""
    props = show(unit)
    pid = int(props["MainPID"])
    coverage(props, pid, deadline, now, mono_us)
    start = capture.process_start(pid)
    require(start > 0, "Lease process start missing")
    status = pathlib.Path(f"/proc/{pid}/status").read_text()
    uid = next(line for line in status.splitlines() if line.startswith("Uid:"))
    require(uid == "Uid:\t1000\t1000\t1000\t1000", "Lease UID differs")
    argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    require(
        len(argv) == 6
        and pathlib.Path(argv[0].decode()).name == "flock"
        and argv[1:4] == [b"--exclusive", b"--nonblock", str(lock).encode()]
        and pathlib.Path(argv[4].decode()).name == "sleep"
        and argv[5] == b"900",
        "Lease command differs",
    )
    found = []
    lock_stat = lock.stat()
    for entry in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            value = entry.stat()
        except FileNotFoundError:
            continue
        if (value.st_dev, value.st_ino) == (lock_stat.st_dev, lock_stat.st_ino):
            found.append(int(entry.name))
    require(len(found) == 1, "Lease lock FD missing or ambiguous")
    busy = subprocess.run(
        ["flock", "--exclusive", "--nonblock", str(lock), "true"],
        capture_output=True,
        check=False,
        timeout=5,
    ).returncode
    require(busy == 1, "Oracle lock is not held exclusively")
    require(
        show(unit) == props and capture.process_start(pid) == start,
        "Lease changed during inspection",
    )
    return {
        "unit": unit,
        "pid": pid,
        "start": start,
        "fd": found[0],
        "lock_inode": lock_stat.st_ino,
        "busy_exit": busy,
        "uid": uid,
        "unit_properties": props,
    }


def isolated_routes(pid: int) -> None:
    """Require the isolated namespace's IPv4 and IPv6 main routing tables to be empty and only the loopback interface to exist."""
    base = ["/usr/sbin/nsenter", "-t", str(pid), "-n", "/usr/sbin/ip", "-j"]
    for family in ("-4", "-6"):
        require(
            json.loads(command([*base, family, "route", "show", "table", "main"]))
            == [],
            "Isolated namespace route appeared",
        )
    links = json.loads(command([*base, "link", "show"]))
    require(
        [item["ifname"] for item in links] == ["lo"], "Non-loopback interface appeared"
    )


def live_runtime(runtime: dict, guest_pcap: pathlib.Path) -> None:
    """Require the running emulator to match the runtime record."""
    pid = runtime["emulator_pid"]
    require(
        capture.process_start(pid) == int(runtime["emulator_starttime"]),
        "Emulator PID/start differs",
    )
    proc = pathlib.Path(f"/proc/{pid}")
    require(
        hashlib.sha256((proc / "exe").read_bytes()).hexdigest()
        == runtime["emulator_sha256"],
        "Emulator executable differs",
    )
    require(
        os.readlink(proc / "fd/6") == runtime["owned_working_image"]
        and pathlib.Path(runtime["owned_working_image"]).stat().st_ino
        == (proc / "fd/6").stat().st_ino
        == runtime["owned_working_image_inode"],
        "Working image FD/inode differs",
    )
    require(
        capture.namespace_inode(pid) == runtime["emulator_netns_inode"]
        and os.readlink(proc / "ns/net") == runtime["emulator_netns"],
        "Emulator namespace differs",
    )
    require(os.readlink(proc / "fd/16") == str(guest_pcap), "Guest capture FD differs")
    fd_stat, file_stat = (proc / "fd/16").stat(), guest_pcap.stat()
    require(
        (fd_stat.st_dev, fd_stat.st_ino) == (file_stat.st_dev, file_stat.st_ino),
        "Guest capture inode differs",
    )
    with guest_pcap.open("rb") as stream:
        header = stream.read(24)
    require(
        len(header) == 24 and header[:4] in capture.PCAP_MAGIC,
        "Guest PCAP header differs",
    )
    isolated_routes(pid)


def write_exclusive(output: pathlib.Path, value: dict) -> None:
    """Write the receipt to a new file, refusing an existing path or a symbolic link."""
    parent = output.parent
    require(
        parent.is_dir() and not parent.is_symlink(),
        "Output parent must exist without symlink",
    )
    require(not output.exists() and not output.is_symlink(), "Output already exists")
    data = (json.dumps(value, indent=2) + "\n").encode()
    owner = parent.stat()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.fchown(fd, owner.st_uid, owner.st_gid)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    except BaseException as original:
        try:
            output.unlink(missing_ok=True)
        except OSError as cleanup:
            original.add_note(f"Receipt removal also failed: {cleanup}")
        raise
    finally:
        os.close(fd)
    try:
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as original:
        try:
            output.unlink(missing_ok=True)
        except OSError as cleanup:
            original.add_note(f"Receipt removal also failed: {cleanup}")
        raise


def main() -> None:
    """Parse the command line, verify both captures and the lease and write the receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--host-ready", type=pathlib.Path, required=True)
    parser.add_argument("--namespace-ready", type=pathlib.Path, required=True)
    parser.add_argument("--host-filter", required=True)
    parser.add_argument("--namespace-filter", required=True)
    parser.add_argument("--lease-unit", required=True)
    parser.add_argument("--oracle-lock", type=pathlib.Path, required=True)
    parser.add_argument("--guest-pcap", type=pathlib.Path, required=True)
    parser.add_argument("--epoch-start", required=True)
    parser.add_argument("--deadline", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "Receipt construction requires root for /proc ownership")
    epoch, deadline = utc(args.epoch_start), utc(args.deadline)
    runtime = json.loads(args.runtime.read_text())
    host = json.loads(args.host_ready.read_text())
    namespace = json.loads(args.namespace_ready.read_text())
    require(
        args.oracle_lock.is_absolute() and args.guest_pcap.is_absolute(),
        "Lock/guest paths must be absolute",
    )
    live_runtime(runtime, args.guest_pcap)
    verify_capture(
        host, args.host_filter, capture.namespace_inode(os.getpid()), deadline
    )
    verify_capture(
        namespace, args.namespace_filter, runtime["emulator_netns_inode"], deadline
    )
    require(
        pathlib.Path(host["capture"]).stat().st_size == 24,
        "Primary SYN capture is not empty",
    )
    isolated_routes(namespace["pid"])
    now = dt.datetime.now(dt.timezone.utc)
    mono_us = time.monotonic_ns() // 1000
    lease = lease_probe(args.lease_unit, args.oracle_lock, deadline, now, mono_us)
    value = construct(
        runtime,
        host,
        namespace,
        lease,
        epoch=epoch,
        deadline=deadline,
        now=now,
        mono_us=mono_us,
        lock=args.oracle_lock,
        guest_pcap=args.guest_pcap,
    )
    # Recheck the process most likely to race after constructing the receipt.
    require(
        capture.process_start(runtime["emulator_pid"])
        == int(runtime["emulator_starttime"]),
        "Emulator changed before output",
    )
    write_exclusive(args.output, value)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "lease_pid": lease["pid"],
                "deadline_utc": value["deadline_utc"],
            }
        )
    )


if __name__ == "__main__":
    main()
