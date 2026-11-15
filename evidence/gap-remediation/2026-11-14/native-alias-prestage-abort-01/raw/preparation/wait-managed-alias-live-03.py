#!/usr/bin/env python3
"""Bound a first-start wait before any capture readiness invocation."""

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import time


def show(unit: str) -> dict[str, str]:
    raw = subprocess.run(
        [
            "systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=ActiveState,SubState,MainPID,Result",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=1,
    ).stdout
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def matching_fd(pid: int, target: pathlib.Path) -> int | None:
    ref = target.stat()
    for entry in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            value = entry.stat()
        except (OSError, PermissionError):
            continue
        if (value.st_dev, value.st_ino) == (ref.st_dev, ref.st_ino):
            return int(entry.name)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--deadline", required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--pcap", type=pathlib.Path)
    choice.add_argument("--lock", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.output.exists():
        raise ValueError("Root and new output path required")
    deadline = dt.datetime.fromisoformat(args.deadline)
    if deadline.tzinfo is None:
        raise ValueError("Epoch deadline lacks UTC offset")
    started = time.monotonic()
    latest = started + 5
    observed_active = False
    while True:
        if dt.datetime.now(dt.UTC) >= deadline or time.monotonic() >= latest:
            raise TimeoutError("Unit PID/FD/header not ready within five seconds")
        props = show(args.unit)
        state, substate = props["ActiveState"], props["SubState"]
        pid = int(props["MainPID"])
        if state == "failed" or props["Result"] not in ("success", ""):
            raise RuntimeError("Managed unit terminal failure")
        if observed_active and (state != "active" or pid == 0):
            raise RuntimeError("Managed unit exited during first-start wait")
        if state == "active" and substate == "running" and pid > 0:
            observed_active = True
            path = args.pcap or args.lock
            assert path is not None
            if path.exists():
                fd = matching_fd(pid, path)
                if fd is not None:
                    header = None
                    if args.pcap is not None:
                        with path.open("rb") as stream:
                            raw = stream.read(24)
                        if len(raw) != 24 or raw[:4] not in (
                            b"\xd4\xc3\xb2\xa1",
                            b"\xa1\xb2\xc3\xd4",
                        ):
                            time.sleep(0.05)
                            continue
                        header = raw.hex()
                    result = {
                        "unit": args.unit,
                        "pid": pid,
                        "fd": fd,
                        "inode": path.stat().st_ino,
                        "header24": header,
                        "wait_seconds": time.monotonic() - started,
                        "deadline_utc": deadline.isoformat(),
                    }
                    args.output.write_text(json.dumps(result, indent=2) + "\n")
                    print(json.dumps(result))
                    return
        time.sleep(0.05)


if __name__ == "__main__":
    main()
