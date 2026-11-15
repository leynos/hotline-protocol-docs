#!/usr/bin/env python3
"""Guard one XTest action on the owned :123 Finder display."""

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path("/data/leynos/Projects/mothra")
O = ROOT / "state/native-sessions/native-alias-live-02"
D = ROOT / "state/mac-displays/native-alias-live-02"
PHASES = ("identity", "startup", "case", "retire")
ACTIONS = ("capture", "move", "click", "double-click", "down", "up", "escape")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case_window(start, now):
    start = dt.datetime.fromisoformat(start)
    return start.tzinfo is not None and start <= now < start + dt.timedelta(seconds=110)


def managed(unit, user=False):
    argv = (
        [
            "sudo",
            "-n",
            "-u",
            "#1000",
            "env",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "systemctl",
            "--user",
        ]
        if user
        else ["systemctl"]
    ) + ["show", unit, "--property=ActiveState,SubState,MainPID,Result"]
    raw = subprocess.run(
        argv, capture_output=True, text=True, check=True, timeout=2
    ).stdout
    value = dict(row.split("=", 1) for row in raw.splitlines() if "=" in row)
    assert value["ActiveState"] == "active" and value["SubState"] == "running"
    assert value["Result"] == "success" and int(value["MainPID"]) > 0
    return int(value["MainPID"])


def display_identity():
    display = json.loads((D / "display-service.json").read_text())
    argv = display["command"][display["command"].index("--") + 1 :]
    assert argv == [
        "/usr/sbin/Xvfb",
        ":123",
        "-screen",
        "0",
        "1024x768x24",
        "-nolisten",
        "tcp",
        "-ac",
        "-noreset",
    ]
    pid = managed(display["unit"], user=True)
    proc = Path(f"/proc/{pid}")
    assert proc.stat().st_uid == 1000
    assert (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0") == [
        part.encode() for part in argv
    ]
    raw = (proc / "stat").read_text()
    return {
        "unit": display["unit"],
        "pid": pid,
        "start_ticks": int(raw[raw.rfind(")") + 2 :].split()[19]),
        "exe": os.readlink(proc / "exe"),
        "exe_sha256": digest(proc / "exe"),
        "uid": 1000,
        "display": ":123",
        "command": argv,
    }


def gate(phase):
    deadline = dt.datetime.fromisoformat((O / "case-deadline.utc").read_text().strip())
    assert deadline.tzinfo is not None and dt.datetime.now(dt.UTC) < deadline
    assert json.loads((O / "display-identity.json").read_text()) == display_identity()
    disk = json.loads((O / "disk-ready.json").read_text())
    expected_inode = json.loads(
        (
            ROOT
            / "state/native-sessions/native-alias-live-preparation-02/stopped-preparation/preflight.json"
        ).read_text()
    )["prepared"]["working.dsk"]["inode"]
    assert disk["phase"] == "disk" and disk["working_inode"] == expected_inode
    assert (
        disk["exe_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
    )
    assert disk["uid"] == 1000
    pid = disk["pid"]
    assert pid > 0
    proc = Path(f"/proc/{pid}")
    fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    assert int(fields[19]) == disk["start_ticks"]
    assert proc.stat().st_uid == 1000
    assert digest(proc / "exe") == disk["exe_sha256"]
    assert (proc / "ns/net").stat().st_ino == disk["netns_inode"]
    if phase != "startup" or (O / "guest-capture-ready.json").exists():
        capture = json.loads((O / "guest-capture-ready.json").read_text())
        assert all(
            capture[key] == disk[key]
            for key in (
                "pid",
                "start_ticks",
                "exe_sha256",
                "uid",
                "netns_inode",
                "working_inode",
            )
        )
        guest = Path(capture["guest_pcap"])
        fd = proc / "fd/16"
        assert os.readlink(fd) == str(guest)
        assert (
            (fd.stat().st_dev, fd.stat().st_ino)
            == (capture["guest_dev"], capture["guest_inode"])
            == (guest.stat().st_dev, guest.stat().st_ino)
        )
    inode = subprocess.run(
        ["stat", "-Lc", "%i", str(proc / "fd/6")],
        capture_output=True,
        text=True,
        check=True,
        timeout=2,
    ).stdout.strip()
    assert int(inode) == expected_inode
    if phase == "startup":
        assert not (O / "case-begun.json").exists()
        return
    if phase == "retire":
        return
    begun = json.loads((O / "case-begun.json").read_text())
    assert begun["emulator_pid"] == disk["pid"]
    assert case_window(begun["utc"], dt.datetime.now(dt.UTC)), (
        "Case UI input window expired"
    )
    managed("mothra-native-alias-live-02-case.service")
    assert (
        not (O / "coordinator/report.json").exists()
        and not (O / "coordinator.exit").exists()
    )
    plan = json.loads((O / "alias-live-plan/plan.json").read_text())
    ready = [
        json.loads(line)
        for line in (O / "coordinator.stdout").read_text().splitlines()
        if line.startswith("{") and '"event": "READY"' in line
    ]
    assert len(ready) == 1
    item = ready[0]
    receipt = json.loads((O / "capture-ready.json").read_text())
    assert (
        item["event"] == "READY" and item["stage"] == "awaiting-reviewed-Finder-receipt"
    )
    assert item["plan_sha256"] == digest(O / "alias-live-plan/plan.json")
    assert item["emulator_pid"] == disk["pid"] == receipt["emulator_pid"]
    assert item["emulator_netns_inode"] == receipt["emulator_netns_inode"]
    assert (
        item["numbered_requests"] == 3
        and plan["environment"]["emulator_pid"] == disk["pid"]
    )


def append_log(path, event):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        assert os.fstat(fd).st_uid == 0
        os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("x", type=int, nargs="?")
    parser.add_argument("y", type=int, nargs="?")
    args = parser.parse_args()
    assert os.geteuid() == 0, (
        "Root is required for protected receipt and process identity"
    )
    if args.phase == "identity":
        assert args.action == "capture" and args.x is args.y is None
        assert not (O / "case-begun.json").exists()
        deadline = dt.datetime.fromisoformat(
            (O / "case-deadline.utc").read_text().strip()
        )
        assert deadline.tzinfo is not None and dt.datetime.now(dt.UTC) < deadline
        with (O / "display-identity.json").open("x") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(display_identity(), output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        return
    assert args.action != "capture"
    if args.phase == "retire":
        assert args.action == "click" and args.x is not None and args.y is not None
        assert 0 <= args.x < 1024 and 0 <= args.y < 768
    elif args.action in ("escape", "up"):
        assert args.x is args.y is None
        assert args.action != "escape" or args.phase == "startup"
    else:
        assert args.x is not None and args.y is not None
        assert 0 <= args.x < 1024 and 0 <= args.y < 768
    gate(args.phase)  # Validate all identity and phase data before XOpenDisplay.
    if args.phase == "retire":
        reviewed_path = O / "retire-approved.json"
        reviewed = json.loads(reviewed_path.read_text())
        assert (
            reviewed_path.stat().st_uid == 0
            and reviewed_path.stat().st_mode & 0o077 == 0
        )
        disk = json.loads((O / "disk-ready.json").read_text())
        assert reviewed["emulator_pid"] == disk["pid"]
        assert reviewed["emulator_starttime"] == disk["start_ticks"]
        assert reviewed["display"] == ":123"
        assert reviewed["deadline_utc"] == (O / "case-deadline.utc").read_text().strip()
        terminal = (O / "coordinator.exit").exists()
        abort_path = O / "precase-abort.json"
        if not terminal:
            abort = json.loads(abort_path.read_text())
            assert (
                abort_path.stat().st_uid == 0 and abort_path.stat().st_mode & 0o077 == 0
            )
            assert (
                abort["status"] == "precase_abort"
                and abort["emulator_pid"] == disk["pid"]
            )
            assert not (O / "case-begun.json").exists()
        controls = reviewed["controls"]
        assert 1 <= len(controls) <= 2
        assert [item["label"] for item in controls] in (["Quit"], ["Quit", "Quit Now"])
        past = (
            [
                json.loads(line)
                for line in (O / "operator-inputlog.jsonl").read_text().splitlines()
            ]
            if (O / "operator-inputlog.jsonl").exists()
            else []
        )
        attempted = [
            item
            for item in past
            if item["phase"] == "retire" and item["status"] == "attempted"
        ]
        completed = [
            item
            for item in past
            if item["phase"] == "retire" and item["status"] == "completed"
        ]
        assert len(attempted) == len(completed) < len(controls)
        wanted = controls[len(attempted)]
        assert (args.x, args.y) == (wanted["x"], wanted["y"])
        shot = O / "retire/screens" / wanted["screenshot"]
        assert shot.name == wanted["screenshot"] and digest(shot) == wanted["sha256"]
        reviewed_utc = dt.datetime.fromisoformat(reviewed["reviewed_utc"])
        assert reviewed_utc.tzinfo is not None and dt.timedelta(0) <= dt.datetime.now(
            dt.UTC
        ) - reviewed_utc < dt.timedelta(seconds=60)
    event = {
        "phase": args.phase,
        "action": args.action,
        "x": args.x,
        "y": args.y,
        "before_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "attempted",
    }
    log = O / "operator-inputlog.jsonl"
    append_log(log, event)
    x11 = ctypes.CDLL("libX11.so.6")
    xt = ctypes.CDLL("libXtst.so.6")
    ptr = ctypes.c_void_p
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x11.XOpenDisplay.restype = ptr
    x11.XFlush.argtypes = [ptr]
    x11.XCloseDisplay.argtypes = [ptr]
    x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
    x11.XStringToKeysym.restype = ctypes.c_ulong
    x11.XKeysymToKeycode.argtypes = [ptr, ctypes.c_ulong]
    x11.XKeysymToKeycode.restype = ctypes.c_ubyte
    xt.XTestFakeMotionEvent.argtypes = [
        ptr,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xt.XTestFakeButtonEvent.argtypes = [
        ptr,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xt.XTestFakeKeyEvent.argtypes = [ptr, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    display = x11.XOpenDisplay(b":123")
    if not display:
        raise RuntimeError("Owned display :123 unavailable")
    try:
        if args.action == "escape":
            code = x11.XKeysymToKeycode(display, x11.XStringToKeysym(b"Escape"))
            assert code > 0
            xt.XTestFakeKeyEvent(display, code, 1, 0)
            x11.XFlush(display)
            time.sleep(0.1)
            xt.XTestFakeKeyEvent(display, code, 0, 0)
            x11.XFlush(display)
        else:
            if args.action != "up":
                xt.XTestFakeMotionEvent(display, -1, args.x, args.y, 0)
                x11.XFlush(display)
                time.sleep(0.1)
            if args.action == "down":
                xt.XTestFakeButtonEvent(display, 1, 1, 0)
                x11.XFlush(display)
            elif args.action == "up":
                xt.XTestFakeButtonEvent(display, 1, 0, 0)
                x11.XFlush(display)
            for _ in range(
                2
                if args.action == "double-click"
                else 1
                if args.action == "click"
                else 0
            ):
                xt.XTestFakeButtonEvent(display, 1, 1, 0)
                x11.XFlush(display)
                time.sleep(0.12)
                xt.XTestFakeButtonEvent(display, 1, 0, 0)
                x11.XFlush(display)
                time.sleep(0.14)
    finally:
        x11.XCloseDisplay(display)
    event["status"] = "completed"
    event["after_utc"] = dt.datetime.now(dt.UTC).isoformat()
    append_log(log, event)


if __name__ == "__main__":
    main()
