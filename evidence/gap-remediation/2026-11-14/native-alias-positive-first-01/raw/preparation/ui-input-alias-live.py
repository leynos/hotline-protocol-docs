#!/usr/bin/env python3
"""Guard one XTest action on the owned :121 Finder display."""
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/data/leynos/Projects/mothra')
O = ROOT / 'state/native-sessions/native-alias-live-01'
D = ROOT / 'state/mac-displays/native-alias-live-01'
PHASES = ('startup', 'case')
ACTIONS = ('move', 'click', 'double-click', 'down', 'up', 'escape')

def digest(path):
    """Return the SHA-256 hex digest of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()

def case_window(start, now):
    """Say whether now falls within 110 seconds after the case start."""
    start = dt.datetime.fromisoformat(start)
    return start.tzinfo is not None and start <= now < start + dt.timedelta(seconds=110)

def managed(unit, user=False):
    """Require a managed unit to be running and return its main process identifier."""
    argv = (['sudo', '-n', '-u', '#1000', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
             'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus', 'systemctl', '--user']
            if user else ['systemctl']) + [
        'show', unit, '--property=ActiveState,SubState,MainPID,Result']
    raw = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=2).stdout
    value = dict(row.split('=', 1) for row in raw.splitlines() if '=' in row)
    assert value['ActiveState'] == 'active' and value['SubState'] == 'running'
    assert value['Result'] == 'success' and int(value['MainPID']) > 0
    return int(value['MainPID'])

def gate(phase):
    """Check the deadline, display, disk readiness and emulator identity before any input."""
    deadline = dt.datetime.fromisoformat((O / 'case-deadline.utc').read_text().strip())
    assert deadline.tzinfo is not None and dt.datetime.now(dt.UTC) < deadline
    display = json.loads((D / 'display-service.json').read_text())
    assert ':121' in display['command']
    assert '1024x768x24' in display['command'] and any(Path(part).name == 'Xvfb' for part in display['command'])
    assert managed(display['unit'], user=True)
    disk = json.loads((O / 'disk-ready.json').read_text())
    assert disk['phase'] == 'disk' and disk['working_inode'] == 1815238450
    assert disk['exe_sha256'] == '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
    pid = disk['pid']
    assert pid > 0
    proc = Path(f'/proc/{pid}')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    assert int(fields[19]) == disk['start_ticks']
    inode = subprocess.run(['stat', '-Lc', '%i', str(proc / 'fd/6')],
                           capture_output=True, text=True, check=True, timeout=2).stdout.strip()
    assert int(inode) == 1815238450
    if phase == 'startup':
        assert not (O / 'case-begun.json').exists()
        return
    begun = json.loads((O / 'case-begun.json').read_text())
    assert begun['emulator_pid'] == disk['pid']
    assert case_window(begun['utc'], dt.datetime.now(dt.UTC)), 'Case UI input window expired'
    managed('mothra-native-alias-live-01-case.service')
    assert not (O / 'coordinator/report.json').exists() and not (O / 'coordinator.exit').exists()
    plan = json.loads((O / 'alias-live-plan/plan.json').read_text())
    ready = [json.loads(line) for line in (O / 'coordinator.stdout').read_text().splitlines()
             if line.startswith('{') and '"event": "READY"' in line]
    assert len(ready) == 1
    item = ready[0]
    receipt = json.loads((O / 'capture-ready.json').read_text())
    assert item['event'] == 'READY' and item['stage'] == 'awaiting-reviewed-Finder-receipt'
    assert item['plan_sha256'] == digest(O / 'alias-live-plan/plan.json')
    assert item['emulator_pid'] == disk['pid'] == receipt['emulator_pid']
    assert item['emulator_netns_inode'] == receipt['emulator_netns_inode']
    assert item['numbered_requests'] == 3 and plan['environment']['emulator_pid'] == disk['pid']

def append_log(path, event):
    """Append one JSON event to the root-owned input log and sync it."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        assert os.fstat(fd).st_uid == 0
        os.write(fd, (json.dumps(event, sort_keys=True) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    """Check the gates, send one recorded input action to the display and log it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('x', type=int, nargs='?')
    parser.add_argument('y', type=int, nargs='?')
    args = parser.parse_args()
    assert os.geteuid() == 0, 'Root is required for protected receipt and process identity'
    if args.action in ('escape', 'up'):
        assert args.x is args.y is None
        assert args.action != 'escape' or args.phase == 'startup'
    else:
        assert args.x is not None and args.y is not None
        assert 0 <= args.x < 1024 and 0 <= args.y < 768
    gate(args.phase)  # Validate all identity and phase data before XOpenDisplay.
    event = {'phase': args.phase, 'action': args.action, 'x': args.x, 'y': args.y,
             'before_utc': dt.datetime.now(dt.UTC).isoformat(), 'status': 'attempted'}
    log = O / 'operator-inputlog.jsonl'
    append_log(log, event)
    x11 = ctypes.CDLL('libX11.so.6'); xt = ctypes.CDLL('libXtst.so.6')
    ptr = ctypes.c_void_p
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]; x11.XOpenDisplay.restype = ptr
    x11.XFlush.argtypes = [ptr]; x11.XCloseDisplay.argtypes = [ptr]
    x11.XStringToKeysym.argtypes = [ctypes.c_char_p]; x11.XStringToKeysym.restype = ctypes.c_ulong
    x11.XKeysymToKeycode.argtypes = [ptr, ctypes.c_ulong]; x11.XKeysymToKeycode.restype = ctypes.c_ubyte
    xt.XTestFakeMotionEvent.argtypes = [ptr, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
    xt.XTestFakeButtonEvent.argtypes = [ptr, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    xt.XTestFakeKeyEvent.argtypes = [ptr, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
    display = x11.XOpenDisplay(b':121')
    if not display: raise RuntimeError('Owned display :121 unavailable')
    try:
        if args.action == 'escape':
            code = x11.XKeysymToKeycode(display, x11.XStringToKeysym(b'Escape'))
            assert code > 0
            xt.XTestFakeKeyEvent(display, code, 1, 0); x11.XFlush(display); time.sleep(.1)
            xt.XTestFakeKeyEvent(display, code, 0, 0); x11.XFlush(display)
        else:
            if args.action != 'up':
                xt.XTestFakeMotionEvent(display, -1, args.x, args.y, 0)
                x11.XFlush(display); time.sleep(.1)
            if args.action == 'down':
                xt.XTestFakeButtonEvent(display, 1, 1, 0); x11.XFlush(display)
            elif args.action == 'up':
                xt.XTestFakeButtonEvent(display, 1, 0, 0); x11.XFlush(display)
            for _ in range(2 if args.action == 'double-click' else 1 if args.action == 'click' else 0):
                xt.XTestFakeButtonEvent(display, 1, 1, 0); x11.XFlush(display); time.sleep(.12)
                xt.XTestFakeButtonEvent(display, 1, 0, 0); x11.XFlush(display); time.sleep(.14)
    finally:
        x11.XCloseDisplay(display)
    event['status'] = 'completed'; event['after_utc'] = dt.datetime.now(dt.UTC).isoformat()
    append_log(log, event)

if __name__ == '__main__':
    main()
