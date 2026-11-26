#!/usr/bin/env python3
"""Bound actual owned emulator PID, FD6, FD16 and namespace discovery."""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import time

ROOT = pathlib.Path('/data/leynos/Projects/mothra')
WORKING = ROOT / 'state/mac-runtime/native-rate304-02/working.dsk'
GUEST = ROOT / 'state/native-sessions/native-rate304-epoch-02/lab-guest.pcap'
EXE_SHA = '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'


def identity(pid: int) -> dict | None:
    """Return the identity of a process if it is the owned emulator, or none if it is not."""
    proc = pathlib.Path(f'/proc/{pid}')
    try:
        if os.readlink(proc / 'fd/6') != str(WORKING):
            return None
        if os.readlink(proc / 'fd/16') != str(GUEST):
            return None
        if proc.stat().st_uid != 1000:
            raise ValueError('Owned emulator UID differs')
        image = WORKING.stat()
        fd6 = (proc / 'fd/6').stat()
        if (fd6.st_dev, fd6.st_ino) != (image.st_dev, image.st_ino):
            raise ValueError('Owned working FD6 inode differs')
        exe = proc / 'exe'
        with exe.open('rb') as source:
            exe_sha = hashlib.file_digest(source, 'sha256').hexdigest()
        if exe_sha != EXE_SHA:
            raise ValueError('Emulator executable SHA differs')
        with GUEST.open('rb') as source:
            header = source.read(24)
        if len(header) != 24 or header[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            return None
        raw = (proc / 'stat').read_text()
        tick = raw[raw.rfind(')') + 2:].split()[19]
        return {'pid': pid, 'starttime': tick, 'exe': os.readlink(exe),
                'exe_sha256': exe_sha, 'uid': 1000, 'working_inode': image.st_ino,
                'guest_pcap_inode': GUEST.stat().st_ino,
                'netns_inode': (proc / 'ns/net').stat().st_ino,
                'guest_header24': header.hex()}
    except FileNotFoundError:
        return None
    except PermissionError as exc:
        raise ValueError('Root /proc access required') from exc
    except OSError:
        # A process can exit between proc enumeration and FD inspection.
        return None


def main() -> None:
    """Wait briefly for the owned emulator to appear before the deadline and write its identity."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--deadline', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.output.exists():
        raise ValueError('Root and new output path required')
    deadline = dt.datetime.fromisoformat(args.deadline)
    if deadline.tzinfo is None:
        raise ValueError('UTC deadline required')
    end = time.monotonic() + 5
    while time.monotonic() < end and dt.datetime.now(dt.UTC) < deadline:
        matches = []
        for proc in pathlib.Path('/proc').iterdir():
            if proc.name.isdigit():
                found = identity(int(proc.name))
                if found is not None:
                    matches.append(found)
        if len(matches) > 1:
            raise ValueError('Ambiguous owned emulator PIDs')
        if matches:
            result = {'status': 'actual_emulator_ready', 'utc': dt.datetime.now(dt.UTC).isoformat(),
                      'deadline_utc': deadline.isoformat(), **matches[0]}
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result))
            return
        time.sleep(0.05)
    raise TimeoutError('Owned emulator FD6/FD16/header not ready within five seconds')


if __name__ == '__main__':
    main()
