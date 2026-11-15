from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path('/data/leynos/Projects/mothra')
P = ROOT / 'state/native-sessions/native-alias-live-preparation-01'
R = ROOT / 'state/mac-runtime/native-alias-live-01'
BASELINE = P / 'corrected/preflight.json'
OUTPUT = P / 'finf-supplement.json'
LEAF = 'm-alias54-target'
PAYLOAD = b'U54TM54X' + bytes(24)
SOURCE = ROOT / 'tools/macemu/SheepShaver/src/Unix/extfs_unix.cpp'
EXPECTED_SOURCE = '3121708131dd9398a22d1ae3f1035b4e1d99613a13cbbb1b27d9b874a024b292'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def details(s: os.stat_result) -> dict:
    return {'device': s.st_dev, 'inode': s.st_ino, 'size': s.st_size,
            'mode': oct(stat.S_IMODE(s.st_mode)), 'uid': s.st_uid,
            'gid': s.st_gid, 'nlink': s.st_nlink, 'mtime_ns': s.st_mtime_ns}


if OUTPUT.exists():
    raise RuntimeError('supplement receipt exists; refuse overwrite')
baseline_bytes = BASELINE.read_bytes()
baseline = json.loads(baseline_bytes)
if baseline['status'] != 'prepared_stopped':
    raise RuntimeError('C133 baseline is not prepared_stopped')
expected = baseline['target_leaf']
if (expected['inode'] != 3818213780 or expected['size'] != 20 or
    expected['mode'] != '0o600' or expected['uid'] != 1000 or
    expected['nlink'] != 1 or expected['sha256'] !=
    '8d1841a0106a3d6e9a4e4cee76eecd48912545fcc73d87446b05ada0800ae5a8'):
    raise RuntimeError('C133 target leaf pins differ')
if os.getuid() != 1000 or len(PAYLOAD) != 32:
    raise RuntimeError('operator UID or sidecar size differs')
if sha(SOURCE.read_bytes()) != EXPECTED_SOURCE:
    raise RuntimeError('emulator extfs source hash differs')

record = {'scope': 'C134 stopped Finder sidecar supplement only',
          'utc': dt.datetime.now(dt.UTC).isoformat(),
          'baseline_receipt': str(BASELINE.relative_to(ROOT)),
          'baseline_receipt_sha256': sha(baseline_bytes),
          'extfs_source': str(SOURCE.relative_to(ROOT)),
          'extfs_source_sha256': EXPECTED_SOURCE,
          'commands': []}
for name in ('base.dsk', 'working.dsk', 'rom'):
    path = R / name
    argv = ['sudo', '-n', 'fuser', str(path)]
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
    record['commands'].append({'argv': argv, 'exit': proc.returncode,
                               'stdout': proc.stdout.decode(errors='replace'),
                               'stderr': proc.stderr.decode(errors='replace')})
    if proc.returncode != 1 or proc.stdout or proc.stderr:
        raise RuntimeError(f'{name} has holder or fuser diagnostic')
    if path.stat().st_ino != baseline['prepared'][name]['inode']:
        raise RuntimeError(f'{name} inode changed')

shared = R / 'shared'
shared_stat = shared.lstat()
if not stat.S_ISDIR(shared_stat.st_mode) or stat.S_ISLNK(shared_stat.st_mode):
    raise RuntimeError('shared parent is not a physical directory')
if (shared_stat.st_dev != baseline['shared_parent']['dev'] or
    shared_stat.st_ino != baseline['shared_parent']['inode']):
    raise RuntimeError('shared parent identity changed')
shared_fd = os.open(shared, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    target_fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=shared_fd)
    try:
        before = os.fstat(target_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_dev != expected['dev'] or
            before.st_ino != expected['inode'] or before.st_size != 20 or
            stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != 1000 or
            before.st_nlink != 1):
            raise RuntimeError('owned target identity changed')
        target_bytes = os.read(target_fd, 21)
        if len(target_bytes) != 20 or sha(target_bytes) != expected['sha256']:
            raise RuntimeError('owned target bytes changed')
    finally:
        os.close(target_fd)
    if (shared / '.finf').exists() or (shared / '.finf').is_symlink():
        raise RuntimeError('.finf parent exists')
    if (shared / '.rsrc').exists() or (shared / '.rsrc').is_symlink():
        raise RuntimeError('.rsrc exists before sidecar staging')
    os.mkdir('.finf', 0o700, dir_fd=shared_fd)
    finf_fd = os.open('.finf', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                      dir_fd=shared_fd)
    try:
        os.fchmod(finf_fd, 0o700)
        side_fd = os.open(LEAF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=finf_fd)
        try:
            os.fchmod(side_fd, 0o600)
            if os.write(side_fd, PAYLOAD) != len(PAYLOAD):
                raise RuntimeError('short sidecar write')
            os.fsync(side_fd)
            side_stat = os.fstat(side_fd)
        finally:
            os.close(side_fd)
        os.fsync(finf_fd)
    finally:
        os.close(finf_fd)
    os.fsync(shared_fd)
finally:
    os.close(shared_fd)

after_bytes = (shared / LEAF).read_bytes()
side_path = shared / '.finf' / LEAF
side_bytes = side_path.read_bytes()
side_dir_stat = (shared / '.finf').lstat()
if (sha(after_bytes) != expected['sha256'] or len(after_bytes) != 20 or
    side_bytes != PAYLOAD or not stat.S_ISREG(side_stat.st_mode) or
    side_stat.st_nlink != 1 or side_stat.st_uid != 1000 or
    stat.S_IMODE(side_stat.st_mode) != 0o600 or
    stat.S_IMODE(side_dir_stat.st_mode) != 0o700 or
    not stat.S_ISDIR(side_dir_stat.st_mode) or (shared / '.rsrc').exists()):
    raise RuntimeError('post-stage sidecar or target check failed')
record['target_before'] = details(before) | {'sha256': sha(target_bytes)}
record['target_after'] = details((shared / LEAF).lstat()) | {'sha256': sha(after_bytes)}
record['finf_dir'] = details(side_dir_stat)
record['sidecar'] = {'path': str(side_path), **details(side_stat),
                     'sha256': sha(side_bytes), 'first_eight_hex': side_bytes[:8].hex(),
                     'trailing_24_zero': side_bytes[8:] == bytes(24),
                     'full_hex': side_bytes.hex()}
record['rsrc_absent'] = True
record['status'] = 'stopped_finf_staged'
OUTPUT.write_text(json.dumps(record, indent=2) + '\n')
