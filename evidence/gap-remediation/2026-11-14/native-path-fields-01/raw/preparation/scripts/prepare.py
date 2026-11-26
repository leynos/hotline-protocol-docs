"""Prepare the path fields runtime: copy the image, record every identity and write the evidence."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
from pathlib import Path

ROOT = Path('/data/leynos/Projects/mothra')
OUT = ROOT / 'state/native-sessions/native-path-fields-preparation-01'
SRC = ROOT / 'state/mac-runtime/native-board-02'
DEST = ROOT / 'state/mac-runtime/native-path-fields-01'
DISPLAY = ROOT / 'state/mac-displays/native-path-fields-01'
LIB = ROOT / 'tools/sleuthkit/usr/lib64'
BIN = ROOT / 'tools/sleuthkit/usr/bin'
ENV = dict(os.environ, LD_LIBRARY_PATH=str(LIB))
EXPECTED = {
    'base': 'e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910',
    'rom': '18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd',
    'exe': '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4',
    'admin': '26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3',
    'fixture-low': 'fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5',
    'Prefs': '4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196',
    'server-data': 'ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b',
    'server-rsrc': 'fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12',
}

def sha(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def meta(path: Path, with_hash=True) -> dict:
    """Return a path's inode, device, size, mode and modification time, and optionally its hash."""
    s = path.stat()
    d = {'path': str(path), 'inode': s.st_ino, 'dev': s.st_dev, 'size': s.st_size,
         'mode': oct(stat.S_IMODE(s.st_mode)), 'mtime_ns': s.st_mtime_ns}
    if with_hash:
        d['sha256'] = sha(path)
    return d

def run(label: str, argv: list[str], *, env=None, binary=False) -> subprocess.CompletedProcess:
    """Run a command, save its output and exit status and fail on an unexpected non-zero exit."""
    p = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, check=False)
    (OUT / f'{label}.stdout').write_bytes(p.stdout)
    (OUT / f'{label}.stderr').write_bytes(p.stderr)
    (OUT / f'{label}.exit').write_text(str(p.returncode) + '\n')
    commands.append({'label': label, 'argv': argv, 'exit': p.returncode,
                     'env_extra': {'LD_LIBRARY_PATH': str(LIB)} if env else {}})
    if p.returncode and label not in ('source-fuser', 'source-rom-fuser', 'working-fuser'):
        raise RuntimeError(f'{label} exit {p.returncode}')
    return p

commands = []
record = {'started_at_utc': dt.datetime.now(dt.UTC).isoformat(), 'scope': 'C122 stopped path-fields-01 preparation only'}
try:
    if DEST.exists() or DISPLAY.exists() or (ROOT / 'state/native-sessions/native-path-fields-epoch-01').exists() or Path('/tmp/.X11-unix/X120').exists():
        raise RuntimeError('Owned runtime/display or X socket already exists')
    source_base, source_rom = SRC / 'base.dsk', SRC / 'rom'
    # Root holder checks precede any source-byte read or copy.
    for label, path in (('source-fuser', source_base), ('source-rom-fuser', source_rom)):
        holder = run(label, ['sudo', '-n', 'fuser', str(path)])
        if holder.returncode != 1 or holder.stdout or holder.stderr:
            raise RuntimeError(f'{label}: immutable source has holder or fuser failed')
    source_before = {'base': meta(source_base), 'rom': meta(source_rom),
                     'exe': meta(ROOT / 'tools/macemu/SheepShaver/src/Unix/SheepShaver') if (ROOT / 'tools/macemu/SheepShaver/src/Unix/SheepShaver').exists() else None}
    if source_before['base']['sha256'] != EXPECTED['base'] or source_before['rom']['sha256'] != EXPECTED['rom'] or source_before['exe']['sha256'] != EXPECTED['exe']:
        raise RuntimeError('Immutable source hash mismatch')
    record['source_before'] = source_before
    free = shutil.disk_usage(ROOT / 'state/mac-runtime').free
    record['free_bytes_before'] = free
    if free < 2 * source_before['base']['size'] + 100_000_000:
        raise RuntimeError('Insufficient space for two owned disk copies')
    ss = run('port-ss', ['ss', '-ltn']).stdout.decode()
    record['ports_15900_15903_absent'] = all(f':{p} ' not in ss and not ss.rstrip().endswith(f':{p}') for p in range(15900, 15884))
    if not record['ports_15900_15903_absent']:
        raise RuntimeError('Future path-fields port occupied')
    for pid, tick in [(1099659, '767842'), (1012834, '2357813')]:
        raw = Path(f'/proc/{pid}/stat').read_text()
        actual = raw[raw.rfind(')') + 2:].split()[19]
        if actual != tick:
            raise RuntimeError(f'Original process {pid} changed')
    record['original_ticks'] = {'1099659': '767842', '1012834': '2357813'}
    prepare = ['python3', 'scripts/mac_runtime.py', 'prepare', str(DEST.relative_to(ROOT)),
               '--rom', str(source_rom.relative_to(ROOT)), '--disk', str(source_base.relative_to(ROOT))]
    run('prepare', prepare)
    prepared = {name: meta(DEST / name) for name in ('base.dsk', 'working.dsk', 'rom')}
    if prepared['base.dsk']['sha256'] != EXPECTED['base'] or prepared['working.dsk']['sha256'] != EXPECTED['base'] or prepared['rom']['sha256'] != EXPECTED['rom']:
        raise RuntimeError('Prepared asset hash mismatch')
    record['prepared'] = prepared
    holder = run('working-fuser', ['sudo', '-n', 'fuser', str(DEST / 'working.dsk')])
    if holder.returncode != 1 or holder.stdout or holder.stderr:
        raise RuntimeError('Stopped working disk has holder or fuser failed')
    image = str(DEST / 'working.dsk')
    full = run('catalog-full', [str(BIN / 'fls'), '-r', '-p', '-f', 'hfs', image], env=ENV).stdout.decode(errors='replace')
    allocated = run('catalog-allocated', [str(BIN / 'fls'), '-u', '-r', '-p', '-f', 'hfs', image], env=ENV).stdout.decode(errors='replace')
    lines = [line for line in allocated.splitlines() if '/Users/' in line and line.endswith('/UserData')]
    expected_users = ['-/r 11193:\tHotline19/Users/admin/UserData', '-/r 11201:\tHotline19/Users/fixture-low/UserData']
    if lines != expected_users or 'Hotline19/Banned' in allocated:
        raise RuntimeError('Allocated users or Banned state differ')
    board = [line for line in allocated.splitlines() if line.endswith('Hotline19/MessageBoard.txt')]
    if board != ['-/r 11191:\tHotline19/MessageBoard.txt']:
        raise RuntimeError('Board catalogue path differs')
    record['catalog'] = {'files_news': [line for line in allocated.splitlines() if line.endswith(('Hotline19/Files', 'Hotline19/News'))], 'full_lines': len(full.splitlines()), 'full_sha256': hashlib.sha256(full.encode()).hexdigest(),
                         'allocated_lines': len(allocated.splitlines()), 'allocated_sha256': hashlib.sha256(allocated.encode()).hexdigest(),
                         'active_users': lines, 'board': board, 'banned_absent': True}
    forks = {'admin': '11193', 'fixture-low': '11201', 'Prefs': '11202',
             'server-data': '11183-4352-0', 'server-rsrc': '11183-4353-1'}
    record['forks'] = {}
    for name, inode in forks.items():
        p = run(f'icat-{name}', [str(BIN / 'icat'), '-f', 'hfs', image, inode], env=ENV)
        got = hashlib.sha256(p.stdout).hexdigest()
        if got != EXPECTED[name]:
            raise RuntimeError(f'{name} fork hash differs')
        record['forks'][name] = {'catalog': inode, 'size': len(p.stdout), 'sha256': got}
        (OUT / f'icat-{name}.stdout').unlink()
    board_meta = run('istat-board', [str(BIN / 'istat'), '-f', 'hfs', image, '11191'], env=ENV).stdout.decode()
    if not all(term in board_meta for term in ('File Path: /Hotline19/MessageBoard.txt', 'Size:\t0', 'Resource fork size:\t0', 'File type:\t54455854  TEXT', 'File creator:\t74747874  ttxt')):
        raise RuntimeError('Board metadata differs')
    p = run('icat-board', [str(BIN / 'icat'), '-f', 'hfs', image, '11191'], env=ENV)
    if p.stdout:
        raise RuntimeError('Board data fork is not empty')
    record['board'] = {'catalog': '11191', 'data_fork_bytes': 0, 'resource_fork_bytes': 0,
                       'type': 'TEXT', 'creator': 'ttxt', 'istat_sha256': hashlib.sha256(board_meta.encode()).hexdigest()}
    record['source_after'] = {'base': meta(source_base), 'rom': meta(source_rom)}
    if record['source_after']['base'] != source_before['base'] or record['source_after']['rom'] != source_before['rom']:
        raise RuntimeError('Immutable sources changed')
    record['free_bytes_after'] = shutil.disk_usage(ROOT / 'state/mac-runtime').free
    record['status'] = 'prepared_stopped'
except Exception as e:
    record['status'] = 'failed'
    record['error'] = f'{type(e).__name__}: {e}'
    raise
finally:
    record['recorded_at_utc'] = dt.datetime.now(dt.UTC).isoformat()
    record['commands'] = commands
    (OUT / 'preflight.json').write_text(json.dumps(record, indent=2) + '\n')
