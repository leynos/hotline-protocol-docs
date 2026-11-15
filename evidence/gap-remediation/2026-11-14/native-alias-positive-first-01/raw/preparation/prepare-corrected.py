from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path('/data/leynos/Projects/mothra')
OUT = ROOT / 'state/native-sessions/native-alias-live-preparation-01/corrected'
SOURCE = ROOT / 'state/mac-runtime/native-board-02'
DEST = ROOT / 'state/mac-runtime/native-alias-live-01'
DISPLAY = ROOT / 'state/mac-displays/native-alias-live-01'
EPOCH = ROOT / 'state/native-sessions/native-alias-live-01'
TSK = ROOT / 'tools/sleuthkit/usr/bin'
ENV = dict(os.environ, LD_LIBRARY_PATH=str(ROOT / 'tools/sleuthkit/usr/lib64'))
SHA = {
    'base': 'e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910',
    'rom': '18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd',
    'exe': '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4',
    'admin': '26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3',
    'fixture-low': 'fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5',
    'Prefs': '4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196',
    'server-data': 'ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b',
    'server-rsrc': 'fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12',
}
LEAF_NAME = 'm-alias54-target'
LEAF_DATA = b'alias54-live-target\n'
commands = []
record = {'scope': 'C133 stopped alias-live preparation only', 'started_utc': dt.datetime.now(dt.UTC).isoformat()}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def meta(path: Path, *, hash_bytes: bool = True) -> dict:
    s = path.stat()
    answer = {'path': str(path), 'dev': s.st_dev, 'inode': s.st_ino,
              'size': s.st_size, 'mode': oct(stat.S_IMODE(s.st_mode)),
              'mtime_ns': s.st_mtime_ns, 'uid': s.st_uid, 'gid': s.st_gid}
    if hash_bytes:
        with path.open('rb') as stream:
            answer['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return answer


def run(name: str, argv: list[str], *, env=None, expected: int = 0) -> bytes:
    proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, check=False)
    (OUT / f'{name}.stdout').write_bytes(proc.stdout)
    (OUT / f'{name}.stderr').write_bytes(proc.stderr)
    (OUT / f'{name}.exit').write_text(f'{proc.returncode}\n')
    commands.append({'label': name, 'argv': argv, 'exit': proc.returncode,
                     'env_extra': {'LD_LIBRARY_PATH': ENV['LD_LIBRARY_PATH']} if env else {}})
    if proc.returncode != expected:
        raise RuntimeError(f'{name}: exit {proc.returncode}, expected {expected}')
    return proc.stdout


def tick(pid: int) -> str:
    raw = Path(f'/proc/{pid}/stat').read_text()
    return raw[raw.rfind(')') + 2:].split()[19]


try:
    if DEST.exists() or DISPLAY.exists() or EPOCH.exists() or Path('/tmp/.X11-unix/X121').exists():
        raise RuntimeError('new runtime/display/epoch or display socket exists')
    source_base, source_rom = SOURCE / 'base.dsk', SOURCE / 'rom'
    # These holder checks MUST precede source-byte hashes and mac_runtime copy.
    for label, path in (('source-base-fuser', source_base), ('source-rom-fuser', source_rom)):
        got = run(label, ['sudo', '-n', 'fuser', str(path)], expected=1)
        if got or (OUT / f'{label}.stderr').read_bytes():
            raise RuntimeError(f'{label}: holder or fuser diagnostic')
    record['original_ticks_before'] = {str(pid): tick(pid) for pid in (1099659, 1012834)}
    if record['original_ticks_before'] != {'1099659': '767842', '1012834': '2357813'}:
        raise RuntimeError('original runtime identity changed')
    source = {'base': meta(source_base), 'rom': meta(source_rom),
              'exe': meta(ROOT / 'tools/macemu/SheepShaver/src/Unix/SheepShaver')}
    if any(source[name]['sha256'] != SHA[name] for name in ('base', 'rom', 'exe')):
        raise RuntimeError('source identity mismatch')
    if source['base']['mode'] != '0o444' or source['rom']['mode'] != '0o644':
        raise RuntimeError('source base/ROM modes differ from accepted 0444/0644')
    record['source_before'] = source
    free = shutil.disk_usage(ROOT / 'state/mac-runtime').free
    record['free_bytes_before'] = free
    if free < 2 * source['base']['size'] + 100_000_000:
        raise RuntimeError('insufficient free bytes')
    ss = run('listeners-before', ['ss', '-ltn']).decode()
    ports = [15920, 15921, 15922, 15923]
    record['proposed_ports'] = ports
    record['proposed_ports_absent'] = all(f':{port} ' not in ss and not ss.rstrip().endswith(f':{port}') for port in ports)
    if not record['proposed_ports_absent']:
        raise RuntimeError('proposed frontend port occupied')
    # Recheck both sources before the copy's second byte-read phase.
    for label, path in (('before-copy-base-fuser', source_base), ('before-copy-rom-fuser', source_rom)):
        got = run(label, ['sudo', '-n', 'fuser', str(path)], expected=1)
        if got or (OUT / f'{label}.stderr').read_bytes():
            raise RuntimeError(f'{label}: holder or fuser diagnostic')
    run('prepare', ['python3', 'scripts/mac_runtime.py', 'prepare', str(DEST.relative_to(ROOT)),
                    '--rom', str(source_rom.relative_to(ROOT)), '--disk', str(source_base.relative_to(ROOT))])
    for name in ('base.dsk', 'working.dsk', 'rom'):
        label = f'prepared-{name}-fuser'
        got = run(label, ['sudo', '-n', 'fuser', str(DEST / name)], expected=1)
        if got or (OUT / f'{label}.stderr').read_bytes():
            raise RuntimeError(f'{label}: holder or fuser diagnostic')
    prepared = {name: meta(DEST / name) for name in ('base.dsk', 'working.dsk', 'rom')}
    if (prepared['base.dsk']['sha256'] != SHA['base'] or
        prepared['working.dsk']['sha256'] != SHA['base'] or
        prepared['rom']['sha256'] != SHA['rom']):
        raise RuntimeError('prepared copy hash mismatch')
    if len({item['inode'] for item in prepared.values()}) != 3:
        raise RuntimeError('prepared assets share inode')
    record['prepared'] = prepared
    got = run('working-fuser', ['sudo', '-n', 'fuser', str(DEST / 'working.dsk')], expected=1)
    if got or (OUT / 'working-fuser.stderr').read_bytes():
        raise RuntimeError('prepared working image has holder')
    image = str(DEST / 'working.dsk')
    full = run('catalog-full', [str(TSK / 'fls'), '-r', '-p', '-f', 'hfs', image], env=ENV).decode(errors='replace')
    allocated = run('catalog-allocated', [str(TSK / 'fls'), '-u', '-r', '-p', '-f', 'hfs', image], env=ENV).decode(errors='replace')
    users = [line for line in allocated.splitlines() if '/Users/' in line and line.endswith('/UserData')]
    if users != ['-/r 11193:\tHotline19/Users/admin/UserData',
                 '-/r 11201:\tHotline19/Users/fixture-low/UserData']:
        raise RuntimeError('active user catalogue differs')
    if 'Hotline19/Banned' in allocated or LEAF_NAME in allocated:
        raise RuntimeError('Banned or target-name baseline conflict')
    files_news = [line for line in allocated.splitlines() if line.endswith(('Hotline19/Files', 'Hotline19/News'))]
    if len(files_news) != 2:
        raise RuntimeError('Files/News catalog mismatch')
    record['catalog'] = {'full_lines': len(full.splitlines()), 'full_sha256': digest(full.encode()),
                         'allocated_lines': len(allocated.splitlines()), 'allocated_sha256': digest(allocated.encode()),
                         'active_users': users, 'files_news': files_news, 'banned_absent': True}
    forks = {'admin': '11193', 'fixture-low': '11201', 'Prefs': '11202',
             'server-data': '11183-4352-0', 'server-rsrc': '11183-4353-1'}
    record['forks'] = {}
    for name, inode in forks.items():
        blob = run(f'icat-{name}', [str(TSK / 'icat'), '-f', 'hfs', image, inode], env=ENV)
        got = digest(blob)
        if got != SHA[name]:
            raise RuntimeError(f'{name} fork mismatch')
        record['forks'][name] = {'catalog': inode, 'size': len(blob), 'sha256': got}
    board_meta = run('istat-board', [str(TSK / 'istat'), '-f', 'hfs', image, '11191'], env=ENV).decode()
    board_data = run('icat-board', [str(TSK / 'icat'), '-f', 'hfs', image, '11191'], env=ENV)
    if board_data or not all(term in board_meta for term in (
        'File Path: /Hotline19/MessageBoard.txt', 'Size:\t0', 'Resource fork size:\t0',
        'File type:\t54455854  TEXT', 'File creator:\t74747874  ttxt')):
        raise RuntimeError('empty board baseline differs')
    record['board'] = {'catalog': 11191, 'data_size': 0, 'resource_size': 0,
                       'finder_type': 'TEXT', 'finder_creator': 'ttxt'}
    shared = DEST / 'shared'
    if not shared.is_dir() or list(shared.iterdir()):
        raise RuntimeError('shared directory missing or not empty')
    if os.getuid() != 1000 or len(LEAF_DATA) != 20:
        raise RuntimeError('UID or target payload length differs')
    leaf = shared / LEAF_NAME
    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, LEAF_DATA) != len(LEAF_DATA):
            raise RuntimeError('short target write')
        os.fsync(fd)
    finally:
        os.close(fd)
    leaf_stat = leaf.lstat()
    if (not stat.S_ISREG(leaf_stat.st_mode) or leaf_stat.st_nlink != 1 or
        stat.S_IMODE(leaf_stat.st_mode) != 0o600 or leaf_stat.st_uid != 1000):
        raise RuntimeError('owned target leaf attributes differ')
    record['shared_parent'] = meta(shared, hash_bytes=False)
    record['target_leaf'] = meta(leaf)
    record['target_leaf']['nlink'] = leaf_stat.st_nlink
    if record['target_leaf']['sha256'] != digest(LEAF_DATA):
        raise RuntimeError('target leaf hash differs')
    record['sidecars_absent'] = not (shared / '.finf').exists() and not (shared / '.rsrc').exists()
    if not record['sidecars_absent']:
        raise RuntimeError('unexpected sidecar directory before Finder')
    for label, path in (('source-after-base-fuser', source_base), ('source-after-rom-fuser', source_rom)):
        got = run(label, ['sudo', '-n', 'fuser', str(path)], expected=1)
        if got or (OUT / f'{label}.stderr').read_bytes():
            raise RuntimeError(f'{label}: holder or fuser diagnostic')
    record['source_after'] = {'base': meta(source_base), 'rom': meta(source_rom)}
    if record['source_after'] != {name: source[name] for name in ('base', 'rom')}:
        raise RuntimeError('source changed during preparation')
    record['original_ticks_after'] = {str(pid): tick(pid) for pid in (1099659, 1012834)}
    if record['original_ticks_after'] != record['original_ticks_before']:
        raise RuntimeError('original runtime changed')
    record['status'] = 'prepared_stopped'
except Exception as error:
    record['status'] = 'failed'
    record['error'] = f'{type(error).__name__}: {error}'
    raise
finally:
    record['commands'] = commands
    record['recorded_utc'] = dt.datetime.now(dt.UTC).isoformat()
    (OUT / 'preflight.json').write_text(json.dumps(record, indent=2) + '\n')
