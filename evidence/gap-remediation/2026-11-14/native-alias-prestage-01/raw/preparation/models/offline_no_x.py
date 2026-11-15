"""Offline identity and single-use X input guards; never opens X."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / 'ui-input-alias-live-02.py'
spec = importlib.util.spec_from_file_location('alias_p02_ui_model', SCRIPT)
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

with tempfile.TemporaryDirectory(prefix='alias-p02-no-x-') as tmp:
    base = pathlib.Path(tmp)
    p = base / 'proc/4242'
    (p / 'fd').mkdir(parents=True)
    (p / 'ns').mkdir()
    os.chown(p, 1000, 1000)
    (p / 'stat').write_text('4242 (Xvfb) S ' + ' '.join(['1'] * 18 + ['7123']) + '\n')
    (p / 'cmdline').write_bytes(b'\0'.join(x.encode() for x in ['/usr/sbin/Xvfb', ':123', '-screen', '0', '1024x768x24', '-nolisten', 'tcp', '-ac', '-noreset']) + b'\0')
    exe = base / 'xvfb-good'
    exe.write_bytes(b'good-Xvfb')
    (p / 'exe').symlink_to(exe)
    d = base / 'display'
    d.mkdir()
    command = ['systemd-run', '--', '/usr/sbin/Xvfb', ':123', '-screen', '0', '1024x768x24', '-nolisten', 'tcp', '-ac', '-noreset']
    (d / 'display-service.json').write_text(json.dumps({'unit': 'owned-display', 'command': command}))
    original_path = ui.Path
    ui.Path = lambda value: base / value.lstrip('/') if str(value).startswith('/proc/') else original_path(value)
    ui.D = d
    ui.managed = lambda unit, user=False: 4242
    frozen = ui.display_identity()
    assert frozen['pid'] == 4242 and frozen['start_ticks'] == 7123
    ui.managed = lambda unit, user=False: 4243
    try:
        ui.display_identity()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError('display MainPID replacement accepted')
    ui.managed = lambda unit, user=False: 4242
    exe.write_bytes(b'changed-Xvfb')
    assert ui.display_identity()['exe_sha256'] != frozen['exe_sha256']

    # Fake only the actual disk/capture snapshot inputs for gate(retire).
    o = base / 'epoch'
    o.mkdir()
    ui.O = o
    ui.ROOT = base
    (o / 'display-identity.json').write_text(json.dumps(frozen))
    (o / 'case-deadline.utc').write_text((dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)).isoformat())
    prep = base / 'state/native-sessions/native-alias-live-preparation-02/stopped-preparation'
    prep.mkdir(parents=True)
    working = base / 'working.dsk'
    working.write_bytes(b'fake-working')
    guest = base / 'guest.pcap'
    guest.write_bytes(b'fake-pcap')
    (p / 'fd/6').symlink_to(working)
    (p / 'fd/16').symlink_to(guest)
    ns = p / 'ns/net'
    ns.write_bytes(b'netns')
    exe.write_bytes(b'good-Xvfb')
    (prep / 'preflight.json').write_text(json.dumps({'prepared': {'working.dsk': {'inode': working.stat().st_ino}}}))
    disk = {'phase': 'disk', 'working_inode': working.stat().st_ino,
            'exe_sha256': '9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4',
            'uid': 1000, 'pid': 4242, 'start_ticks': 7123, 'netns_inode': ns.stat().st_ino}
    (o / 'disk-ready.json').write_text(json.dumps(disk))
    capture = dict(disk, phase='capture', guest_pcap=str(guest),
                   guest_dev=guest.stat().st_dev, guest_inode=guest.stat().st_ino)
    (o / 'guest-capture-ready.json').write_text(json.dumps(capture))
    ui.display_identity = lambda: frozen
    ui.digest = lambda path: disk['exe_sha256'] if str(path).endswith('/exe') else sha(path)
    ui.subprocess.run = lambda *args, **kwargs: type('R', (), {'stdout': str(working.stat().st_ino)})()
    (o / 'guest-capture-ready.json').rename(o / 'capture-later.json')
    ui.gate('startup')
    (o / 'capture-later.json').rename(o / 'guest-capture-ready.json')
    ui.gate('retire')
    (p / 'fd/16').unlink()
    other = base / 'other.pcap'
    other.write_bytes(b'other')
    (p / 'fd/16').symlink_to(other)
    try:
        ui.gate('startup')
    except AssertionError:
        pass
    else:
        raise AssertionError('startup after capture accepted replaced FD16')
    try:
        ui.gate('retire')
    except AssertionError:
        pass
    else:
        raise AssertionError('capture FD16 replacement accepted')

    # An attempted Quit is consumed even if X fails before completion.
    ui.gate = lambda phase: None
    shot = o / 'retire/screens/quit.png'
    shot.parent.mkdir(parents=True)
    shot.write_bytes(b'fresh-reviewed-image')
    (o / 'coordinator.exit').write_text('0\n')
    (o / 'retire-approved.json').write_text(json.dumps({
        'emulator_pid': 4242, 'emulator_starttime': 7123, 'display': ':123',
        'deadline_utc': (o / 'case-deadline.utc').read_text().strip(),
        'controls': [{'label': 'Quit', 'x': 50, 'y': 50,
                      'screenshot': 'quit.png', 'sha256': sha(shot)}],
        'reviewed_utc': dt.datetime.now(dt.UTC).isoformat(),
    }))
    (o / 'retire-approved.json').chmod(0o600)
    with patch.object(sys, 'argv', [str(SCRIPT), 'retire', 'click', '50', '50']), patch.object(ui.ctypes, 'CDLL', side_effect=RuntimeError('no X in model')):
            try:
                ui.main()
            except RuntimeError as exc:
                assert str(exc) == 'no X in model'
            else:
                raise AssertionError('model unexpectedly reached X')
            try:
                ui.main()
            except AssertionError:
                pass
            else:
                raise AssertionError('retirement click replay accepted')
    rows = [json.loads(x) for x in (o / 'operator-inputlog.jsonl').read_text().splitlines()]
    assert [x['status'] for x in rows if x['phase'] == 'retire'] == ['attempted']
print('display replacement, executable replacement, FD16 replacement and attempted Quit replay rejected without X')
