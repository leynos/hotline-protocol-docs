"""Prepared only: snapshot approved canonical M1 bytes after root import."""

import ast
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path('/data/leynos/Projects/mothra')
P = ROOT / 'state/native-sessions/native-alias-live-preparation-01'
DOCS = ROOT.parent / 'hotline-protocol-docs'
SCRIPTS = DOCS / 'scripts'
candidate = json.loads((P / 'candidate-source-closure.json').read_text())
assert candidate['status'] == 'candidate_only_not_approved_no_canonical_snapshot'
assert not (P / 'proposed-sources').exists()
assert not (P / 'proposed-source-closure.json').exists()
for name in candidate['root_pin_files_absent'][:4]:
    assert not (P / name).exists(), f'root pin already exists: {name}'

seeds = {'native_missing_alias_cases', 'native_missing_alias_control',
         'native_ban_control_cases', 'native_control_readiness',
         'native_ban_expiry_control', 'protocol_capture'}
pending = list(seeds)
resolved = {}
while pending:
    name = pending.pop()
    if name in resolved:
        continue
    path = SCRIPTS / f'{name}.py'
    if not path.is_file():
        raise FileNotFoundError(path)
    raw = path.read_bytes()
    resolved[name] = hashlib.sha256(raw).hexdigest()
    imports = set()
    for node in ast.walk(ast.parse(raw, filename=str(path))):
        if isinstance(node, ast.Import):
            imports.update(a.name.split('.')[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split('.')[0])
    pending.extend(n for n in imports if n not in resolved and
                   (SCRIPTS / f'{n}.py').is_file())
expected = {name: item['sha256']
            for name, item in candidate['protocol_modules'].items()}
assert resolved == expected, 'candidate and canonical source closure differ'
helpers = {}
for name in ('native_emulator_readiness.py', 'capture_readiness.py',
             'native_capture_receipt.py'):
    helpers[name] = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
assert helpers == candidate['helpers'], 'Mothra helper source drifted'
launchers = {}
for name in ('mac_runtime.py', 'mac_network_isolation.py'):
    launchers[name] = hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()

dest = P / 'proposed-sources'
dest.mkdir(exist_ok=False)
for name in sorted(resolved):
    shutil.copy2(SCRIPTS / f'{name}.py', dest / f'{name}.py')
for name in sorted(helpers):
    shutil.copy2(ROOT / 'scripts' / name, dest / name)
launcher_dest = P / 'proposed-runtime-launchers'
launcher_dest.mkdir(exist_ok=False)
for name in sorted(launchers):
    shutil.copy2(ROOT / 'scripts' / name, launcher_dest / name)
    assert hashlib.sha256((launcher_dest / name).read_bytes()).hexdigest() == launchers[name]
for name, digest in {**{f'{x}.py': y for x, y in resolved.items()},
                     **helpers}.items():
    assert hashlib.sha256((dest / name).read_bytes()).hexdigest() == digest
head = subprocess.check_output(
    ['git', '-c', f'safe.directory={DOCS}', '-C', str(DOCS), 'rev-parse', 'HEAD'],
    text=True,
).strip()
record = {'status': 'proposed_canonical_snapshot_not_root_approved',
          'docs_head': head, 'modules': sorted(resolved),
          'hashes': {f'{name}.py': digest for name, digest in sorted(resolved.items())},
          'helpers': helpers, 'launchers': launchers,
          'source_cases_sha256': resolved['native_missing_alias_cases'],
          'source_control_sha256': resolved['native_missing_alias_control']}
(P / 'proposed-source-closure.json').write_text(json.dumps(record, indent=2) + '\n')
print(len(resolved), record['source_cases_sha256'], record['source_control_sha256'])
