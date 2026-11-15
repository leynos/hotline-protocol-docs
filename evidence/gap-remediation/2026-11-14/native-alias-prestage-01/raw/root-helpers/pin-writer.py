"""Create exact public source pins after the parent's independent review."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path('/data/leynos/Projects/mothra')
DOCS = ROOT.parent / 'hotline-protocol-docs'
P = ROOT / 'state/native-sessions/native-alias-live-preparation-02'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert os.geteuid() == 0
proposal = json.loads((P / 'proposed-source-closure.json').read_text())
assert len(proposal['hashes']) == 35
assert set(proposal['helpers']) == {'native_emulator_readiness.py', 'capture_readiness.py', 'native_capture_receipt.py'}
assert set(proposal['launchers']) == {'mac_runtime.py', 'mac_network_isolation.py'}
assert proposal['hashes']['native_missing_alias_cases.py'] == 'd80f83f8af746641b415045cf5c50ccb62adc55e10a08133fc4ea7d23e48560b'
assert proposal['hashes']['native_missing_alias_control.py'] == 'ddbf153daf49d52b4a65170d90b02eb16a0e9cd33ae1eb2268e9fd22590fe0e3'
sets = [
 ('approved-alias-live-sources.sha256', DOCS, {f'scripts/{n}': proposal['hashes'][n] for n in ('native_missing_alias_cases.py', 'native_missing_alias_control.py')}),
 ('approved-source-closure.sha256', DOCS, {f'scripts/{n}': h for n,h in proposal['hashes'].items()}),
 ('approved-helpers.sha256', ROOT, {f'scripts/{n}': h for n,h in proposal['helpers'].items()}),
 ('approved-runtime-launchers.sha256', ROOT, {f'scripts/{n}': h for n,h in proposal['launchers'].items()}),
]
rows = [line.split() for line in (P / 'proposed-script-SHA256SUMS').read_text().splitlines()]
assert len(rows) == 10 and len({x[1] for x in rows}) == 10
scripts = {name: digest for digest, name in rows}
assert all(Path(name).parent == P.relative_to(ROOT) for name in scripts)
assert {Path(name).name for name in scripts} == {'boot-alias-live-02.sh', 'complete-readiness-alias-live-02.sh', 'run18-alias-live-02.sh', 'build-runtime-alias-live-02.py', 'wait-managed-alias-live-02.py', 'launch-case-alias-live-02.sh', 'run-case-alias-live-02.sh', 'candidate-closure-02.py', 'freeze-after-import-02.py', 'ui-input-alias-live-02.py'}
sets.append(('script-SHA256SUMS', ROOT, scripts))
for _, origin, mapping in sets:
 for name,digest in mapping.items():
  assert sha(origin/name) == digest, name
for name,digest in {**proposal['hashes'], **proposal['helpers']}.items():
 assert sha(P/'proposed-sources'/name) == digest
for name,digest in proposal['launchers'].items():
 assert sha(P/'proposed-runtime-launchers'/name) == digest
assert all(not (P/name).exists() for name,_,_ in sets)
# The caller must separately record accepted review names and this script's hash.
for name,_,mapping in sets:
 raw=''.join(f'{digest}  {path}\n' for path,digest in sorted(mapping.items())).encode()
 fd=os.open(P/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
 with os.fdopen(fd,'wb') as out:
  os.fchmod(out.fileno(),0o444)
  out.write(raw);out.flush();os.fsync(out.fileno())
print(json.dumps({'status':'pins_created','sets':{name:len(mapping) for name,_,mapping in sets},'proposal_sha256':sha(P/'proposed-source-closure.json')}))
