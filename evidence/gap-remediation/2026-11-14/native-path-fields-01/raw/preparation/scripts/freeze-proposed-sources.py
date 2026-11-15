"""Snapshot current local import closure for offline review; no source execution."""

import ast
import hashlib
import json
import shutil
from pathlib import Path

root = Path('/data/leynos/Projects/mothra')
docs = root.parent / 'hotline-protocol-docs'
out = root / 'state/native-sessions/native-path-fields-preparation-01'
seeds = {
    'native_path_fields_cases', 'native_path_fields_control',
    'native_board_cases', 'native_board_control',
    'native_ban_control_cases', 'native_control_readiness',
    'native_ban_expiry_control', 'protocol_capture',
}
pending = sorted(seeds)
resolved = set()
while pending:
    module = pending.pop()
    if module in resolved:
        continue
    path = docs / 'scripts' / f'{module}.py'
    if not path.is_file():
        raise FileNotFoundError(path)
    resolved.add(module)
    imports = set()
    for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split('.')[0])
    pending.extend(name for name in imports if (docs / 'scripts' / f'{name}.py').is_file() and name not in resolved)
proposed = out / 'proposed-sources'
proposed.mkdir(exist_ok=False)
hashes = {}
for module in sorted(resolved):
    name = f'{module}.py'
    shutil.copy2(docs / 'scripts' / name, proposed / name)
    hashes[name] = hashlib.sha256((proposed / name).read_bytes()).hexdigest()
helpers = {}
for name in ('native_emulator_readiness.py', 'native_capture_receipt.py', 'capture_readiness.py'):
    shutil.copy2(root / 'scripts' / name, proposed / name)
    helpers[name] = hashlib.sha256((proposed / name).read_bytes()).hexdigest()
record = {'status': 'proposed_only_no_root_source_pin', 'docs_head': __import__('subprocess').check_output(['git','-C',str(docs),'rev-parse','HEAD'],text=True).strip(),
          'modules': sorted(resolved), 'hashes': hashes, 'helpers': helpers,
          'source_cases_sha256': hashes['native_path_fields_cases.py'],
          'source_control_sha256': hashes['native_path_fields_control.py']}
(out / 'proposed-source-closure.json').write_text(json.dumps(record,indent=2)+'\n')
print(len(resolved), record['source_cases_sha256'], record['source_control_sha256'])
