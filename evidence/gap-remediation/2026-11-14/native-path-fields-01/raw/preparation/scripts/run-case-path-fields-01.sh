#!/bin/bash
set -euo pipefail
RATE_ROOT=/data/leynos/Projects/mothra
RATE_O=$RATE_ROOT/state/native-sessions/native-path-fields-epoch-01
trap 'printf "%s\n" "$?" > "$RATE_O/coordinator.exit"' EXIT
cd /data/leynos/Projects/hotline-protocol-docs
test ! -e "$RATE_O/coordinator"
(cd "$RATE_ROOT" && sha256sum --quiet -c "$RATE_ROOT/state/native-sessions/native-path-fields-preparation-01/script-SHA256SUMS")
(cd "$RATE_ROOT" && sha256sum --quiet -c "$RATE_ROOT/state/native-sessions/native-path-fields-preparation-01/approved-helpers.sha256")
sha256sum --quiet -c "$RATE_ROOT/state/native-sessions/native-path-fields-preparation-01/approved-path-fields-sources.sha256"
sha256sum --quiet -c "$RATE_ROOT/state/native-sessions/native-path-fields-preparation-01/approved-source-closure.sha256"
/usr/bin/python3 - <<'PY' > "$RATE_O/source-prerun-check.json"
import hashlib
import json
from pathlib import Path

root = Path('/data/leynos/Projects/mothra')
docs = root.parent / 'hotline-protocol-docs'
out = root / 'state/native-sessions/native-path-fields-epoch-01'
freeze = json.loads((out / 'source-freeze.json').read_text())
hashes = freeze['hashes']
assert len(hashes) >= 2
assert set(hashes) == {f'{module}.py' for module in freeze['closure_modules']}
assert set(freeze['helper_hashes']) == {'native_emulator_readiness.py', 'native_capture_receipt.py', 'capture_readiness.py'}
for name, digest in hashes.items():
    for path in (docs / 'scripts' / name, out / 'sources' / name):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, path
for name, digest in freeze['helper_hashes'].items():
    for path in (root / 'scripts' / name, out / 'helper-sources' / name):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, path
print(json.dumps({'status': 'all_frozen_sources_match_current',
                  'protocol_sources': len(hashes), 'helpers': len(freeze['helper_hashes'])}))
PY
/usr/bin/python3 scripts/native_path_fields_control.py --plan-dir "$RATE_O/path-fields-plan" --capture-receipt "$RATE_O/capture-ready.json" --binary "$RATE_ROOT/evidence/hotline-server-1.9/inputs/HLserver19.pef" --output "$RATE_O/coordinator"
