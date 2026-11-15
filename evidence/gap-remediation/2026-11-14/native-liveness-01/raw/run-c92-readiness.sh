#!/bin/bash
set -euo pipefail
trap 'code=$?; printf "%s\n" "$code" > /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/readiness.exit' EXIT
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 - <<'PYCHECK'
import json,sys
from pathlib import Path
sys.path.insert(0, "scripts")
from native_ban_expiry_control import runtime_gate,utc
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01')
r=json.loads((p/'capture-ready.json').read_text())
plan=json.loads((p/'control-plans/readiness.json').read_text())
runtime_gate(r,plan['environment'],utc(r['deadline_utc']))
print('runtime_gate PASS')
PYCHECK
/usr/bin/python3 scripts/protocol_capture.py capture /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/control-plans/readiness.json --oracle-binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/readiness
/usr/bin/python3 scripts/protocol_capture.py verify /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/readiness
/usr/bin/python3 - <<'PYSEM'
import json,sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from native_control_readiness import readiness
r=json.loads(Path('/data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/readiness/report.json').read_text())
readiness(r)
print('semantic readiness PASS')
PYSEM
