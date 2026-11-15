#!/bin/bash
set -euo pipefail
BOARD_OUT=/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-01
trap 'code=$?; printf "%s\n" "$code" > "$BOARD_OUT/readiness.exit"' EXIT
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts')
from native_ban_expiry_control import runtime_gate,utc
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-01')
r=json.loads((p/'capture-ready.json').read_text())
plan=json.loads((p/'control-plans/readiness.json').read_text())
runtime_gate(r,plan['environment'],utc(r['deadline_utc']))
print('runtime_gate PASS')
PY
/usr/bin/python3 scripts/protocol_capture.py capture "$BOARD_OUT/control-plans/readiness.json" --oracle-binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output "$BOARD_OUT/readiness"
/usr/bin/python3 scripts/protocol_capture.py verify "$BOARD_OUT/readiness"
/usr/bin/python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts')
from native_control_readiness import readiness
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-01')
r=json.loads((p/'readiness/report.json').read_text())
readiness(r)
print('semantic readiness PASS')
PY
