#!/bin/bash
# shellcheck disable=SC2024
set -euo pipefail
RATE_PID=${1:?actual emulator PID required}
[[ $RATE_PID =~ ^[0-9]+$ ]]
RATE_ROOT=/data/leynos/Projects/mothra
RATE_PREP=$RATE_ROOT/state/native-sessions/native-rate304-preparation-03
RATE_O=$RATE_ROOT/state/native-sessions/native-rate304-epoch-03
cd "$RATE_ROOT"
test -s "$RATE_PREP/approved-rate304-sources.sha256"
test -s "$RATE_PREP/approved-source-closure.sha256"
test -s "$RATE_PREP/approved-helpers.sha256"
test -s "$RATE_PREP/script-SHA256SUMS"
(cd "$RATE_ROOT" && sha256sum --quiet -c "$RATE_PREP/approved-helpers.sha256")
(cd "$RATE_ROOT" && sha256sum --quiet -c "$RATE_PREP/script-SHA256SUMS")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$RATE_PREP/approved-rate304-sources.sha256")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$RATE_PREP/approved-source-closure.sha256")
test -s "$RATE_O/capture-ready.json" && test -s "$RATE_O/rate304-plan/plan.json"
test ! -e "$RATE_O/coordinator" && test ! -e "$RATE_O/coordinator.exit"
python3 - "$RATE_PID" "$RATE_O" <<'PY'
import datetime as dt,json,sys
from pathlib import Path
pid=int(sys.argv[1]); out=Path(sys.argv[2])
receipt=json.loads((out/'capture-ready.json').read_text())
assert receipt['emulator_pid']==pid
fixed=dt.datetime.fromisoformat((out/'case-deadline.utc').read_text().strip())
assert receipt['deadline_utc']==fixed.isoformat()
assert (fixed-dt.datetime.now(dt.UTC)).total_seconds()>=390, 'Case start margin under 390 seconds'
print(f'case start margin {(fixed-dt.datetime.now(dt.UTC)).total_seconds():.1f}s')
PY
sudo -n systemd-run --unit=mothra-native-rate304-r03-case --property=Type=exec "--property=NetworkNamespacePath=/proc/$RATE_PID/ns/net" --property=KillMode=control-group --property=RuntimeMaxSec=240 --property=Restart=no --property=RemainAfterExit=yes --no-block /bin/bash "$RATE_PREP/run-case-r03.sh" > "$RATE_O/case-launch.stdout"
