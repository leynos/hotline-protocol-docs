#!/bin/bash
set -o pipefail
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 scripts/native_liveness_control.py --plan-dir /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/liveness-plan --capture-receipt /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/capture-ready.json --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/coordinator > /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/c93-run.log 2>&1
code=$?
printf '%s\n' "$code" > /data/leynos/Projects/mothra/state/native-sessions/native-liveness-epoch-01/c93-run.exit
exit "$code"
