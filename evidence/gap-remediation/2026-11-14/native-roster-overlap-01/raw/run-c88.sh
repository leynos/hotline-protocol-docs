#!/bin/bash
set -o pipefail
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 scripts/protocol_capture.py capture /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/control-plans/readiness.json --oracle-binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/postflight > /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/c88-postflight.log 2>&1
status=$?
printf '%s\n' "$status" > /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/c88-postflight.exit
exit "$status"
