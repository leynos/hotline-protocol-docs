#!/bin/bash
set -o pipefail
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 scripts/native_roster_overlap_control.py --plan-dir /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/roster-plan --capture-receipt /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/capture-ready.json --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/results > /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/c87-run.log 2>&1
status=$?
printf '%s\n' "$status" > /data/leynos/Projects/mothra/state/native-sessions/native-roster-overlap-01/c87-run.exit
exit "$status"
