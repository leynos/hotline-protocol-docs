#!/bin/bash
set +e
/usr/bin/python3 /data/leynos/Projects/hotline-protocol-docs/scripts/native_ban_expiry_control.py --run --phase first --plans /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/plans --readiness-dir /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/captures/readiness --capture-receipt /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/capture-ready.json --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/results-first > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/first.log 2>&1
rc=$?
printf '%s\n' "$rc" > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/first.exit
exit "$rc"
