#!/bin/bash
set +e
readlink /proc/self/ns/net > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-runner-netns.txt
if [ "$(cat /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-runner-netns.txt)" != 'net:[4026533397]' ]; then
  printf 'wrong netns\n' > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-first.log
  printf '98\n' > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-first.exit
  exit 98
fi
/usr/bin/python3 /data/leynos/Projects/hotline-protocol-docs/scripts/native_ban_expiry_control.py --run --phase first --plans /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/plans --readiness-dir /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/captures/readiness --capture-receipt /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/capture-ready.json --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/results-first-c77 > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-first.log 2>&1
rc=$?
printf '%s\n' "$rc" > /data/leynos/Projects/mothra/state/native-sessions/native-ban-expiry-epoch-first-01/c77-first.exit
exit "$rc"
