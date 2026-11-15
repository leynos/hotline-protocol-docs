#!/bin/bash
set -euo pipefail
RATE_OUT=/data/leynos/Projects/mothra/state/native-sessions/native-rate304-epoch-01
trap 'printf "%s\n" "$?" > "$RATE_OUT/coordinator.exit"' EXIT
cd /data/leynos/Projects/hotline-protocol-docs
test ! -e "$RATE_OUT/coordinator"
/usr/bin/python3 scripts/native_rate304_control.py --plan-dir "$RATE_OUT/rate304-plan" --capture-receipt "$RATE_OUT/capture-ready.json" --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output "$RATE_OUT/coordinator"
