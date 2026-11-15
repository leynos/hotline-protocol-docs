#!/bin/bash
set -euo pipefail
BOARD_OUT=/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-02
trap 'printf "%s\n" "$?" > "$BOARD_OUT/coordinator.exit"' EXIT
cd /data/leynos/Projects/hotline-protocol-docs
/usr/bin/python3 scripts/native_board_control.py --plan "$BOARD_OUT/board-plan" --receipt "$BOARD_OUT/capture-ready.json" --binary /data/leynos/Projects/mothra/evidence/hotline-server-1.9/inputs/HLserver19.pef --output "$BOARD_OUT/coordinator"
