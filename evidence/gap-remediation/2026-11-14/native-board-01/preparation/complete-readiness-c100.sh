#!/bin/bash
# shellcheck disable=SC2024
# Redirect privileged command output as the unprivileged owner of BOARD_O.
set -euo pipefail
# PREPARED ONLY. Invoke on the HOST after separate C100 START and actual PID proof.
BOARD_PID=${1:?actual emulator PID required}
[[ $BOARD_PID =~ ^[0-9]+$ ]]
BOARD_ROOT=/data/leynos/Projects/mothra
BOARD_PREP=$BOARD_ROOT/state/native-sessions/native-board-preparation-02
BOARD_O=$BOARD_ROOT/state/native-sessions/native-board-epoch-02
BOARD_LOCK=$BOARD_ROOT/state/delegation/oracle.lock
cd "$BOARD_ROOT"
test -f "$BOARD_PREP/approved-helper.sha256"
sha256sum --quiet -c "$BOARD_PREP/approved-helper.sha256"
for script in boot-c100.sh complete-readiness-c100.sh run18-c100.sh build-runtime-c100.py wait-managed-c100.py; do
    test -s "$BOARD_PREP/$script"
done
bash -n "$BOARD_PREP/run18-c100.sh"
test ! -e "$BOARD_O/runtime.json" && test ! -e "$BOARD_O/capture-ready.json" && test ! -e "$BOARD_O/readiness"
test -f "$BOARD_O/host-ready.json" && test -f "$BOARD_O/epoch-start.utc" && test -f "$BOARD_O/case-deadline.utc"
BOARD_NS=$(sudo -n stat -Lc %i "/proc/$BOARD_PID/ns/net")
sudo -n python3 "$BOARD_PREP/build-runtime-c100.py" "$BOARD_PID" > "$BOARD_O/build-runtime.stdout"
sudo -n systemd-run --unit=mothra-native-board02-c100-namespace --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/sbin/tcpdump -i lo -U -n -s 0 -w "$BOARD_O/lab-namespace.pcap" '(tcp port 15500 or tcp port 15501 or tcp port 15860 or tcp port 15861)' > "$BOARD_O/namespace-launch.stdout"
sudo -n python3 "$BOARD_PREP/wait-managed-c100.py" --unit mothra-native-board02-c100-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/namespace-initial-wait.json" > "$BOARD_O/namespace-initial-wait.stdout"
sudo -n python3 scripts/capture_readiness.py --unit mothra-native-board02-c100-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --netns-inode "$BOARD_NS" --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --filter '(tcp port 15500 or tcp port 15501 or tcp port 15860 or tcp port 15861)' > "$BOARD_O/namespace-ready.json"
# B82/B83 helper runs in HOST root namespace; it alone builds managed_lock.
sudo -n python3 scripts/native_capture_receipt.py --runtime "$BOARD_O/runtime.json" --host-ready "$BOARD_O/host-ready.json" --namespace-ready "$BOARD_O/namespace-ready.json" --host-filter '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' --namespace-filter '(tcp port 15500 or tcp port 15501 or tcp port 15860 or tcp port 15861)' --lease-unit mothra-native-board02-c100-lease.service --oracle-lock "$BOARD_LOCK" --guest-pcap "$BOARD_O/lab-guest.pcap" --epoch-start "$(cat "$BOARD_O/epoch-start.utc")" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/capture-ready.json" > "$BOARD_O/receipt-helper.stdout"
(cd /data/leynos/Projects/hotline-protocol-docs && sudo -n python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts')
from native_ban_control_cases import write_plans
from native_board_cases import write_plan
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-02')
r=json.loads((p/'runtime.json').read_text())
print('control',write_plans(p/'control-plans',r,15860)['readiness'])
print('board',write_plan(p/'board-plan',r,15860))
PY
) > "$BOARD_O/plan-hashes.stdout"
sudo -n systemd-run --unit=mothra-native-board02-c100-readiness --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=90 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /bin/bash "$BOARD_PREP/run18-c100.sh" > "$BOARD_O/readiness-launch.stdout"
for ((attempt=0; attempt<90; attempt++)); do
    if test -f "$BOARD_O/readiness.exit"; then break; fi
    sleep 1
done
test -f "$BOARD_O/readiness.exit" && test "$(cat "$BOARD_O/readiness.exit")" = 0
sudo -n systemctl show mothra-native-board02-c100-readiness.service -p Id -p ActiveState -p Result -p ExecMainStatus > "$BOARD_O/readiness-unit-final.txt"
rg -q '^ExecMainStatus=0$' "$BOARD_O/readiness-unit-final.txt"
python3 - <<'PY'
import datetime as dt,json
from pathlib import Path
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-board-epoch-02')
r=json.loads((p/'readiness/report.json').read_text())
assert r['status']=='completed' and r['completed_actions']==18
remaining=(dt.datetime.fromisoformat((p/'case-deadline.utc').read_text().strip())-dt.datetime.now(dt.UTC)).total_seconds()
print(f'readiness complete; seconds until fixed cutoff: {remaining:.1f}')
if remaining < 390: raise SystemExit('C101 >=390s readiness margin missed; retire lab')
PY
