#!/bin/bash
# shellcheck disable=SC2024
# Prepared operator command; output belongs to the owned lab epoch.
set -euo pipefail
# PREPARED ONLY. Invoke on the host after a separate live START and PID proof.
BOARD_PID=${1:?actual emulator PID required}
[[ $BOARD_PID =~ ^[0-9]+$ ]]
BOARD_ROOT=/data/leynos/Projects/mothra
BOARD_PREP=$BOARD_ROOT/state/native-sessions/native-path-fields-preparation-01
BOARD_O=$BOARD_ROOT/state/native-sessions/native-path-fields-epoch-01
BOARD_LOCK=$BOARD_ROOT/state/delegation/oracle.lock
test "$EUID" = 0
cd "$BOARD_ROOT"
test -s "$BOARD_PREP/approved-helpers.sha256"
test -s "$BOARD_PREP/approved-path-fields-sources.sha256"
test -s "$BOARD_PREP/approved-source-closure.sha256"
test -s "$BOARD_PREP/script-SHA256SUMS"
sha256sum --quiet -c "$BOARD_PREP/approved-helpers.sha256"
sha256sum --quiet -c "$BOARD_PREP/script-SHA256SUMS"
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-path-fields-sources.sha256")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-source-closure.sha256")
for script in boot-path-fields-01.sh complete-readiness-path-fields-01.sh run18-path-fields-01.sh build-runtime-path-fields-01.py wait-managed-path-fields-01.py run-case-path-fields-01.sh launch-case-path-fields-01.sh; do
    test -s "$BOARD_PREP/$script"
done
bash -n "$BOARD_PREP/run18-path-fields-01.sh"
test ! -e "$BOARD_O/runtime.json" && test ! -e "$BOARD_O/capture-ready.json" && test ! -e "$BOARD_O/readiness"
test -f "$BOARD_O/host-ready.json" && test -f "$BOARD_O/epoch-start.utc" && test -f "$BOARD_O/case-deadline.utc"
test -s "$BOARD_O/disk-ready.json"
python3 - "$BOARD_PID" "$BOARD_O/disk-ready.json" <<'PY'
import json,sys
actual=json.load(open(sys.argv[2]))
assert actual['phase']=='disk' and actual['pid']==int(sys.argv[1])
assert actual['working_inode']==5999397982 and actual['exe_sha256']=='9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
PY
# Operator has launched the guest server; capture phase binds that same
# disk receipt PID/start/namespace and requires FD16 plus a writable header.
# This must pass before any Hotline protocol controller starts.
sudo -n python3 scripts/native_emulator_readiness.py --phase capture --working-image "$BOARD_ROOT/state/mac-runtime/native-path-fields-01/working.dsk" --working-inode 5999397982 --exe-sha256 9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4 --uid 1000 --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --disk-receipt "$BOARD_O/disk-ready.json" --guest-pcap "$BOARD_O/lab-guest.pcap" --output "$BOARD_O/guest-capture-ready.json" > "$BOARD_O/guest-capture-ready.stdout"
python3 - "$BOARD_PID" "$BOARD_O/guest-capture-ready.json" <<'PY'
import json,sys
actual=json.load(open(sys.argv[2]))
assert actual['phase']=='capture' and actual['pid']==int(sys.argv[1])
assert actual['working_inode']==5999397982 and actual['guest_fd']==16
PY
BOARD_NS=$(sudo -n stat -Lc %i "/proc/$BOARD_PID/ns/net")
sudo -n python3 "$BOARD_PREP/build-runtime-path-fields-01.py" "$BOARD_PID" > "$BOARD_O/build-runtime.stdout"
sudo -n systemd-run --unit=mothra-native-path-fields-01-namespace --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/sbin/tcpdump -i lo -U -n -s 0 -w "$BOARD_O/lab-namespace.pcap" '(tcp port 15500 or tcp port 15501 or tcp port 15900 or tcp port 15901)' > "$BOARD_O/namespace-launch.stdout"
sudo -n python3 "$BOARD_PREP/wait-managed-path-fields-01.py" --unit mothra-native-path-fields-01-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/namespace-initial-wait.json" > "$BOARD_O/namespace-initial-wait.stdout"
sudo -n python3 scripts/capture_readiness.py --unit mothra-native-path-fields-01-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --netns-inode "$BOARD_NS" --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --filter '(tcp port 15500 or tcp port 15501 or tcp port 15900 or tcp port 15901)' > "$BOARD_O/namespace-ready.json"
# B82/B83 helper runs in HOST root namespace; it alone builds managed_lock.
sudo -n python3 scripts/native_capture_receipt.py --runtime "$BOARD_O/runtime.json" --host-ready "$BOARD_O/host-ready.json" --namespace-ready "$BOARD_O/namespace-ready.json" --host-filter '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' --namespace-filter '(tcp port 15500 or tcp port 15501 or tcp port 15900 or tcp port 15901)' --lease-unit mothra-native-path-fields-01-lease.service --oracle-lock "$BOARD_LOCK" --guest-pcap "$BOARD_O/lab-guest.pcap" --epoch-start "$(cat "$BOARD_O/epoch-start.utc")" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/capture-ready.json" > "$BOARD_O/receipt-helper.stdout"
(cd /data/leynos/Projects/hotline-protocol-docs && sudo -n python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts')
from native_ban_control_cases import write_plans
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-path-fields-epoch-01')
r=json.loads((p/'runtime.json').read_text())
print('control',write_plans(p/'control-plans',r,15900)['readiness'])

PY
) > "$BOARD_O/plan-hashes.stdout"
(cd /data/leynos/Projects/hotline-protocol-docs && python3 scripts/native_path_fields_cases.py --runtime "$BOARD_O/runtime.json" --output "$BOARD_O/path-fields-plan" --port 15900) >> "$BOARD_O/plan-hashes.stdout"
sudo -n systemd-run --unit=mothra-native-path-fields-01-readiness --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=90 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /bin/bash "$BOARD_PREP/run18-path-fields-01.sh" > "$BOARD_O/readiness-launch.stdout"
for ((attempt=0; attempt<90; attempt++)); do
    if test -f "$BOARD_O/readiness.exit"; then break; fi
    sleep 1
done
test -f "$BOARD_O/readiness.exit" && test "$(cat "$BOARD_O/readiness.exit")" = 0
sudo -n systemctl show mothra-native-path-fields-01-readiness.service -p Id -p ActiveState -p Result -p ExecMainStatus > "$BOARD_O/readiness-unit-final.txt"
rg -q '^ExecMainStatus=0$' "$BOARD_O/readiness-unit-final.txt"
python3 - <<'PY'
import datetime as dt,json
from pathlib import Path
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-path-fields-epoch-01')
r=json.loads((p/'readiness/report.json').read_text())
assert r['status']=='completed' and r['completed_actions']==18
remaining=(dt.datetime.fromisoformat((p/'case-deadline.utc').read_text().strip())-dt.datetime.now(dt.UTC)).total_seconds()
print(f'readiness complete; seconds until fixed cutoff: {remaining:.1f}')
if remaining < 390: raise SystemExit('Next-case >=390s readiness margin missed; retire lab')
PY
